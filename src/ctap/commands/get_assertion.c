/*
 * ZeroFIDO
 * Copyright (C) 2026 Alex Stoyanov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "get_assertion.h"
#include "../../zerofido_trace.h"
#include "../../pin/vault.h"

#include <furi.h>
#include <string.h>

#include "../core/approval.h"
#include "../core/assertion_queue.h"
#include "../core/internal.h"
#include "../extensions/hmac_secret.h"
#include "../parse.h"
#include "../policy.h"
#include "../response.h"
#include "../../pin/protocol.h"
#include "../../transport/adapter.h"
#include "../../zerofido_app_i.h"
#include "../../zerofido_crypto.h"
#include "../../zerofido_notify.h"
#include "../../zerofido_store.h"

#if defined(ZF_RELEASE_DIAGNOSTICS) && ZF_RELEASE_DIAGNOSTICS
#define ZF_CTAP_GA_DIAG(text) FURI_LOG_I("ZeroFIDO:CTAP", "GA %s", (text))
#else
#define ZF_CTAP_GA_DIAG(text)                                                                      \
    do {                                                                                           \
        (void)(text);                                                                              \
    } while (false)
#endif

typedef struct {
    ZfGetAssertionRequest request;
    uint16_t matches[ZF_MAX_CREDENTIALS];
    ZfClientPinState pin_state;
    ZfCredentialRecord selected_record;
    union {
        ZfCredentialDescriptor descriptors[ZF_MAX_ALLOW_LIST];
        ZfAssertionResponseScratch response;
        uint8_t store_io[ZF_STORE_RECORD_IO_SIZE];
    } work;
} ZfGetAssertionScratch;

_Static_assert(sizeof(ZfGetAssertionScratch) <= ZF_COMMAND_SCRATCH_SIZE,
               "getAssertion scratch exceeds command arena");

/*
 * Prepares a signed assertion response and computes the next sign counter, but
 * does not publish the counter. Callers must still reserve/publish the counter
 * only after confirming the selected record is current under the store lock.
 */
static uint8_t zf_prepare_assertion_response(const ZfAssertionRequestData *request,
                                             const ZfClientPinState *pin_state,
                                             const ZfCredentialRecord *record, bool user_present,
                                             bool uv_verified, bool include_user_details,
                                             bool include_count, size_t match_count,
                                             bool user_selected, bool include_user_selected,
                                             uint32_t *out_next_sign_count,
                                             ZfAssertionResponseScratch *response_scratch,
                                             uint8_t *out, size_t out_capacity, size_t *out_len) {
    uint32_t next_sign_count = 0;
    size_t extension_data_len = 0;
    uint8_t status = ZF_CTAP_SUCCESS;

    if (!record || !out_next_sign_count || record->sign_count == UINT32_MAX) {
        return ZF_CTAP_ERR_OTHER;
    }
    next_sign_count = record->sign_count + 1;

    status = zf_ctap_hmac_secret_build_extension(
        pin_state, request, record, uv_verified, &response_scratch->hmac_secret,
        response_scratch->extension_data, sizeof(response_scratch->extension_data),
        &extension_data_len);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    status = zf_ctap_build_assertion_response_with_scratch(
        response_scratch, request, record, user_present, uv_verified, next_sign_count,
        include_user_details, include_count, match_count, include_user_selected, user_selected,
        response_scratch->extension_data, extension_data_len, out, out_capacity, out_len);
    if (status == ZF_CTAP_SUCCESS) {
        *out_next_sign_count = next_sign_count;
    }
    return status;
}

static bool zf_ctap_index_entry_matches_record(const ZfCredentialIndexEntry *entry,
                                               const ZfCredentialRecord *record) {
    return entry && record && entry->in_use && record->in_use &&
           entry->credential_id_len == record->credential_id_len &&
           memcmp(entry->credential_id, record->credential_id, record->credential_id_len) == 0;
}

static bool zf_ctap_snapshot_index_entry_locked(ZerofidoApp *app, size_t record_index,
                                                ZfCredentialIndexEntry *entry) {
    if (!app->store.records || record_index >= app->store.count ||
        !app->store.records[record_index].in_use) {
        return false;
    }

    *entry = app->store.records[record_index];
    return true;
}

static bool zf_ctap_selected_record_still_current_locked(ZerofidoApp *app, size_t record_index,
                                                         const ZfCredentialRecord *record) {
    if (!app->store.records || record_index >= app->store.count) {
        return false;
    }

    return zf_ctap_index_entry_matches_record(&app->store.records[record_index], record);
}

static size_t zf_ctap_resolve_assertion_matches_snapshot(ZerofidoApp *app,
                                                         const ZfGetAssertionRequest *request,
                                                         bool uv_verified, uint16_t *matches) {
    size_t match_count = 0;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    match_count =
        zf_ctap_resolve_assertion_matches(app->storage, &app->store, request, uv_verified, matches);
    furi_mutex_release(app->ui_mutex);
    return match_count;
}

static bool zf_ctap_load_assertion_record(ZerofidoApp *app, size_t record_index, const char *rp_id,
                                          ZfCredentialRecord *record,
                                          ZfCredentialIndexEntry *out_entry, uint8_t *store_io,
                                          size_t store_io_size) {
    ZfCredentialIndexEntry entry = {0};
    bool snapshot_ok = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    snapshot_ok = zf_ctap_snapshot_index_entry_locked(app, record_index, &entry);
    furi_mutex_release(app->ui_mutex);

    if (!snapshot_ok ||
        !zf_store_load_record_with_buffer(app->storage, &entry, record, store_io, store_io_size) ||
        strcmp(record->rp_id, rp_id) != 0) {
        zf_crypto_secure_zero(record, sizeof(*record));
        return false;
    }
    if (!zf_ctap_index_entry_matches_record(&entry, record)) {
        return false;
    }
    if (out_entry) {
        *out_entry = entry;
    }
    return true;
}

static uint8_t zf_ctap_publish_assertion_counter(
    ZerofidoApp *app, const ZfCredentialIndexEntry *entry, ZfCredentialRecord *record,
    size_t record_index, uint32_t next_sign_count, ZfTransportSessionId session_id,
    const ZfGetAssertionRequest *request, bool uv_verified, const uint16_t *match_indices,
    size_t match_count, bool seed_assertion_queue, uint8_t *store_io, size_t store_io_size) {
    uint32_t prepared_counter_high_water = 0;

    record->sign_count = next_sign_count;
    if (!zf_store_prepare_counter_advance(app->storage, entry, record, store_io, store_io_size,
                                          &prepared_counter_high_water)) {
        return ZF_CTAP_ERR_OTHER;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!zf_ctap_selected_record_still_current_locked(app, record_index, record)) {
        furi_mutex_release(app->ui_mutex);
        return ZF_CTAP_ERR_NO_CREDENTIALS;
    }
    if (!zf_store_publish_counter_advance(&app->store, record, prepared_counter_high_water)) {
        furi_mutex_release(app->ui_mutex);
        return ZF_CTAP_ERR_OTHER;
    }
    zf_ctap_assertion_queue_clear(app);
    if (seed_assertion_queue) {
        zf_ctap_assertion_queue_seed(app, session_id, request, uv_verified, match_indices,
                                     match_count);
    }
    furi_mutex_release(app->ui_mutex);
    zerofido_notify_success(app);
    return ZF_CTAP_SUCCESS;
}

static uint8_t zf_ctap_load_and_prepare_assertion(
    ZerofidoApp *app, const ZfAssertionRequestData *request, const ZfClientPinState *pin_state,
    size_t record_index, bool user_present, bool uv_verified, bool include_user_details,
    bool include_count, size_t match_count, bool user_selected, bool include_user_selected,
    ZfCredentialRecord *record, ZfCredentialIndexEntry *entry, uint8_t *store_io,
    size_t store_io_size, ZfAssertionResponseScratch *response_scratch, uint32_t *next_sign_count,
    uint8_t *out, size_t out_capacity, size_t *out_len) {
    if (!zf_ctap_load_assertion_record(app, record_index, request->rp_id, record, entry, store_io,
                                       store_io_size)) {
        return ZF_CTAP_ERR_NO_CREDENTIALS;
    }
/*
 * tpm branch (2026-11-07): the record file keeps the *reserved* counter ceiling
 * (sign_count + ZF_COUNTER_RESERVATION_WINDOW), so that an unclean shutdown can
 * never hand out a counter twice. The in-RAM index keeps the value actually
 * used. Signing from the file's value put every single assertion one step above
 * the ceiling, so each one reserved again - two SD writes, about 1.25 s of the
 * 1.9 s an account cost while the PC walked a six-account list. Take the used
 * value from the index: the window then does its job and only every 32nd
 * assertion pays for a reservation. After a restart the index is rebuilt from
 * the file, so the counter resumes above the ceiling and still never repeats.
 */
    zf_store_counter_base_from_index(entry, record);
    return zf_prepare_assertion_response(request, pin_state, record, user_present, uv_verified,
                                         include_user_details, include_count, match_count,
                                         user_selected, include_user_selected, next_sign_count,
                                         response_scratch, out, out_capacity, out_len);
}

static uint8_t zf_ctap_finish_assertion(ZerofidoApp *app, ZfTransportSessionId session_id,
                                        const ZfGetAssertionRequest *request,
                                        ZfGetAssertionScratch *scratch, bool resolve_match,
                                        size_t record_index, bool user_present, bool uv_verified,
                                        bool include_user_details, bool include_user_selected,
                                        bool poll_before_publish, bool *maintenance_acquired,
                                        uint8_t *out, size_t out_capacity, size_t *out_len) {
    uint32_t next_sign_count = 0;
    ZfCredentialIndexEntry selected_entry = {0};
    uint8_t status = ZF_CTAP_ERR_OTHER;
    size_t match_count = 1U;
    bool include_count = false;
    bool seed_assertion_queue = false;
    uint32_t phase_started = furi_get_tick();
    uint32_t resolve_ms = 0;
    uint32_t sign_ms = 0;

    if (!zf_ctap_begin_maintenance(app)) {
        return ZF_CTAP_ERR_NOT_ALLOWED;
    }
    *maintenance_acquired = true;

    if (resolve_match) {
        match_count =
            zf_ctap_resolve_assertion_matches_snapshot(app, request, uv_verified, scratch->matches);
        if (match_count == 0) {
            return ZF_CTAP_ERR_NO_CREDENTIALS;
        }
        record_index = scratch->matches[0];
    }
    resolve_ms = furi_get_tick() - phase_started;
    /*
     * tpm branch (2026-11-07): record lookup and signing take seconds on this
     * hardware. Without a touch prompt (a silent up=false pre-flight) nothing
     * else keeps the CTAPHID transaction alive, so the host can give up before
     * the answer arrives. Hardening note F10.
     */
    zf_transport_processing_keepalive(app, session_id);
    phase_started = furi_get_tick();
    /*
     * tpm branch (2026-11-06): with a PIN check (UV) and several passkeys for
     * the site, return the first one with numberOfCredentials and queue the
     * rest for getNextAssertion: Windows shows the account picker, with names,
     * on the PC screen (the CTAP 2.0 flow for authenticators without a
     * display). Without UV, names must not leave the device, so the caller
     * keeps the on-Flipper choice for that case.
     */
    include_count = !zf_ctap_request_uses_allow_list(request) && match_count > 1U &&
                    ((request->has_up && !request->up) || uv_verified);
    seed_assertion_queue = include_count;

    memset(&scratch->selected_record, 0, sizeof(scratch->selected_record));
    status = zf_ctap_load_and_prepare_assertion(
        app, &request->assertion, &scratch->pin_state, record_index, user_present, uv_verified,
        include_user_details, include_count, match_count, include_user_selected,
        include_user_selected, &scratch->selected_record, &selected_entry, scratch->work.store_io,
        sizeof(scratch->work.store_io), &scratch->work.response, &next_sign_count, out,
        out_capacity, out_len);
    sign_ms = furi_get_tick() - phase_started;
    zf_transport_processing_keepalive(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    /*
     * tpm branch (2026-11-07): how long the slow phases took. Record lookup and
     * signing cost seconds here, and that is what made the host give up before
     * the keepalives below were added.
     */
    ZF_TRACE(app->storage, "GAR m=%u idx=%u len=%u rs=%lu sg=%lu", (unsigned)match_count,
             (unsigned)record_index, (unsigned)(out_len ? *out_len : 0U),
             (unsigned long)resolve_ms, (unsigned long)sign_ms);

    if (poll_before_publish) {
        status = zf_transport_poll_cbor_control(app, session_id);
        if (status != ZF_CTAP_SUCCESS) {
            return status;
        }
    }

    return zf_ctap_publish_assertion_counter(
        app, &selected_entry, &scratch->selected_record, record_index, next_sign_count, session_id,
        request, uv_verified, scratch->matches, match_count, seed_assertion_queue,
        scratch->work.store_io, sizeof(scratch->work.store_io));
}

/*
 * Assertion handling has three security-relevant paths:
 * - up=false: no touch, no UP flag, queued continuation when multiple
 *   discoverable credentials match.
 * - multiple discoverable credentials without allowList: with UV the platform
 *   picks (numberOfCredentials + getNextAssertion, tpm branch); without UV the
 *   on-device UI selection chooses one.
 * - normal flow: touch approval, first match returned, optional continuation queue.
 *
 * Credential records are loaded from a snapshot and revalidated before counter
 * publication so deleted/replaced records cannot be signed or advanced stale.
 */
uint8_t zf_ctap_handle_get_assertion(ZerofidoApp *app, ZfTransportSessionId session_id,
                                     const uint8_t *data, size_t data_len, uint8_t *out,
                                     size_t out_capacity, size_t *out_len) {
    ZfGetAssertionScratch *scratch = zf_ctap_command_scratch(app, sizeof(*scratch));
    uint32_t started_at = furi_get_tick(); /* tpm branch: trace timing */
    size_t match_count = 0;
    bool uv_verified = false;
    bool uses_allow_list = false;
    bool maintenance_acquired = false;
    uint8_t status = ZF_CTAP_ERR_OTHER;
    ZfGetAssertionRequest *request = NULL;
    uint16_t *matches = NULL;

    ZF_CTAP_GA_DIAG("entry");
    if (!scratch) {
        return ZF_CTAP_ERR_OTHER;
    }
    ZF_CTAP_GA_DIAG("scratch");
    request = &scratch->request;
    matches = scratch->matches;
    request->allow_list.entries = scratch->work.descriptors;
    request->allow_list.capacity =
        sizeof(scratch->work.descriptors) / sizeof(scratch->work.descriptors[0]);

    status = zf_ctap_parse_get_assertion(data, data_len, request);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    ZF_CTAP_GA_DIAG("parsed");
    status = zf_ctap_validate_pin_auth_protocol(request->has_pin_auth, request->has_pin_protocol,
                                                request->pin_protocol,
                                                app->capabilities.pin_uv_auth_protocol_2_enabled);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    if (request->assertion.has_hmac_secret &&
        (!zf_pin_protocol_supported(request->assertion.hmac_secret_pin_protocol) ||
         (request->assertion.hmac_secret_pin_protocol == ZF_PIN_PROTOCOL_V2 &&
          !app->capabilities.pin_uv_auth_protocol_2_enabled))) {
        status = ZF_CTAP_ERR_INVALID_PARAMETER;
        goto cleanup;
    }
    if (request->assertion.has_hmac_secret && request->has_up && !request->up) {
        status = ZF_CTAP_ERR_UNSUPPORTED_OPTION;
        goto cleanup;
    }
    ZF_CTAP_GA_DIAG("clear queue");
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    zf_ctap_assertion_queue_clear(app);
    furi_mutex_release(app->ui_mutex);
    if (request->has_pin_auth && request->pin_auth_len == 0) {
        status = zf_ctap_handle_empty_pin_auth_probe(app, session_id, "Authenticate",
                                                     request->assertion.rp_id, "Touch required");
        goto cleanup;
    }
    if (zf_ctap_effective_uv_requested(request->has_pin_auth, request->has_uv, request->uv)) {
        status = ZF_CTAP_ERR_UNSUPPORTED_OPTION;
        goto cleanup;
    }
    uses_allow_list = zf_ctap_request_uses_allow_list(request);
    status = zf_ctap_require_pin_auth_with_state(
        app, &scratch->pin_state, request->has_uv && request->uv, request->has_pin_auth,
        request->assertion.client_data_hash, request->pin_auth, request->pin_auth_len,
        request->has_pin_protocol, request->pin_protocol, request->assertion.rp_id,
        ZF_PIN_PERMISSION_GA, &uv_verified);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    ZF_CTAP_GA_DIAG("pin ok");
    status = zf_transport_poll_cbor_control(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    if (request->has_up && !request->up) {
        ZF_CTAP_GA_DIAG("silent");

        status = zf_ctap_finish_assertion(app, session_id, request, scratch, true, 0, false,
                                          uv_verified, uv_verified && !uses_allow_list, false,
                                          false, &maintenance_acquired, out, out_capacity, out_len);
        goto cleanup;
    }

    match_count = zf_ctap_resolve_assertion_matches_snapshot(app, request, uv_verified, matches);
    ZF_CTAP_GA_DIAG("matches");

    /* tpm branch (2026-11-06): on-device choice only without a PIN check, see above. */
    if (!uses_allow_list && match_count > 1 && !uv_verified) {
        ZF_CTAP_GA_DIAG("select");
        uint32_t selected_record_index = 0;

        status =
            zf_ctap_request_assertion_selection(app, request->assertion.rp_id, matches, match_count,
                                                session_id, &selected_record_index);
        if (status != ZF_CTAP_SUCCESS) {
            goto cleanup;
        }
        status = zf_transport_poll_cbor_control(app, session_id);
        if (status != ZF_CTAP_SUCCESS) {
            goto cleanup;
        }
        status = zf_ctap_finish_assertion(app, session_id, request, scratch, false,
                                          selected_record_index, true, uv_verified, uv_verified,
                                          app->capabilities.advertise_fido_2_1, true,
                                          &maintenance_acquired, out, out_capacity, out_len);
        goto cleanup;
    }

    status = zf_ctap_request_approval(app, "Authenticate", request->assertion.rp_id,
                                      "Touch required", session_id);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    ZF_CTAP_GA_DIAG("approved");
    status = zf_transport_poll_cbor_control(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    ZF_CTAP_GA_DIAG("maintenance");

    status = zf_ctap_finish_assertion(app, session_id, request, scratch, true, 0, true, uv_verified,
                                      uv_verified && !uses_allow_list, false, true,
                                      &maintenance_acquired, out, out_capacity, out_len);
    ZF_CTAP_GA_DIAG("loaded");
    ZF_CTAP_GA_DIAG("response");
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    ZF_CTAP_GA_DIAG("counter");
    ZF_CTAP_GA_DIAG("success");

cleanup:
#if defined(ZF_RELEASE_DIAGNOSTICS) && ZF_RELEASE_DIAGNOSTICS
    if (status != ZF_CTAP_SUCCESS) {
        FURI_LOG_I("ZeroFIDO:CTAP", "GA error=%02X", status);
    }
    UNUSED(started_at);
#else
    /*
     * tpm branch (2026-11-07): uv and al were added while chasing a Windows
     * "this security key doesn't look familiar" on a credential that had just
     * been registered. Without them a NO_CREDENTIALS answer cannot be told
     * apart from a PIN-bound record hidden because the request carried no PIN.
     */
    ZF_TRACE(app->storage, "GA st=%02X ms=%lu up=%d uv=%d al=%d n=%u vault=%d/%d", status,
             (unsigned long)(furi_get_tick() - started_at),
             (request && request->has_up && !request->up) ? 0 : 1, uv_verified ? 1 : 0,
             uses_allow_list ? 1 : 0, (unsigned)match_count, zf_vault_is_present() ? 1 : 0,
             zf_vault_is_unlocked() ? 1 : 0);
#endif
    if (maintenance_acquired) {
        zf_ctap_end_maintenance(app);
    }
    zf_crypto_secure_zero(scratch, sizeof(*scratch));
    zf_app_command_scratch_release(app);
    return status;
}
