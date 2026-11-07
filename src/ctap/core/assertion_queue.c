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

#include "assertion_queue.h"

#include <string.h>

#include "../extensions/hmac_secret.h"
#include "../response.h"
#include "../../transport/adapter.h"
#include "../../zerofido_app_i.h"
#include "../../zerofido_crypto.h"
#include "../../zerofido_notify.h"
#include "../../zerofido_store.h"
#include "../../zerofido_trace.h"

static bool zf_get_next_sign_count(const ZfCredentialRecord *record, uint32_t *next_sign_count) {
    if (!record || !next_sign_count || record->sign_count == UINT32_MAX) {
        return false;
    }

    *next_sign_count = record->sign_count + 1;
    return true;
}

static bool zf_ctap_queue_entry_matches_record(const ZfCredentialIndexEntry *entry,
                                               const ZfCredentialRecord *record) {
    return entry && record && entry->in_use && record->in_use &&
           entry->credential_id_len == record->credential_id_len &&
           memcmp(entry->credential_id, record->credential_id, record->credential_id_len) == 0;
}

void zf_ctap_assertion_queue_clear(ZerofidoApp *app) {
    memset(&app->assertion_queue, 0, sizeof(app->assertion_queue));
}

static bool zf_ctap_assertion_queue_begin_maintenance(ZerofidoApp *app) {
    bool acquired = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!app->maintenance_busy) {
        app->maintenance_busy = true;
        acquired = true;
    }
    furi_mutex_release(app->ui_mutex);
    return acquired;
}

static void zf_ctap_assertion_queue_end_maintenance(ZerofidoApp *app) {
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->maintenance_busy = false;
    furi_mutex_release(app->ui_mutex);
}

void zerofido_ctap_invalidate_assertion_queue(ZerofidoApp *app) {
    if (!app) {
        return;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    zf_ctap_assertion_queue_clear(app);
    furi_mutex_release(app->ui_mutex);
}

/*
 * getNextAssertion state is a continuation of one getAssertion request. It is
 * bound to the original transport session, RP ID, match ordering, current queue
 * index, expiry window, and still-current credential index entries.
 */
void zf_ctap_assertion_queue_seed(ZerofidoApp *app, ZfTransportSessionId session_id,
                                  const ZfGetAssertionRequest *request, bool uv_verified,
                                  const uint16_t *match_indices, size_t match_count) {
    zf_ctap_assertion_queue_clear(app);
    if (match_count <= 1) {
        return;
    }

    app->assertion_queue.active = true;
    app->assertion_queue.session_id = session_id;
    app->assertion_queue.uv_verified = uv_verified;
    app->assertion_queue.user_present = !(request->has_up && !request->up);
    app->assertion_queue.count = match_count;
    app->assertion_queue.index = 1;
    app->assertion_queue.expires_at = furi_get_tick() + ZF_ASSERTION_QUEUE_TIMEOUT_MS;
    app->assertion_queue.request = request->assertion;

    memcpy(app->assertion_queue.record_indices, match_indices,
           sizeof(app->assertion_queue.record_indices[0]) * match_count);
}

static bool zf_ctap_assertion_queue_snapshot_entry_locked(ZerofidoApp *app, size_t record_index,
                                                          ZfCredentialIndexEntry *entry) {
    if (!app->store.records || record_index >= app->store.count ||
        !app->store.records[record_index].in_use) {
        return false;
    }

    *entry = app->store.records[record_index];
    return true;
}

static bool zf_ctap_assertion_queue_still_current_locked(ZerofidoApp *app,
                                                         ZfTransportSessionId session_id,
                                                         size_t queue_index, size_t record_index,
                                                         size_t count, const char *rp_id) {
    return app->assertion_queue.active && session_id == app->assertion_queue.session_id &&
           queue_index == app->assertion_queue.index && count == app->assertion_queue.count &&
           queue_index < app->assertion_queue.count &&
           app->assertion_queue.record_indices[queue_index] == record_index &&
           strcmp(app->assertion_queue.request.rp_id, rp_id) == 0;
}

static void zf_ctap_assertion_queue_clear_if_current(ZerofidoApp *app,
                                                     ZfTransportSessionId session_id,
                                                     size_t queue_index, size_t record_index,
                                                     size_t count, const char *rp_id) {
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (zf_ctap_assertion_queue_still_current_locked(app, session_id, queue_index, record_index,
                                                     count, rp_id)) {
        zf_ctap_assertion_queue_clear(app);
    }
    furi_mutex_release(app->ui_mutex);
}

/*
 * Serves one queued continuation response. The record is loaded from the queued
 * index snapshot, then the queue and credential identity are checked again under
 * ui_mutex immediately before publishing the counter and advancing the queue.
 */
uint8_t zf_ctap_assertion_queue_handle_next(ZerofidoApp *app, ZfTransportSessionId session_id,
                                            uint8_t *out, size_t out_capacity, size_t *out_len) {
    typedef struct {
        ZfAssertionRequestData request;
        ZfClientPinState pin_state;
        ZfCredentialIndexEntry entry;
        ZfCredentialRecord record;
        union {
            ZfAssertionResponseScratch response;
            uint8_t store_io[ZF_STORE_RECORD_IO_SIZE];
        } work;
    } ZfAssertionQueueScratch;

    _Static_assert(sizeof(ZfAssertionQueueScratch) <= ZF_COMMAND_SCRATCH_SIZE,
                   "getNextAssertion scratch exceeds command arena");

    uint8_t status = ZF_CTAP_ERR_OTHER;
    ZfAssertionQueueScratch *scratch = NULL;
    size_t queue_index = 0;
    size_t record_index = 0;
    size_t match_count = 0;
    bool user_present = false;
    bool uv_verified = false;
    uint32_t next_sign_count = 0;
    uint32_t prepared_counter_high_water = 0;
    bool maintenance_acquired = false;
    /* tpm branch (2026-11-07): where the seconds per queued account go. */
    uint32_t phase_started = furi_get_tick();
    uint32_t load_ms = 0;
    uint32_t sign_ms = 0;

    if (!app) {
        return ZF_CTAP_ERR_OTHER;
    }
    status = zf_transport_poll_cbor_control(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        zf_ctap_assertion_queue_clear(app);
        furi_mutex_release(app->ui_mutex);
        return status;
    }

    if (!zf_ctap_assertion_queue_begin_maintenance(app)) {
        return ZF_CTAP_ERR_NOT_ALLOWED;
    }
    maintenance_acquired = true;

    scratch = zf_app_command_scratch_acquire(app, sizeof(*scratch));
    if (!scratch) {
        status = ZF_CTAP_ERR_OTHER;
        goto cleanup;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!app->assertion_queue.active ||
        (int32_t)(furi_get_tick() - app->assertion_queue.expires_at) >= 0 ||
        app->assertion_queue.index >= app->assertion_queue.count) {
        zf_ctap_assertion_queue_clear(app);
        status = ZF_CTAP_ERR_NOT_ALLOWED;
        furi_mutex_release(app->ui_mutex);
        goto cleanup;
    }
    if (session_id != app->assertion_queue.session_id) {
        status = ZF_CTAP_ERR_INVALID_CHANNEL;
        furi_mutex_release(app->ui_mutex);
        goto cleanup;
    }

    scratch->request = app->assertion_queue.request;
    scratch->pin_state = app->pin_state;

    queue_index = app->assertion_queue.index;
    record_index = app->assertion_queue.record_indices[queue_index];
    match_count = app->assertion_queue.count;
    user_present = app->assertion_queue.user_present;
    uv_verified = app->assertion_queue.uv_verified;
    if (!zf_ctap_assertion_queue_snapshot_entry_locked(app, record_index, &scratch->entry)) {
        zf_ctap_assertion_queue_clear(app);
        status = ZF_CTAP_ERR_NOT_ALLOWED;
        furi_mutex_release(app->ui_mutex);
        goto cleanup;
    }
    furi_mutex_release(app->ui_mutex);

    /*
     * tpm branch (2026-11-07): a queued entry costs about two seconds (record
     * read, signature, counter write). Keep the CTAPHID transaction alive, or
     * the host gives up on a long account list. Never under ui_mutex: the
     * keepalive polls the transport and would re-enter it.
     */
    zf_transport_processing_keepalive(app, session_id);

    if (!zf_store_load_record_with_buffer(app->storage, &scratch->entry, &scratch->record,
                                          scratch->work.store_io, sizeof(scratch->work.store_io)) ||
        strcmp(scratch->record.rp_id, scratch->request.rp_id) != 0 ||
        !zf_ctap_queue_entry_matches_record(&scratch->entry, &scratch->record)) {
        status = ZF_CTAP_ERR_NOT_ALLOWED;
        zf_ctap_assertion_queue_clear_if_current(app, session_id, queue_index, record_index,
                                                 match_count, scratch->request.rp_id);
        goto cleanup;
    }

    load_ms = furi_get_tick() - phase_started;
    phase_started = furi_get_tick();
    zf_transport_processing_keepalive(app, session_id);
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
    zf_store_counter_base_from_index(&scratch->entry, &scratch->record);
    if (!zf_get_next_sign_count(&scratch->record, &next_sign_count)) {
        status = ZF_CTAP_ERR_OTHER;
        zf_ctap_assertion_queue_clear_if_current(app, session_id, queue_index, record_index,
                                                 match_count, scratch->request.rp_id);
        goto cleanup;
    }

    size_t extension_data_len = 0;
    status = zf_ctap_hmac_secret_build_extension(
        &scratch->pin_state, &scratch->request, &scratch->record, uv_verified,
        &scratch->work.response.hmac_secret, scratch->work.response.extension_data,
        sizeof(scratch->work.response.extension_data), &extension_data_len);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    status = zf_ctap_build_assertion_response_with_scratch(
        &scratch->work.response, &scratch->request, &scratch->record, user_present, uv_verified,
        next_sign_count, uv_verified, false, match_count, false, false,
        scratch->work.response.extension_data, extension_data_len, out, out_capacity, out_len);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    sign_ms = furi_get_tick() - phase_started;
    phase_started = furi_get_tick();
    zf_transport_processing_keepalive(app, session_id);

    status = zf_transport_poll_cbor_control(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        zf_ctap_assertion_queue_clear_if_current(app, session_id, queue_index, record_index,
                                                 match_count, scratch->request.rp_id);
        goto cleanup;
    }
    scratch->record.sign_count = next_sign_count;
    if (!zf_store_prepare_counter_advance(app->storage, &scratch->entry, &scratch->record,
                                          scratch->work.store_io, sizeof(scratch->work.store_io),
                                          &prepared_counter_high_water)) {
        zf_ctap_assertion_queue_clear_if_current(app, session_id, queue_index, record_index,
                                                 match_count, scratch->request.rp_id);
        status = ZF_CTAP_ERR_OTHER;
        goto cleanup;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    bool queue_current = zf_ctap_assertion_queue_still_current_locked(
        app, session_id, queue_index, record_index, match_count, scratch->request.rp_id);
    bool record_current =
        queue_current && app->store.records && record_index < app->store.count &&
        zf_ctap_queue_entry_matches_record(&app->store.records[record_index], &scratch->record);
    if (!record_current) {
        if (queue_current) {
            zf_ctap_assertion_queue_clear(app);
        }
        status = ZF_CTAP_ERR_NOT_ALLOWED;
        furi_mutex_release(app->ui_mutex);
        goto cleanup;
    }
    if (!zf_store_publish_counter_advance(&app->store, &scratch->record,
                                          prepared_counter_high_water)) {
        zf_ctap_assertion_queue_clear(app);
        status = ZF_CTAP_ERR_OTHER;
        furi_mutex_release(app->ui_mutex);
        goto cleanup;
    }
    app->assertion_queue.index = queue_index + 1U;
    app->assertion_queue.expires_at = furi_get_tick() + ZF_ASSERTION_QUEUE_TIMEOUT_MS;
    if (app->assertion_queue.index >= app->assertion_queue.count) {
        zf_ctap_assertion_queue_clear(app);
    }
    furi_mutex_release(app->ui_mutex);
    /*
     * tpm branch (2026-11-07): no success buzz per queued account. A sign-in
     * without a user name makes the PC walk the whole list through
     * getNextAssertion, and one buzz per entry reads as the key misbehaving
     * (owner, 2026-11-07: "endless login and the Flipper kept vibrating").
     * The buzz for the assertion the user approved already happened in
     * getAssertion; these entries are the PC building its account list.
     */

cleanup:
    /*
     * tpm branch (2026-11-07): getNextAssertion is how a PC builds the account
     * list for a sign-in without a user name. Without this line a client that
     * never asks cannot be told from one we answer badly.
     */
    ZF_TRACE(app->storage, "GN st=%02X i=%u/%u ld=%lu sg=%lu ct=%lu", status,
             (unsigned)queue_index, (unsigned)match_count, (unsigned long)load_ms,
             (unsigned long)sign_ms, (unsigned long)(furi_get_tick() - phase_started));
    if (maintenance_acquired) {
        zf_ctap_assertion_queue_end_maintenance(app);
    }
    if (scratch) {
        zf_crypto_secure_zero(scratch, sizeof(*scratch));
    }
    zf_app_command_scratch_release(app);
    return status;
}
