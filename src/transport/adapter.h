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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "dispatch.h"

typedef struct ZerofidoApp ZerofidoApp;

typedef struct {
    int32_t (*worker)(void *context);
    size_t worker_stack_size;
    void (*stop)(ZerofidoApp *app);
    void (*send_dispatch_result)(ZerofidoApp *app, const ZfProtocolDispatchRequest *request,
                                 const ZfProtocolDispatchResult *result);
    bool (*wait_for_interaction)(ZerofidoApp *app, ZfTransportSessionId current_session_id,
                                 bool *approved);
    void (*notify_interaction_changed)(ZerofidoApp *app);
    uint8_t (*poll_cbor_control)(ZerofidoApp *app, ZfTransportSessionId current_session_id);
} ZfTransportAdapterOps;

/* tpm branch: keepalive during long command work. */
void zf_transport_processing_keepalive(ZerofidoApp *app, ZfTransportSessionId current_session_id);

/*
 * Transport adapters let CTAP/U2F command code be agnostic to USB HID versus
 * Bluetooth LE. Each adapter owns its worker loop, response publication,
 * keepalive/cancel polling, and local user-interaction waiting semantics.
 *
 * tpm branch (2026-11-06): the NFC adapter is gone with the NFC transport
 * (owner: "NFC out of the project — too complicated and not needed"). The
 * upstream project still has it; see README.
 */
#ifndef ZF_USB_ONLY
extern const ZfTransportAdapterOps zf_transport_usb_hid_adapter;
#endif
#if ZF_BLE_ENABLED && !defined(ZF_USB_ONLY)
extern const ZfTransportAdapterOps zf_transport_ble_adapter;
#endif

void zf_transport_stop(ZerofidoApp *app);
void zf_transport_send_dispatch_result(ZerofidoApp *app, const ZfProtocolDispatchRequest *request,
                                       const ZfProtocolDispatchResult *result);
bool zf_transport_wait_for_interaction(ZerofidoApp *app, ZfTransportSessionId current_session_id,
                                       bool *approved);
void zf_transport_notify_interaction_changed(ZerofidoApp *app);
uint8_t zf_transport_poll_cbor_control(ZerofidoApp *app, ZfTransportSessionId current_session_id);
