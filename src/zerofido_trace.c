/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-05: new file.
 * See zerofido_trace.h.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#include "zerofido_trace.h"

#if ZF_TPM_TRACE

#include <furi.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zerofido_storage.h"
#include "zerofido_types.h"

#define ZF_TRACE_PATH ZF_APP_DATA_DIR "/trace.txt"
#define ZF_TRACE_MAX_BYTES 16384U

static void zf_trace_append_file(Storage *storage, const char *data, size_t len);

static void zf_trace_v(Storage *storage, const char *fmt, va_list args) {
    char line[112];
    int prefix = 0;
    int body = 0;

    if (!storage || !fmt) {
        return;
    }
    prefix = snprintf(line, sizeof(line), "%lu ", (unsigned long)furi_get_tick());
    if (prefix < 0 || (size_t)prefix >= sizeof(line)) {
        return;
    }
    body = vsnprintf(line + prefix, sizeof(line) - (size_t)prefix - 1U, fmt, args);
    if (body < 0) {
        return;
    }
    size_t len = (size_t)prefix + (size_t)body;
    if (len > sizeof(line) - 2U) {
        len = sizeof(line) - 2U;
    }
    line[len++] = '\n';

    if (zf_storage_ensure_app_data_dir(storage)) {
        zf_trace_append_file(storage, line, len);
    }
}

void zf_trace(Storage *storage, const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    zf_trace_v(storage, fmt, args);
    va_end(args);
}

static void zf_trace_append_file(Storage *storage, const char *data, size_t len) {
    File *file = storage_file_alloc(storage);

    if (!file) {
        return;
    }
    if (storage_file_open(file, ZF_TRACE_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
        if (storage_file_size(file) > ZF_TRACE_MAX_BYTES) {
            storage_file_close(file);
            storage_file_open(file, ZF_TRACE_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS);
        }
        storage_file_write(file, data, len);
    }
    storage_file_close(file);
    storage_file_free(file);
}

#endif
