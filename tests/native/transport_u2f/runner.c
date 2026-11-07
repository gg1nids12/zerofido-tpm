#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZF_AUTO_ACCEPT_REQUESTS 1
#define ZF_DEV_FIDO2_1 1

#include "furi.h"
#include "furi_hal.h"
#include "furi_hal_random.h"
#include "furi_hal_usb_hid_u2f.h"
#include "flipper_format/flipper_format.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "storage/storage.h"
#include "crypto/ecdsa_der.h"
#include "zerofido_crypto.h"
#include "zerofido_ui_format.h"

/*
 * Host-native transport/U2F regression harness. It stubs USB, storage, UI,
 * and crypto boundaries so the production transport and U2F modules can be
 * tested as compiled C on the workstation.
 */

#define FURI_PACKED __attribute__((packed))
#define FURI_LOG_E(tag, fmt, ...) ((void)0)
#define FURI_LOG_W(tag, fmt, ...) ((void)0)
#define FURI_LOG_D(tag, fmt, ...) ((void)0)
#define furi_assert(expr) ((void)(expr))

#define FURI_LOG_I(tag, fmt, ...) ((void)0)

typedef int FuriStatus;
typedef struct ZerofidoApp ZerofidoApp;
static bool test_transport_auto_accept_enabled(const ZerofidoApp *app);

struct Storage {
    int unused;
};

struct File {
    char path[160];
    FS_AccessMode access_mode;
    size_t offset;
    bool open;
};

struct FileInfo {
    int unused;
};

struct FlipperFormat {
    int unused;
};

struct FuriString {
    char value[64];
};

struct FuriHalUsbInterface {
    int unused;
};

struct FuriThread {
    FuriThreadCallback callback;
    void *context;
    size_t stack_size;
    FuriThreadPriority priority;
    bool started;
    bool joined;
    bool freed;
};

struct FuriSemaphore {
    int unused;
};

struct FuriTimer {
    FuriTimerCallback callback;
    void *context;
    FuriTimerType type;
    uint32_t last_timeout;
    size_t start_count;
    size_t stop_count;
    bool running;
};

struct FuriMutex {
    size_t depth;
};

struct BitBuffer {
    uint8_t *data;
    size_t size_bits;
    size_t size_bytes;
    size_t capacity;
};

#define FuriStatusOk 0
#define FuriFlagError 0x80000000U
#define FuriFlagErrorTimeout 0xFFFFFFFEU
#define FuriFlagWaitAny 0U
#define FuriWaitForever 0U

static uint32_t g_fake_tick = 0;
static uint32_t g_random_values[16];
static size_t g_random_count = 0;
static size_t g_random_index = 0;
static uint32_t g_thread_flag_results[8];
static size_t g_thread_flag_result_count = 0;
static size_t g_thread_flag_result_index = 0;
static uint32_t g_last_thread_flags_set = 0;
static size_t g_thread_flags_set_count = 0;
static uint32_t g_last_thread_wait_timeout = 0;
static size_t g_thread_flag_wait_call_count = 0;
static uint32_t g_last_delay_ms = 0;
static size_t g_delay_ms_count = 0;
static FuriMutex *g_thread_start_observed_mutex = NULL;
static size_t g_thread_start_observed_depth = 0;
static size_t g_thread_join_count = 0;
static size_t g_thread_free_count = 0;
static FuriMutex *g_thread_join_observed_mutex = NULL;
static size_t g_thread_join_observed_depth = 0;
static FuriStatus g_semaphore_results[8];
static size_t g_semaphore_result_count = 0;
static size_t g_semaphore_result_index = 0;
static size_t g_cancel_pending_interaction_count = 0;
static bool g_cancel_pending_interaction_result = false;
static size_t g_approval_request_count = 0;
static char g_last_approval_rp_id[64];
static bool g_auto_accept_requests = false;
static size_t g_transport_connected_set_count = 0;
static size_t g_transport_connected_true_count = 0;
static bool g_last_transport_connected = false;
static size_t g_notify_prompt_count = 0;
static uint8_t g_last_hid_response[64];
static size_t g_last_hid_response_len = 0;
static size_t g_hid_response_count = 0;
static size_t g_mutex_max_depth = 0;
static char g_last_status_text[64];
static bool g_ctap2_saw_transport_auto_accept = false;
static bool g_ctap2_request_response_overlap = false;
static size_t g_ctap2_large_response_len = 0U;
static bool g_get_info_builder_called = false;
static bool g_get_info_builder_saw_usb_transport = false;
static bool g_u2f_cert_assets_present = true;
static bool g_u2f_cert_check_result = true;
static bool g_u2f_cert_key_load_result = true;
static bool g_u2f_cert_key_matches_result = true;
static size_t g_u2f_attestation_ensure_call_count = 0;
static bool g_u2f_attestation_ensure_result = true;
static bool g_u2f_key_exists_result = true;
static bool g_u2f_key_load_result = true;
static size_t g_u2f_key_generate_count = 0;
static bool g_u2f_cnt_exists_result = true;
static bool g_u2f_cnt_read_result = true;
static size_t g_u2f_cnt_write_count = 0;
static uint32_t g_u2f_last_written_counter = 0;
static size_t g_u2f_cnt_reserve_count = 0;
static uint32_t g_u2f_last_reserved_counter = 0;
static uint8_t g_hid_request_packets[8][64];
static size_t g_hid_request_packet_lens[8];
static size_t g_hid_request_count = 0;
static size_t g_hid_request_index = 0;
static bool g_hid_connected = false;
static bool g_usb_set_config_result = true;
static size_t g_usb_set_config_count = 0;
static const FuriHalUsbInterface *g_last_usb_set_config = NULL;
static FuriHalUsbInterface g_previous_usb_config = {1};
static uint8_t g_sha256_trace[4096];
static size_t g_sha256_trace_len = 0;
#define TEST_STORAGE_MAX_FILE_SIZE 128
typedef struct {
    bool in_use;
    char path[128];
    uint8_t data[TEST_STORAGE_MAX_FILE_SIZE];
    size_t size;
    bool exists;
} TestStorageFile;
static bool g_storage_root_exists = true;
static bool g_storage_app_data_exists = true;
static const char *g_storage_fail_write_match = NULL;
static TestStorageFile g_storage_files[4];
static FuriTimer g_timer_pool[8];
static size_t g_timer_pool_count = 0;

;

static void expect(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void test_reset(void) {
    g_fake_tick = 0;
    memset(g_random_values, 0, sizeof(g_random_values));
    g_random_count = 0;
    g_random_index = 0;
    memset(g_thread_flag_results, 0, sizeof(g_thread_flag_results));
    g_thread_flag_result_count = 0;
    g_thread_flag_result_index = 0;
    g_last_thread_flags_set = 0;
    g_thread_flags_set_count = 0;
    g_last_thread_wait_timeout = 0;
    g_thread_flag_wait_call_count = 0;
    g_last_delay_ms = 0;
    g_delay_ms_count = 0;
    g_thread_start_observed_mutex = NULL;
    g_thread_start_observed_depth = 0;
    g_thread_join_count = 0;
    g_thread_free_count = 0;
    g_thread_join_observed_mutex = NULL;
    g_thread_join_observed_depth = 0;
    memset(g_semaphore_results, 0, sizeof(g_semaphore_results));
    g_semaphore_result_count = 0;
    g_semaphore_result_index = 0;
    g_cancel_pending_interaction_count = 0;
    g_cancel_pending_interaction_result = false;
    g_approval_request_count = 0;
    memset(g_last_approval_rp_id, 0, sizeof(g_last_approval_rp_id));
    g_auto_accept_requests = false;
    g_transport_connected_set_count = 0;
    g_transport_connected_true_count = 0;
    g_last_transport_connected = false;
    g_notify_prompt_count = 0;
    memset(g_last_hid_response, 0, sizeof(g_last_hid_response));
    g_last_hid_response_len = 0;
    g_hid_response_count = 0;
    g_mutex_max_depth = 0;
    memset(g_last_status_text, 0, sizeof(g_last_status_text));
    g_ctap2_saw_transport_auto_accept = false;
    g_ctap2_request_response_overlap = false;
    g_ctap2_large_response_len = 0U;
    g_get_info_builder_called = false;
    g_get_info_builder_saw_usb_transport = false;
    g_u2f_cert_assets_present = true;
    g_u2f_cert_check_result = true;
    g_u2f_cert_key_load_result = true;
    g_u2f_cert_key_matches_result = true;
    g_u2f_attestation_ensure_call_count = 0;
    g_u2f_attestation_ensure_result = true;
    g_u2f_key_exists_result = true;
    g_u2f_key_load_result = true;
    g_u2f_key_generate_count = 0;
    g_u2f_cnt_exists_result = true;
    g_u2f_cnt_read_result = true;
    g_u2f_cnt_write_count = 0;
    g_u2f_last_written_counter = 0;
    g_u2f_cnt_reserve_count = 0;
    g_u2f_last_reserved_counter = 0;
    memset(g_hid_request_packets, 0, sizeof(g_hid_request_packets));
    memset(g_hid_request_packet_lens, 0, sizeof(g_hid_request_packet_lens));
    g_hid_request_count = 0;
    g_hid_request_index = 0;
    g_hid_connected = false;
    g_usb_set_config_result = true;
    g_usb_set_config_count = 0;
    g_last_usb_set_config = NULL;
    g_previous_usb_config.unused = 1;
    memset(g_sha256_trace, 0, sizeof(g_sha256_trace));
    g_sha256_trace_len = 0;
    g_storage_root_exists = true;
    g_storage_app_data_exists = true;
    g_storage_fail_write_match = NULL;
    memset(g_storage_files, 0, sizeof(g_storage_files));
    memset(g_timer_pool, 0, sizeof(g_timer_pool));
    g_timer_pool_count = 0;
}

uint32_t furi_get_tick(void) {
    return g_fake_tick;
}

uint32_t furi_hal_random_get(void) {
    if (g_random_index < g_random_count) {
        return g_random_values[g_random_index++];
    }

    return 0xA5A50000U + (uint32_t)g_random_index++;
}

void furi_hal_random_fill_buf(void *buffer, size_t size) {
    memset(buffer, 0xA5, size);
}

bool furi_hal_crypto_enclave_load_key(uint8_t slot, const uint8_t *iv) {
    UNUSED(slot);
    UNUSED(iv);
    return true;
}

bool furi_hal_crypto_enclave_ensure_key(uint8_t slot) {
    UNUSED(slot);
    return true;
}

void furi_hal_crypto_enclave_unload_key(uint8_t slot) {
    UNUSED(slot);
}

bool furi_hal_crypto_load_key(const uint8_t *key, const uint8_t *iv) {
    UNUSED(key);
    UNUSED(iv);
    return true;
}

bool furi_hal_crypto_unload_key(void) {
    return true;
}

bool furi_hal_crypto_encrypt(const uint8_t *input, uint8_t *output, size_t size) {
    memcpy(output, input, size);
    return true;
}

bool furi_hal_crypto_decrypt(const uint8_t *input, uint8_t *output, size_t size) {
    memcpy(output, input, size);
    return true;
}

FuriThreadId furi_thread_get_current_id(void) {
    return (FuriThreadId)0x1;
}

uint32_t furi_thread_get_stack_space(FuriThreadId thread_id) {
    UNUSED(thread_id);
    return 4096U;
}

FuriThreadId furi_thread_get_id(FuriThread *thread) {
    UNUSED(thread);
    return (FuriThreadId)0x2;
}

uint32_t furi_thread_flags_set(FuriThreadId thread_id, uint32_t flags) {
    UNUSED(thread_id);
    g_last_thread_flags_set = flags;
    g_thread_flags_set_count++;
    return 0;
}

uint32_t furi_thread_flags_get(void) {
    return 0;
}

uint32_t furi_thread_flags_clear(uint32_t flags) {
    UNUSED(flags);
    return 0;
}

uint32_t furi_thread_flags_wait(uint32_t flags, uint32_t options, uint32_t timeout) {
    UNUSED(flags);
    UNUSED(options);
    g_last_thread_wait_timeout = timeout;
    g_thread_flag_wait_call_count++;
    if (g_thread_flag_result_index < g_thread_flag_result_count) {
        return g_thread_flag_results[g_thread_flag_result_index++];
    }
    return FuriFlagErrorTimeout;
}

FuriThread *furi_thread_alloc_ex(const char *name, size_t stack_size, FuriThreadCallback callback,
                                 void *context) {
    FuriThread *thread = malloc(sizeof(*thread));
    UNUSED(name);
    if (!thread) {
        return NULL;
    }
    memset(thread, 0, sizeof(*thread));
    thread->callback = callback;
    thread->context = context;
    thread->stack_size = stack_size;
    return thread;
}

void furi_thread_set_appid(FuriThread *thread, const char *appid) {
    UNUSED(thread);
    UNUSED(appid);
}

void furi_thread_set_priority(FuriThread *thread, FuriThreadPriority priority) {
    if (thread) {
        thread->priority = priority;
    }
}

void furi_thread_start(FuriThread *thread) {
    if (thread) {
        if (g_thread_start_observed_mutex) {
            g_thread_start_observed_depth = g_thread_start_observed_mutex->depth;
        }
        thread->started = true;
    }
}

void furi_thread_join(FuriThread *thread) {
    if (thread) {
        g_thread_join_count++;
        if (g_thread_join_observed_mutex) {
            g_thread_join_observed_depth = g_thread_join_observed_mutex->depth;
        }
        thread->joined = true;
    }
}

void furi_thread_free(FuriThread *thread) {
    if (thread) {
        g_thread_free_count++;
        thread->freed = true;
        free(thread);
    }
}

void furi_delay_ms(uint32_t milliseconds) {
    g_last_delay_ms = milliseconds;
    g_delay_ms_count++;
}

FuriStatus furi_semaphore_acquire(FuriSemaphore *sem, uint32_t timeout) {
    UNUSED(sem);
    UNUSED(timeout);
    if (g_semaphore_result_index < g_semaphore_result_count) {
        return g_semaphore_results[g_semaphore_result_index++];
    }
    return 1;
}

FuriStatus furi_semaphore_release(FuriSemaphore *sem) {
    UNUSED(sem);
    return FuriStatusOk;
}

FuriStatus furi_mutex_acquire(FuriMutex *mutex, uint32_t timeout) {
    UNUSED(timeout);
    if (mutex) {
        mutex->depth++;
        if (mutex->depth > g_mutex_max_depth) {
            g_mutex_max_depth = mutex->depth;
        }
    }
    return FuriStatusOk;
}

void furi_mutex_release(FuriMutex *mutex) {
    if (mutex && mutex->depth > 0U) {
        mutex->depth--;
    }
}

FuriTimer *furi_timer_alloc(FuriTimerCallback callback, FuriTimerType type, void *context) {
    FuriTimer *timer = NULL;

    expect(g_timer_pool_count < (sizeof(g_timer_pool) / sizeof(g_timer_pool[0])),
           "timer pool should have free slots");
    timer = &g_timer_pool[g_timer_pool_count++];
    memset(timer, 0, sizeof(*timer));
    timer->callback = callback;
    timer->context = context;
    timer->type = type;
    return timer;
}

void furi_timer_free(FuriTimer *timer) {
    if (timer) {
        timer->running = false;
    }
}

void furi_timer_start(FuriTimer *timer, uint32_t timeout) {
    expect(timer != NULL, "timer start should receive a timer");
    timer->last_timeout = timeout;
    timer->start_count++;
    timer->running = true;
}

void furi_timer_stop(FuriTimer *timer) {
    expect(timer != NULL, "timer stop should receive a timer");
    timer->stop_count++;
    timer->running = false;
}

static TestStorageFile *test_storage_file_slot(const char *path, bool create) {
    size_t free_index = SIZE_MAX;

    for (size_t i = 0; i < (sizeof(g_storage_files) / sizeof(g_storage_files[0])); ++i) {
        if (g_storage_files[i].in_use && strcmp(g_storage_files[i].path, path) == 0) {
            return &g_storage_files[i];
        }
        if (create && free_index == SIZE_MAX && !g_storage_files[i].in_use) {
            free_index = i;
        }
    }

    if (!create || free_index == SIZE_MAX) {
        return NULL;
    }

    g_storage_files[free_index].in_use = true;
    strncpy(g_storage_files[free_index].path, path, sizeof(g_storage_files[free_index].path) - 1);
    g_storage_files[free_index].path[sizeof(g_storage_files[free_index].path) - 1] = '\0';
    return &g_storage_files[free_index];
}

bool file_info_is_dir(const FileInfo *info) {
    UNUSED(info);
    return false;
}

FS_Error storage_common_remove(Storage *storage, const char *path) {
    TestStorageFile *slot = NULL;

    UNUSED(storage);
    slot = test_storage_file_slot(path, false);
    if (!slot || !slot->exists) {
        return FSE_NOT_EXIST;
    }

    slot->exists = false;
    slot->size = 0;
    memset(slot->data, 0, sizeof(slot->data));
    return FSE_OK;
}

FS_Error storage_common_copy(Storage *storage, const char *old_path, const char *new_path) {
    TestStorageFile *old_slot = NULL;
    TestStorageFile *new_slot = NULL;

    UNUSED(storage);
    old_slot = test_storage_file_slot(old_path, false);
    new_slot = test_storage_file_slot(new_path, true);
    if (!old_slot || !new_slot || !old_slot->exists) {
        return FSE_NOT_EXIST;
    }

    memcpy(new_slot->data, old_slot->data, old_slot->size);
    new_slot->size = old_slot->size;
    new_slot->exists = true;
    return FSE_OK;
}

FS_Error storage_common_rename(Storage *storage, const char *old_path, const char *new_path) {
    TestStorageFile *old_slot = NULL;
    FS_Error copy_result = FSE_NOT_EXIST;

    old_slot = test_storage_file_slot(old_path, false);
    if (!old_slot || !old_slot->exists) {
        return FSE_NOT_EXIST;
    }

    if (storage_file_exists(storage, new_path)) {
        storage_common_remove(storage, new_path);
    }
    copy_result = storage_common_copy(storage, old_path, new_path);
    if (copy_result != FSE_OK) {
        return copy_result;
    }

    old_slot->exists = false;
    old_slot->size = 0;
    memset(old_slot->data, 0, sizeof(old_slot->data));
    return FSE_OK;
}

bool storage_dir_exists(Storage *storage, const char *path) {
    UNUSED(storage);
    if (strcmp(path, "/ext/apps_data") == 0) {
        return g_storage_root_exists;
    }
    if (strcmp(path, "/ext/apps_data/zerofido") == 0) {
        return g_storage_app_data_exists;
    }
    return false;
}

bool storage_simply_mkdir(Storage *storage, const char *path) {
    UNUSED(storage);
    if (strcmp(path, "/ext/apps_data") == 0) {
        g_storage_root_exists = true;
        return true;
    }
    if (strcmp(path, "/ext/apps_data/zerofido") == 0) {
        g_storage_app_data_exists = true;
        return true;
    }
    return false;
}

bool storage_file_exists(Storage *storage, const char *path) {
    TestStorageFile *slot = NULL;

    UNUSED(storage);
    slot = test_storage_file_slot(path, false);
    return slot && slot->exists;
}

bool storage_dir_open(File *file, const char *path) {
    UNUSED(file);
    UNUSED(path);
    return false;
}

bool storage_dir_read(File *file, FileInfo *info, char *name, size_t name_size) {
    UNUSED(file);
    UNUSED(info);
    UNUSED(name);
    UNUSED(name_size);
    return false;
}

void storage_dir_close(File *file) {
    UNUSED(file);
}

File *storage_file_alloc(Storage *storage) {
    static File files[2];
    static size_t next_file = 0;
    File *file = NULL;

    UNUSED(storage);
    file = &files[next_file++ % (sizeof(files) / sizeof(files[0]))];
    memset(file, 0, sizeof(*file));
    return file;
}

void storage_file_free(File *file) {
    UNUSED(file);
}

bool storage_file_open(File *file, const char *path, FS_AccessMode access_mode,
                       FS_OpenMode open_mode) {
    TestStorageFile *slot = NULL;

    if (strncmp(path, "/ext/apps_data/zerofido/", strlen("/ext/apps_data/zerofido/")) == 0 &&
        !g_storage_app_data_exists) {
        return false;
    }

    slot = test_storage_file_slot(path,
                                  access_mode == FSAM_WRITE &&
                                      (open_mode == FSOM_CREATE_ALWAYS ||
                                       open_mode == FSOM_OPEN_APPEND));
    if (!slot) {
        return false;
    }
    if (access_mode == FSAM_READ && (!slot->exists || open_mode != FSOM_OPEN_EXISTING)) {
        return false;
    }
    if (access_mode == FSAM_WRITE && open_mode == FSOM_CREATE_ALWAYS) {
        slot->size = 0;
        slot->exists = true;
        memset(slot->data, 0, sizeof(slot->data));
    }
    if (access_mode == FSAM_WRITE && open_mode == FSOM_OPEN_APPEND) {
        slot->exists = true;
    }

    strncpy(file->path, path, sizeof(file->path) - 1);
    file->path[sizeof(file->path) - 1] = '\0';
    file->access_mode = access_mode;
    file->offset = (access_mode == FSAM_WRITE && open_mode == FSOM_OPEN_APPEND) ? slot->size : 0U;
    file->open = true;
    return true;
}

size_t storage_file_size(File *file) {
    TestStorageFile *slot = NULL;

    if (!file->open) {
        return 0;
    }
    slot = test_storage_file_slot(file->path, false);
    if (!slot || !slot->exists) {
        return 0;
    }
    return slot->size;
}

size_t storage_file_read(File *file, void *buffer, size_t size) {
    TestStorageFile *slot = NULL;
    size_t remaining = 0;

    if (!file->open || file->access_mode != FSAM_READ) {
        return 0;
    }
    slot = test_storage_file_slot(file->path, false);
    if (!slot || !slot->exists || file->offset >= slot->size) {
        return 0;
    }

    remaining = slot->size - file->offset;
    if (size > remaining) {
        size = remaining;
    }
    memcpy(buffer, slot->data + file->offset, size);
    file->offset += size;
    return size;
}

size_t storage_file_write(File *file, const void *buffer, size_t size) {
    TestStorageFile *slot = NULL;

    if (!file->open || file->access_mode != FSAM_WRITE) {
        return 0;
    }
    if (g_storage_fail_write_match && strstr(file->path, g_storage_fail_write_match) != NULL) {
        return 0;
    }
    slot = test_storage_file_slot(file->path, true);
    if (!slot || (file->offset + size) > sizeof(slot->data)) {
        return 0;
    }

    memcpy(slot->data + file->offset, buffer, size);
    file->offset += size;
    if (file->offset > slot->size) {
        slot->size = file->offset;
    }
    slot->exists = true;
    return size;
}

void storage_file_close(File *file) {
    file->open = false;
}

FlipperFormat *flipper_format_file_alloc(Storage *storage) {
    static FlipperFormat flipper_format;

    UNUSED(storage);
    return &flipper_format;
}

void flipper_format_free(FlipperFormat *flipper_format) {
    UNUSED(flipper_format);
}

bool flipper_format_file_open_always(FlipperFormat *flipper_format, const char *path) {
    UNUSED(flipper_format);
    UNUSED(path);
    return false;
}

bool flipper_format_file_open_existing(FlipperFormat *flipper_format, const char *path) {
    UNUSED(flipper_format);
    UNUSED(path);
    return false;
}

bool flipper_format_file_close(FlipperFormat *flipper_format) {
    UNUSED(flipper_format);
    return true;
}

bool flipper_format_write_header_cstr(FlipperFormat *flipper_format, const char *type,
                                      uint32_t version) {
    UNUSED(flipper_format);
    UNUSED(type);
    UNUSED(version);
    return false;
}

bool flipper_format_write_uint32(FlipperFormat *flipper_format, const char *key,
                                 const uint32_t *value, size_t count) {
    UNUSED(flipper_format);
    UNUSED(key);
    UNUSED(value);
    UNUSED(count);
    return false;
}

bool flipper_format_write_hex(FlipperFormat *flipper_format, const char *key, const uint8_t *value,
                              size_t size) {
    UNUSED(flipper_format);
    UNUSED(key);
    UNUSED(value);
    UNUSED(size);
    return false;
}

bool flipper_format_read_header(FlipperFormat *flipper_format, FuriString *type,
                                uint32_t *version) {
    UNUSED(flipper_format);
    UNUSED(type);
    UNUSED(version);
    return false;
}

bool flipper_format_read_uint32(FlipperFormat *flipper_format, const char *key, uint32_t *value,
                                size_t count) {
    UNUSED(flipper_format);
    UNUSED(key);
    UNUSED(value);
    UNUSED(count);
    return false;
}

bool flipper_format_read_hex(FlipperFormat *flipper_format, const char *key, uint8_t *value,
                             size_t size) {
    UNUSED(flipper_format);
    UNUSED(key);
    UNUSED(value);
    UNUSED(size);
    return false;
}

FuriString *furi_string_alloc(void) {
    static FuriString string;

    memset(&string, 0, sizeof(string));
    return &string;
}

void furi_string_free(FuriString *string) {
    UNUSED(string);
}

const char *furi_string_get_cstr(const FuriString *string) {
    return string ? string->value : "";
}

const FuriHalUsbInterface usb_hid_u2f = {0};

size_t furi_hal_hid_u2f_get_request(uint8_t *packet) {
    size_t packet_len = 0;

    if (g_hid_request_index >= g_hid_request_count) {
        return 0;
    }

    packet_len = g_hid_request_packet_lens[g_hid_request_index];
    memcpy(packet, g_hid_request_packets[g_hid_request_index], packet_len);
    g_hid_request_index++;
    return packet_len;
}

void furi_hal_hid_u2f_send_response(const uint8_t *packet, size_t packet_len) {
    expect(packet_len <= sizeof(g_last_hid_response), "response frame should fit native capture");
    memcpy(g_last_hid_response, packet, packet_len);
    g_last_hid_response_len = packet_len;
    g_hid_response_count++;
}

void furi_hal_hid_u2f_set_callback(HidU2fCallback callback, void *context) {
    UNUSED(callback);
    UNUSED(context);
}

bool furi_hal_hid_u2f_is_connected(void) {
    return g_hid_connected;
}

FuriHalUsbInterface *furi_hal_usb_get_config(void) {
    return &g_previous_usb_config;
}

bool furi_hal_usb_set_config(const FuriHalUsbInterface *interface, void *context) {
    UNUSED(context);
    g_usb_set_config_count++;
    g_last_usb_set_config = interface;
    return g_usb_set_config_result;
}

void zerofido_ui_dispatch_custom_event(ZerofidoApp *app, uint32_t event) {
    UNUSED(app);
    UNUSED(event);
}

void zerofido_ui_set_status(ZerofidoApp *app, const char *status) {
    UNUSED(app);
    if (status) {
        snprintf(g_last_status_text, sizeof(g_last_status_text), "%s", status);
    }
}

bool zerofido_ui_cancel_pending_interaction(ZerofidoApp *app) {
    UNUSED(app);
    g_cancel_pending_interaction_count++;
    return g_cancel_pending_interaction_result;
}

bool zerofido_ui_cancel_pending_interaction_locked(ZerofidoApp *app) {
    return zerofido_ui_cancel_pending_interaction(app);
}

void zerofido_ui_set_status_locked(ZerofidoApp *app, const char *status) {
    zerofido_ui_set_status(app, status);
}

void zerofido_ui_refresh_status(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_ui_refresh_status_line(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_ui_refresh_credentials_status(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_ui_set_transport_connected(ZerofidoApp *app, bool connected) {
    UNUSED(app);
    g_transport_connected_set_count++;
    if (connected) {
        g_transport_connected_true_count++;
    }
    g_last_transport_connected = connected;
}

void zerofido_notify_reset(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_notify_error(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_notify_success(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_notify_prompt(ZerofidoApp *app) {
    UNUSED(app);
    g_notify_prompt_count++;
}

void zerofido_notify_wink(ZerofidoApp *app) {
    UNUSED(app);
}

bool zerofido_ui_request_approval(ZerofidoApp *app, ZfUiProtocol protocol, const char *operation,
                                  const char *rp_id, const char *user_text, uint32_t cid,
                                  bool *approved) {
    UNUSED(protocol);
    UNUSED(operation);
    UNUSED(user_text);
    UNUSED(cid);
    if (g_auto_accept_requests || test_transport_auto_accept_enabled(app)) {
        if (approved) {
            *approved = true;
        }
        return true;
    }
    g_approval_request_count++;
    if (rp_id) {
        strncpy(g_last_approval_rp_id, rp_id, sizeof(g_last_approval_rp_id) - 1);
        g_last_approval_rp_id[sizeof(g_last_approval_rp_id) - 1] = '\0';
    }
    if (approved) {
        *approved = true;
    }
    return true;
}

const uint8_t *zf_attestation_get_aaguid(void) {
    static const uint8_t aaguid[ZF_AAGUID_LEN] = {
        0xB5, 0x1A, 0x97, 0x6A, 0x0B, 0x02, 0x40, 0xAA,
        0x9D, 0x8A, 0x36, 0xC8, 0xB9, 0x1B, 0xBD, 0x1A,
    };
    return aaguid;
}

void zf_crypto_secure_zero(void *data, size_t size) {
    memset(data, 0, size);
}

void zf_crypto_sha256(const uint8_t *data, size_t size, uint8_t out[32]) {
    if (size > 0U) {
        expect(data != NULL, "sha256 input should be present when size is non-zero");
        expect(g_sha256_trace_len + size <= sizeof(g_sha256_trace),
               "sha256 trace buffer should fit");
        memcpy(&g_sha256_trace[g_sha256_trace_len], data, size);
        g_sha256_trace_len += size;
    }
    memset(out, 0, 32);
}

bool zf_crypto_hmac_sha256_parts_with_scratch(ZfHmacSha256Scratch *scratch, const uint8_t *key,
                                              size_t key_len, const uint8_t *first,
                                              size_t first_size, const uint8_t *second,
                                              size_t second_size, uint8_t out[32]) {
    uint8_t key_block[64] = {0};
    uint8_t inner_hash[32] = {0};
    uint8_t pad[64] = {0};
    mbedtls_sha256_context sha;

    UNUSED(scratch);
    if (!key || !out || (first_size > 0U && !first) || (second_size > 0U && !second)) {
        return false;
    }

    if (key_len > sizeof(key_block)) {
        mbedtls_sha256_init(&sha);
        mbedtls_sha256_starts(&sha, 0);
        mbedtls_sha256_update(&sha, key, key_len);
        mbedtls_sha256_finish(&sha, key_block);
        mbedtls_sha256_free(&sha);
    } else if (key_len > 0U) {
        memcpy(key_block, key, key_len);
    }

    for (size_t i = 0; i < sizeof(pad); ++i) {
        pad[i] = key_block[i] ^ 0x36U;
    }
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, pad, sizeof(pad));
    if (first_size > 0U) {
        mbedtls_sha256_update(&sha, first, first_size);
    }
    if (second_size > 0U) {
        mbedtls_sha256_update(&sha, second, second_size);
    }
    mbedtls_sha256_finish(&sha, inner_hash);
    mbedtls_sha256_free(&sha);

    for (size_t i = 0; i < sizeof(pad); ++i) {
        pad[i] = key_block[i] ^ 0x5CU;
    }
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, pad, sizeof(pad));
    mbedtls_sha256_update(&sha, inner_hash, sizeof(inner_hash));
    mbedtls_sha256_finish(&sha, out);
    mbedtls_sha256_free(&sha);

    return true;
}

bool zf_crypto_hmac_sha256_parts(const uint8_t *key, size_t key_len, const uint8_t *first,
                                 size_t first_size, const uint8_t *second, size_t second_size,
                                 uint8_t out[32]) {
    ZfHmacSha256Scratch scratch;

    return zf_crypto_hmac_sha256_parts_with_scratch(&scratch, key, key_len, first, first_size,
                                                    second, second_size, out);
}

bool zf_crypto_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t size,
                           uint8_t out[32]) {
    return zf_crypto_hmac_sha256_parts(key, key_len, data, size, NULL, 0, out);
}

size_t zerofido_handle_ctap2(ZerofidoApp *app, uint32_t cid, const uint8_t *request,
                             size_t request_len, uint8_t *response, size_t response_capacity) {
    UNUSED(cid);
    if (!request || request_len == 0 || !response || response_capacity < 2) {
        return 0;
    }

    g_ctap2_request_response_overlap = request == response;
    if (request[0] == ZfCtapeCmdGetInfo) {
        response[0] = ZF_CTAP_SUCCESS;
        response[1] = 0xA0;
        return 2;
    }
    if (request[0] == ZfCtapeCmdMakeCredential) {
        g_ctap2_saw_transport_auto_accept = test_transport_auto_accept_enabled(app);
        response[0] = ZF_CTAP_SUCCESS;
        response[1] = 0xA0;
        return 2;
    }
    if (request[0] == ZfCtapeCmdClientPin) {
        g_ctap2_saw_transport_auto_accept = test_transport_auto_accept_enabled(app);
        if (g_ctap2_large_response_len != 0U) {
            const size_t response_len = g_ctap2_large_response_len < response_capacity
                                            ? g_ctap2_large_response_len
                                            : response_capacity;
            for (size_t i = 0U; i < response_len; ++i) {
                response[i] = (uint8_t)(0xA0U + (i & 0x0FU));
            }
            response[0] = ZF_CTAP_SUCCESS;
            response[1] = 0xA1U;
            return response_len;
        }
        response[0] = ZF_CTAP_SUCCESS;
        response[1] = 0xA1;
        return 2;
    }

    return 0;
}

bool u2f_data_check(bool cert_only) {
    UNUSED(cert_only);
    return g_u2f_cert_assets_present;
}

bool u2f_data_cert_check(void) {
    return g_u2f_cert_assets_present && g_u2f_cert_check_result;
}

uint32_t u2f_data_cert_load(uint8_t *cert, size_t capacity) {
    if (capacity > 0) {
        cert[0] = 0;
        return 1;
    }

    return 0;
}

bool u2f_data_cert_key_load(uint8_t *cert_key) {
    if (!g_u2f_cert_assets_present || !g_u2f_cert_key_load_result) {
        memset(cert_key, 0, 32);
        return false;
    }
    memset(cert_key, 0, 32);
    return true;
}

bool u2f_data_cert_key_matches(const uint8_t *cert_key) {
    UNUSED(cert_key);
    return g_u2f_cert_key_matches_result;
}

bool u2f_data_ensure_local_attestation_assets(void) {
    g_u2f_attestation_ensure_call_count++;
    if (!g_u2f_attestation_ensure_result) {
        return false;
    }
    g_u2f_cert_assets_present = true;
    g_u2f_cert_check_result = true;
    g_u2f_cert_key_load_result = true;
    g_u2f_cert_key_matches_result = true;
    return true;
}

bool u2f_data_generate_attestation_assets(void) {
    return u2f_data_ensure_local_attestation_assets();
}

bool u2f_data_key_exists(void) {
    return g_u2f_key_exists_result;
}

bool u2f_data_key_load(uint8_t *device_key) {
    memset(device_key, 0, 32);
    return g_u2f_key_load_result;
}

bool u2f_data_key_generate(uint8_t *device_key) {
    g_u2f_key_generate_count++;
    memset(device_key, 0, 32);
    return true;
}

bool u2f_data_cnt_exists(void) {
    return g_u2f_cnt_exists_result;
}

bool u2f_data_cnt_read(uint32_t *cnt) {
    *cnt = 0;
    return g_u2f_cnt_read_result;
}

bool u2f_data_cnt_write(uint32_t cnt) {
    g_u2f_cnt_write_count++;
    g_u2f_last_written_counter = cnt;
    return true;
}

bool u2f_data_cnt_reserve(uint32_t cnt, uint32_t *reserved_cnt) {
    g_u2f_cnt_reserve_count++;
    g_u2f_last_reserved_counter = cnt + ZF_COUNTER_RESERVATION_WINDOW;
    if (reserved_cnt) {
        *reserved_cnt = g_u2f_last_reserved_counter;
    }
    return true;
}

bool zf_crypto_p256_private_key_valid(const uint8_t private_key[ZF_PRIVATE_KEY_LEN]) {
    return private_key != NULL;
}

bool zf_crypto_p256_public_key_valid(const uint8_t public_x[ZF_PUBLIC_KEY_LEN],
                                     const uint8_t public_y[ZF_PUBLIC_KEY_LEN]) {
    return public_x != NULL && public_y != NULL;
}

bool zf_crypto_compute_public_key_from_private(const uint8_t private_key[ZF_PRIVATE_KEY_LEN],
                                               uint8_t public_x[ZF_PUBLIC_KEY_LEN],
                                               uint8_t public_y[ZF_PUBLIC_KEY_LEN]) {
    UNUSED(private_key);
    if (!public_x || !public_y) {
        return false;
    }
    memset(public_x, 0x11, ZF_PUBLIC_KEY_LEN);
    memset(public_y, 0x22, ZF_PUBLIC_KEY_LEN);
    return true;
}

bool zf_crypto_sign_hash_raw(const uint8_t private_key[ZF_PRIVATE_KEY_LEN], const uint8_t hash[32],
                             uint8_t out[ZF_PUBLIC_KEY_LEN * 2U]) {
    UNUSED(private_key);
    UNUSED(hash);
    if (!out) {
        return false;
    }
    memset(out, 0x01, ZF_PUBLIC_KEY_LEN * 2U);
    return true;
}

bool zf_crypto_sign_hash_with_private_key(const uint8_t private_key[ZF_PRIVATE_KEY_LEN],
                                          const uint8_t hash[32], uint8_t *out, size_t out_capacity,
                                          size_t *out_len) {
    uint8_t raw_signature[ZF_PUBLIC_KEY_LEN * 2U];
    bool ok = false;

    if (!out_len || !zf_crypto_sign_hash_raw(private_key, hash, raw_signature)) {
        goto cleanup;
    }

    *out_len = zf_ecdsa_der_encode_signature(raw_signature, raw_signature + ZF_PUBLIC_KEY_LEN, out,
                                             out_capacity);
    ok = *out_len > 0U;

cleanup:
    zf_crypto_secure_zero(raw_signature, sizeof(raw_signature));
    return ok;
}

void mbedtls_ecp_group_init(mbedtls_ecp_group *grp) {
    UNUSED(grp);
}

void mbedtls_ecp_group_free(mbedtls_ecp_group *grp) {
    UNUSED(grp);
}

int mbedtls_ecp_group_load(mbedtls_ecp_group *grp, int id) {
    UNUSED(grp);
    UNUSED(id);
    return 0;
}

void mbedtls_ecp_point_init(mbedtls_ecp_point *pt) {
    memset(pt, 0, sizeof(*pt));
}

void mbedtls_ecp_point_free(mbedtls_ecp_point *pt) {
    UNUSED(pt);
}

int mbedtls_ecp_mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *r, const mbedtls_mpi *m,
                    const mbedtls_ecp_point *p, int (*f_rng)(void *, unsigned char *, unsigned int),
                    void *p_rng) {
    UNUSED(grp);
    UNUSED(r);
    UNUSED(m);
    UNUSED(p);
    UNUSED(f_rng);
    UNUSED(p_rng);
    return 0;
}

int mbedtls_ecp_check_privkey(const mbedtls_ecp_group *grp, const mbedtls_mpi *d) {
    UNUSED(grp);
    UNUSED(d);
    return 0;
}

int mbedtls_ecp_check_pubkey(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt) {
    UNUSED(grp);
    UNUSED(pt);
    return 0;
}

int mbedtls_ecp_point_write_binary(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt,
                                   int format, size_t *olen, unsigned char *buf, size_t buflen) {
    UNUSED(grp);
    UNUSED(pt);
    UNUSED(format);
    if (buflen > 0) {
        memset(buf, 0, buflen);
        buf[0] = 0x04;
    }
    *olen = buflen;
    return 0;
}

int mbedtls_ecp_gen_keypair(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *q,
                            int (*f_rng)(void *, unsigned char *, unsigned int), void *p_rng) {
    UNUSED(grp);
    UNUSED(d);
    UNUSED(q);
    UNUSED(f_rng);
    UNUSED(p_rng);
    return 0;
}

int mbedtls_mpi_read_binary(mbedtls_mpi *x, const unsigned char *buf, size_t buflen) {
    UNUSED(x);
    UNUSED(buf);
    UNUSED(buflen);
    return 0;
}

int mbedtls_mpi_write_binary(const mbedtls_mpi *x, unsigned char *buf, size_t buflen) {
    UNUSED(x);
    memset(buf, 0, buflen);
    return 0;
}

int mbedtls_mpi_lset(mbedtls_mpi *x, int z) {
    UNUSED(x);
    UNUSED(z);
    return 0;
}

void mbedtls_mpi_init(mbedtls_mpi *x) {
    memset(x, 0, sizeof(*x));
}

void mbedtls_mpi_free(mbedtls_mpi *x) {
    UNUSED(x);
}

int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s, const mbedtls_mpi *d,
                       const unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, unsigned), void *p_rng) {
    UNUSED(grp);
    UNUSED(r);
    UNUSED(s);
    UNUSED(d);
    UNUSED(buf);
    UNUSED(blen);
    UNUSED(f_rng);
    UNUSED(p_rng);
    return 0;
}

int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp, const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *q, const mbedtls_mpi *r, const mbedtls_mpi *s) {
    UNUSED(grp);
    UNUSED(buf);
    UNUSED(blen);
    UNUSED(q);
    UNUSED(r);
    UNUSED(s);
    return 0;
}

void mbedtls_md_init(mbedtls_md_context_t *ctx) {
    UNUSED(ctx);
}

void mbedtls_md_free(mbedtls_md_context_t *ctx) {
    UNUSED(ctx);
}

const mbedtls_md_info_t *mbedtls_md_info_from_type(int md_type) {
    static const mbedtls_md_info_t info = {0};
    UNUSED(md_type);
    return &info;
}

int mbedtls_md_setup(mbedtls_md_context_t *ctx, const mbedtls_md_info_t *md_info, int hmac) {
    UNUSED(ctx);
    UNUSED(md_info);
    UNUSED(hmac);
    return 0;
}

int mbedtls_md_hmac_starts(mbedtls_md_context_t *ctx, const unsigned char *key, size_t keylen) {
    UNUSED(ctx);
    UNUSED(key);
    UNUSED(keylen);
    return 0;
}

int mbedtls_md_hmac_update(mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen) {
    UNUSED(ctx);
    UNUSED(input);
    UNUSED(ilen);
    return 0;
}

int mbedtls_md_hmac_finish(mbedtls_md_context_t *ctx, unsigned char *output) {
    UNUSED(ctx);
    memset(output, 0, 32);
    return 0;
}

void mbedtls_sha256_init(mbedtls_sha256_context *ctx) {
    UNUSED(ctx);
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx) {
    UNUSED(ctx);
}

void mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224) {
    UNUSED(ctx);
    UNUSED(is224);
}

void mbedtls_sha256_update(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen) {
    UNUSED(ctx);
    expect(g_sha256_trace_len + ilen <= sizeof(g_sha256_trace), "sha256 trace buffer should fit");
    memcpy(&g_sha256_trace[g_sha256_trace_len], input, ilen);
    g_sha256_trace_len += ilen;
}

void mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char output[32]) {
    UNUSED(ctx);
    memset(output, 0, 32);
}

#include "../../../src/crypto/ecdsa_der.c"
#include "../../../src/u2f/apdu.c"
#include "../../../src/u2f/response_encode.c"
#include "../../../src/u2f/session.c"

#include "../../../src/transport/adapter.c"
#include "../../../src/zerofido_storage.c"
#include "../../../src/zerofido_runtime_config.c"
#include "../../../src/u2f/adapter.c"
#include "../../../src/transport/dispatch.c"
#include "../../../src/transport/usb_hid_session.c"
#include "../../../src/transport/usb_hid_worker.c"

static bool test_transport_auto_accept_enabled(const ZerofidoApp *app) {
    return app && app->transport_auto_accept_transaction;
}

uint8_t zf_ctap_build_get_info_response(const ZfResolvedCapabilities *capabilities,
                                        bool client_pin_set, uint8_t *out, size_t out_capacity,
                                        size_t *out_len) {
    UNUSED(client_pin_set);
    g_get_info_builder_called = true;
    g_get_info_builder_saw_usb_transport =
        capabilities && capabilities->usb_hid_enabled && capabilities->advertise_usb_transport;
    expect(out != NULL && out_capacity > 0 && out_len != NULL,
           "test GetInfo builder should receive an output buffer");
    out[0] = 0xA0;
    *out_len = 1U;
    return ZF_CTAP_SUCCESS;
}

bool zerofido_pin_is_set(const ZfClientPinState *state) {
    return state && state->pin_set;
}

#include "subsystems/u2f/tests.inc"
#include "subsystems/transport/tests.inc"

int main(void) {
    test_short_u2f_version_request_is_accepted();
    test_header_only_u2f_version_request_is_accepted_for_stock_compatibility();
    test_u2f_version_accepts_exact_response_buffer();
    test_u2f_version_accepts_extended_length_encoding();
    test_u2f_version_extended_length_with_data_returns_wrong_length();
    test_u2f_extended_length_wrap_is_rejected();
    test_u2f_register_allows_nonzero_p1_p2_for_stock_compatibility();
    test_u2f_dont_enforce_authenticate_mode_is_accepted_without_presence();
    test_u2f_enforce_authenticate_rejects_invalid_handle_before_presence();
    test_u2f_invalid_handle_clears_consumed_presence();
    test_u2f_enforce_authenticate_hash_includes_user_presence_flag();
    test_u2f_authenticate_reserves_counter_window();
    test_zf_u2f_adapter_init_allows_missing_attestation_assets();
    test_zf_u2f_adapter_init_creates_missing_device_key_and_counter();
    test_zf_u2f_adapter_init_allows_invalid_attestation_assets();
    test_u2f_adapter_auto_accept_bypasses_approval_prompt();
    test_u2f_adapter_short_register_approval_uses_payload_app_id();
    test_u2f_adapter_invalid_cla_returns_cla_not_supported();
    test_u2f_adapter_invalid_cla_returns_cla_not_supported_without_live_backend();
    test_u2f_adapter_version_returns_u2f_v2_without_live_backend();
    test_u2f_adapter_version_with_data_returns_wrong_length_without_full_copy();
    test_u2f_adapter_version_extended_length_with_data_returns_wrong_length();
    test_transport_reclaims_lru_cid_when_table_is_full();
    test_transport_allocate_cid_reclaims_lru_when_table_is_full();
    test_transport_cancel_marks_processing_request_without_pending_approval();
    test_transport_cancel_from_other_cid_does_not_cancel_pending_approval();
    test_transport_active_other_cid_short_init_returns_busy();
    test_transport_processing_other_cid_short_init_returns_busy();
    test_transport_processing_broadcast_init_recovers_channel();
    test_usb_restore_keeps_previous_config_after_restore_failure();
    test_usb_worker_polls_while_idle_and_assembling();
    test_transport_worker_processes_disconnect_when_coalesced_with_interaction();
    test_wait_for_interaction_processes_disconnect_when_coalesced_with_completion();
    test_wait_for_interaction_sends_immediate_keepalive();
    test_wait_for_interaction_repeats_keepalive_on_timeout();
    test_wait_for_interaction_omits_keepalive_for_u2f_msg();
    test_transport_fragment_expires_on_session_tick();
    test_transport_request_wakeup_processes_one_complete_transaction();
    test_transport_request_without_wakeup_marks_connected_and_processes_packet();
    test_transport_worker_idle_poll_processes_immediate_u2f_invalid_cla();
    test_transport_worker_idle_poll_processes_immediate_u2f_version_data();
    test_transport_request_wakeup_invalid_seq_allows_followup_init();
    test_transport_same_cid_init_like_invalid_seq_allows_followup_init();
    test_transport_out_of_order_continuation_returns_invalid_seq();
    test_transport_large_ping_out_of_order_continuation_returns_invalid_seq();
    test_transport_large_ping_other_cid_out_of_order_continuation_returns_invalid_seq();
    test_transport_large_ping_other_cid_invalid_seq_allows_followup_init();
    test_transport_processing_same_cid_continuation_returns_invalid_seq();
    test_transport_processing_other_cid_continuation_returns_invalid_seq();
    test_transport_lock_zero_returns_success();
    test_transport_lock_blocks_other_cid_until_released();
    test_transport_disconnect_keeps_allocated_cids();
    test_transport_connect_keeps_allocated_cids();
    test_transport_worker_syncs_initial_hal_connection_state();
    test_transport_dispatch_cbor_preserves_response_buffer();
    test_transport_dispatch_u2f_version_with_data_returns_wrong_length();
    test_transport_dispatch_u2f_version_extended_length_with_data_returns_wrong_length();
    test_transport_dispatch_u2f_version_without_live_backend_returns_version();
    puts("native transport/u2f regressions passed");
    return 0;
}
