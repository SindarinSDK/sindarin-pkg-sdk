/* Independent SDK native module; all file operations use the canonical SDK C
 * implementation. Existing Sindarin callers still include textfile.sn.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define SN_SDK_TEXTFILE_STANDALONE 1
#include "sn_minimal.h"
#include "textfile.sn.c"

SnSdkTextFileRecord *sn_sdk_text_file_retain(SnSdkTextFileRecord *file)
{
    if (file) __atomic_fetch_add(&file->__rc__, 1, __ATOMIC_RELAXED);
    return file;
}

void sn_sdk_text_file_release(SnSdkTextFileRecord *file)
{
    if (!file || __atomic_sub_fetch(&file->__rc__, 1, __ATOMIC_ACQ_REL) != 0) return;
    sn_text_file_dispose(file);
    free(file->path);
    free(file);
}

SnAbiStatus sn_sdk_text_file_path(SnSdkTextFileRecord *file, SnAbiValue **out)
{
    if (!file || !out) return SN_ABI_INVALID_ARGUMENT;
    char *path = sn_text_file_get_path(file);
    SnAbiStatus result = sn_abi_v1_string_copy(path, out);
    free(path);
    return result;
}

void *sn_sdk_text_file_fp(SnSdkTextFileRecord *file) { return file ? file->fp : NULL; }
int32_t sn_sdk_text_file_is_open(SnSdkTextFileRecord *file) { return file ? file->is_open : 0; }
uint64_t sn_sdk_text_file_storage_size(void) { return sizeof(SnSdkTextFileRecord); }
uint64_t sn_sdk_text_file_field_offset(uint32_t field)
{
    switch (field) {
        case 0: return offsetof(SnSdkTextFileRecord, fp);
        case 1: return offsetof(SnSdkTextFileRecord, path);
        case 2: return offsetof(SnSdkTextFileRecord, is_open);
        default: return UINT64_MAX;
    }
}

static void sn_sdk_text_file_abi_destroy(void *record, uintptr_t context)
{
    (void)context;
    sn_sdk_text_file_release(record);
}

static SnAbiStatus sn_sdk_text_file_abi_record(const SnAbiValue *value, SnSdkTextFileRecord **out)
{
    void *record = NULL;
    SnAbiStatus status = sn_abi_v1_resource_data_typed(value, SN_SDK_TEXTFILE_ABI_TYPE, &record);
    if (status) return status;
    if (!record) return SN_ABI_INVALID_ARGUMENT;
    *out = record;
    return SN_ABI_OK;
}

SnAbiStatus sn_sdk_text_file_open_abi(const SnAbiValue *path, SnAbiValue **out)
{
    if (!out) return SN_ABI_INVALID_ARGUMENT;
    SnAbiBytes bytes;
    SnAbiStatus status = sn_abi_v1_string_bytes(path, &bytes);
    if (status) return status;
    /* Canonical open retains its existing nil-path/error behaviour. */
    SnSdkTextFileRecord *record = sn_text_file_open((char *)bytes.data);
    status = sn_abi_v1_resource_new_typed(SN_SDK_TEXTFILE_ABI_TYPE, record,
                                         sn_sdk_text_file_abi_destroy, 0, out);
    if (status) sn_sdk_text_file_release(record);
    return status;
}

SnAbiStatus sn_sdk_text_file_path_abi(const SnAbiValue *file, SnAbiValue **out)
{
    if (!out) return SN_ABI_INVALID_ARGUMENT;
    SnSdkTextFileRecord *record;
    SnAbiStatus status = sn_sdk_text_file_abi_record(file, &record);
    return status ? status : sn_sdk_text_file_path(record, out);
}

SnAbiStatus sn_sdk_text_file_read_line_abi(const SnAbiValue *file, SnAbiValue **out)
{
    if (!out) return SN_ABI_INVALID_ARGUMENT;
    SnSdkTextFileRecord *record;
    SnAbiStatus status = sn_sdk_text_file_abi_record(file, &record);
    if (status) return status;
    char *line = sn_text_file_read_line(record);
    status = sn_abi_v1_string_copy(line, out);
    free(line);
    return status;
}

SnAbiStatus sn_sdk_text_file_dispose_abi(const SnAbiValue *file)
{
    SnSdkTextFileRecord *record;
    SnAbiStatus status = sn_sdk_text_file_abi_record(file, &record);
    if (!status) sn_text_file_dispose(record);
    return status;
}

SnAbiStatus sn_sdk_text_file_is_open_abi(const SnAbiValue *file, int32_t *out)
{
    if (!out) return SN_ABI_INVALID_ARGUMENT;
    SnSdkTextFileRecord *record;
    SnAbiStatus status = sn_sdk_text_file_abi_record(file, &record);
    if (!status) *out = sn_sdk_text_file_is_open(record);
    return status;
}
