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
