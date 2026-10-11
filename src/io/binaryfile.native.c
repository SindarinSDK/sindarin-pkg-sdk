#define SN_SDK_BINARYFILE_STANDALONE 1
#include "sn_minimal.h"
#include "binaryfile.sn.c"

SnSdkBinaryFileRecord *sn_sdk_binary_file_create(void)
{
    SnSdkBinaryFileRecord *file = calloc(1, sizeof(*file));
    if (file) file->__rc__ = 1;
    return file;
}

SnSdkBinaryFileRecord *sn_sdk_binary_file_retain(SnSdkBinaryFileRecord *file)
{
    if (file) __atomic_fetch_add(&file->__rc__, 1, __ATOMIC_RELAXED);
    return file;
}

void sn_sdk_binary_file_release(SnSdkBinaryFileRecord *file)
{
    if (!file || __atomic_sub_fetch(&file->__rc__, 1, __ATOMIC_ACQ_REL) != 0) return;
    sn_binary_file_dispose(file);
    free(file->path);
    free(file);
}

int sn_sdk_binary_file_refs(SnSdkBinaryFileRecord *file)
{
    return file ? __atomic_load_n(&file->__rc__, __ATOMIC_RELAXED) : 0;
}

/* Separate backing names let generated providers namespace their entry points
 * while the unchanged Sindarin facade keeps calling the original C symbols. */
SnSdkBinaryFileRecord *sn_sdk_binary_file_open(char *path) { return sn_binary_file_open(path); }
long long sn_sdk_binary_file_exists(char *path) { return sn_binary_file_exists(path); }
SnArray *sn_sdk_binary_file_read_all_static(char *path) { return sn_binary_file_read_all_static(path); }
void sn_sdk_binary_file_write_all_static(char *path, SnArray *data) { sn_binary_file_write_all_static(path, data); }
void sn_sdk_binary_file_copy(char *source, char *destination) { sn_binary_file_copy(source, destination); }
void sn_sdk_binary_file_move(char *source, char *destination) { sn_binary_file_move(source, destination); }
void sn_sdk_binary_file_delete(char *path) { sn_binary_file_delete(path); }
SnArray *sn_sdk_binary_file_read_bytes(SnSdkBinaryFileRecord *file, long long count) { return sn_binary_file_read_bytes(file, count); }
SnArray *sn_sdk_binary_file_read_remaining(SnSdkBinaryFileRecord *file) { return sn_binary_file_read_remaining(file); }
void sn_sdk_binary_file_dispose(SnSdkBinaryFileRecord *file) { sn_binary_file_dispose(file); }
char *sn_sdk_binary_file_get_path(SnSdkBinaryFileRecord *file) { return sn_binary_file_get_path(file); }
char *sn_sdk_binary_file_get_name(SnSdkBinaryFileRecord *file) { return sn_binary_file_get_name(file); }
