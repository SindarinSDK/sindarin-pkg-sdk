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
