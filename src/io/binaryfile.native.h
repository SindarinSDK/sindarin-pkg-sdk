#ifndef SN_SDK_BINARYFILE_NATIVE_H
#define SN_SDK_BINARYFILE_NATIVE_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    int __rc__;
    void *fp;
    char *path;
    int32_t is_open;
} SnSdkBinaryFileRecord;

#ifdef SN_SDK_BINARYFILE_STANDALONE
#include "sn_array.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif
SnSdkBinaryFileRecord *sn_sdk_binary_file_create(void);
SnSdkBinaryFileRecord *sn_sdk_binary_file_retain(SnSdkBinaryFileRecord *file);
void sn_sdk_binary_file_release(SnSdkBinaryFileRecord *file);
int sn_sdk_binary_file_refs(SnSdkBinaryFileRecord *file);

#ifdef SN_SDK_BINARYFILE_STANDALONE
SnSdkBinaryFileRecord *sn_binary_file_open(char *path);
long long sn_binary_file_exists(char *path);
SnArray *sn_binary_file_read_all_static(char *path);
void sn_binary_file_write_all_static(char *path, SnArray *data);
void sn_binary_file_delete(char *path);
void sn_binary_file_copy(char *source, char *destination);
void sn_binary_file_move(char *source, char *destination);
long long sn_binary_file_read_byte(SnSdkBinaryFileRecord *file);
SnArray *sn_binary_file_read_bytes(SnSdkBinaryFileRecord *file, long long count);
SnArray *sn_binary_file_read_remaining(SnSdkBinaryFileRecord *file);
long long sn_binary_file_read_into(SnSdkBinaryFileRecord *file, SnArray *buffer);
void sn_binary_file_write_byte(SnSdkBinaryFileRecord *file, long long byte);
void sn_binary_file_write_bytes(SnSdkBinaryFileRecord *file, SnArray *data);
bool sn_binary_file_is_eof(SnSdkBinaryFileRecord *file);
bool sn_binary_file_has_bytes(SnSdkBinaryFileRecord *file);
long long sn_binary_file_position(SnSdkBinaryFileRecord *file);
void sn_binary_file_seek(SnSdkBinaryFileRecord *file, long long position);
void sn_binary_file_rewind(SnSdkBinaryFileRecord *file);
void sn_binary_file_flush(SnSdkBinaryFileRecord *file);
void sn_binary_file_dispose(SnSdkBinaryFileRecord *file);
char *sn_binary_file_get_path(SnSdkBinaryFileRecord *file);
char *sn_binary_file_get_name(SnSdkBinaryFileRecord *file);
long long sn_binary_file_get_size(SnSdkBinaryFileRecord *file);
#endif
#ifdef __cplusplus
}
#endif
#endif
