#ifndef SN_SDK_TEXTFILE_NATIVE_H
#define SN_SDK_TEXTFILE_NATIVE_H

#include <stdint.h>
#include <stddef.h>

/* Package-owned storage matches the existing generated C TextFile record.
 * The reference-count prefix is internal; all existing native fields remain. */
typedef struct {
    int __rc__;
    void *fp;
    char *path;
    int32_t is_open;
} SnSdkTextFileRecord;

#ifdef SN_SDK_TEXTFILE_STANDALONE
#include "sn_array.h"
#include "sn_abi.h"
#ifdef __cplusplus
extern "C" {
#endif
SnSdkTextFileRecord *sn_text_file_open(char *path);
long long sn_text_file_exists(char *path);
char *sn_text_file_read_all_static(char *path);
void sn_text_file_write_all_static(char *path, char *content);
void sn_text_file_delete(char *path);
void sn_text_file_copy(char *src, char *dst);
void sn_text_file_move(char *src, char *dst);
long long sn_text_file_read_char(SnSdkTextFileRecord *file);
char *sn_text_file_read_line(SnSdkTextFileRecord *file);
char *sn_text_file_read_remaining(SnSdkTextFileRecord *file);
SnArray *sn_text_file_read_lines(SnSdkTextFileRecord *file);
char *sn_text_file_read_word(SnSdkTextFileRecord *file);
void sn_text_file_write_char(SnSdkTextFileRecord *file, long long ch);
void sn_text_file_write(SnSdkTextFileRecord *file, char *text);
void sn_text_file_write_line(SnSdkTextFileRecord *file, char *text);
void sn_text_file_print(SnSdkTextFileRecord *file, char *text);
void sn_text_file_println(SnSdkTextFileRecord *file, char *text);
bool sn_text_file_is_eof(SnSdkTextFileRecord *file);
bool sn_text_file_has_chars(SnSdkTextFileRecord *file);
bool sn_text_file_has_words(SnSdkTextFileRecord *file);
bool sn_text_file_has_lines(SnSdkTextFileRecord *file);
long long sn_text_file_position(SnSdkTextFileRecord *file);
void sn_text_file_seek(SnSdkTextFileRecord *file, long long pos);
void sn_text_file_rewind(SnSdkTextFileRecord *file);
void sn_text_file_flush(SnSdkTextFileRecord *file);
void sn_text_file_dispose(SnSdkTextFileRecord *file);
char *sn_text_file_get_path(SnSdkTextFileRecord *file);
char *sn_text_file_get_name(SnSdkTextFileRecord *file);
long long sn_text_file_get_size(SnSdkTextFileRecord *file);

/* Independent artifact lifecycle. Retaining preserves identity; final release
 * closes the resource and releases its C-owned fields and storage once. */
SnSdkTextFileRecord *sn_sdk_text_file_retain(SnSdkTextFileRecord *file);
void sn_sdk_text_file_release(SnSdkTextFileRecord *file);
/* Owned shared-runtime string; outputs remain unchanged on invalid arguments. */
SnAbiStatus sn_sdk_text_file_path(SnSdkTextFileRecord *file, SnAbiValue **out);
/* Public field accessors used by foreign bindings without reinterpreting layouts. */
void *sn_sdk_text_file_fp(SnSdkTextFileRecord *file);
int32_t sn_sdk_text_file_is_open(SnSdkTextFileRecord *file);
uint64_t sn_sdk_text_file_storage_size(void);
uint64_t sn_sdk_text_file_field_offset(uint32_t field);
#ifdef __cplusplus
}
#endif
#endif
#endif
