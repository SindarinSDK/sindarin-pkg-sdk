#define SN_SDK_TEXTFILE_STANDALONE 1
#include "textfile.native.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

static void *credits(void *value)
{
    for (int i = 0; i < 10000; i++) sn_sdk_text_file_release(sn_sdk_text_file_retain(value));
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--nil-open") == 0) {
        sn_text_file_open(NULL);
        return 99;
    }
    char path[] = "sdk-native-resource.txt";
    SnSdkTextFileRecord *file = sn_text_file_open(path);
    assert(file && file->fp && file->is_open == 1 && strcmp(file->path, path) == 0);
    assert(sn_sdk_text_file_storage_size() == sizeof(*file));
    assert(sn_sdk_text_file_field_offset(0) == offsetof(SnSdkTextFileRecord, fp));
    assert(sn_sdk_text_file_field_offset(1) == offsetof(SnSdkTextFileRecord, path));
    assert(sn_sdk_text_file_field_offset(2) == offsetof(SnSdkTextFileRecord, is_open));
    SnAbiValue *owned_path = NULL;
    assert(sn_sdk_text_file_path(file, &owned_path) == SN_ABI_OK);
    SnAbiValue *preserved_path = owned_path;
    assert(sn_sdk_text_file_path(NULL, &owned_path) == SN_ABI_INVALID_ARGUMENT);
    assert(owned_path == preserved_path);
    assert(sn_sdk_text_file_path(file, NULL) == SN_ABI_INVALID_ARGUMENT);
    SnAbiBytes bytes;
    assert(sn_abi_v1_bytes(owned_path, &bytes) == SN_ABI_OK);
    assert(bytes.length == strlen(path) && memcmp(bytes.data, path, bytes.length) == 0);
    SnSdkTextFileRecord *alias = sn_sdk_text_file_retain(file);
    sn_sdk_text_file_release(file);
    pthread_t threads[4];
    for (int i = 0; i < 4; i++) assert(pthread_create(&threads[i], NULL, credits, alias) == 0);
    for (int i = 0; i < 4; i++) assert(pthread_join(threads[i], NULL) == 0);
    sn_text_file_write_line(alias, "alpha");
    sn_text_file_write_line(alias, "beta");
    sn_text_file_rewind(alias);
    SnArray *lines = sn_text_file_read_lines(alias);
    assert(lines && lines->len == 2 && strcmp(((char **)lines->data)[0], "alpha") == 0);
    assert(strcmp(((char **)lines->data)[1], "beta") == 0);
    sn_array_free(lines);
    sn_text_file_dispose(alias);
    assert(sn_sdk_text_file_fp(alias) == NULL && sn_sdk_text_file_is_open(alias) == 0);
    sn_text_file_dispose(alias); /* explicit dispose remains idempotent */
    sn_sdk_text_file_release(alias);
    assert(sn_abi_v1_bytes(owned_path, &bytes) == SN_ABI_OK && bytes.length == strlen(path));
    sn_abi_v1_release(owned_path);
    sn_sdk_text_file_release(NULL);
    remove(path);
    /* Final owner release closes a resource even without an explicit dispose. */
    file = sn_text_file_open(path);
    sn_text_file_write_line(file, "final");
    sn_sdk_text_file_release(file);
    FILE *check = fopen(path, "rb");
    assert(check);
    char content[16] = {0};
    assert(fread(content, 1, sizeof(content), check) == 6 && strcmp(content, "final\n") == 0);
    fclose(check);
    assert(remove(path) == 0);
    sn_text_file_write_all_static(path, "typed\nsecond\nthird");
    SnAbiValue *path_value = NULL, *typed_file = NULL, *typed_line = NULL, *wrong = NULL;
    assert(sn_abi_v1_string_copy(path, &path_value) == SN_ABI_OK);
    assert(sn_sdk_text_file_open_abi(path_value, &typed_file) == SN_ABI_OK);
    sn_abi_v1_release(path_value);
    const char *identity = NULL;
    assert(sn_abi_v1_resource_type(typed_file, &identity) == SN_ABI_OK);
    assert(strcmp(identity, SN_SDK_TEXTFILE_ABI_TYPE) == 0);
    SnAbiValue *typed_alias = sn_abi_v1_retain(typed_file);
    sn_abi_v1_release(typed_file);
    int32_t opened = -1;
    assert(sn_sdk_text_file_is_open_abi(typed_alias, &opened) == SN_ABI_OK && opened == 1);
    assert(sn_sdk_text_file_read_line_abi(typed_alias, &typed_line) == SN_ABI_OK);
    assert(sn_abi_v1_bytes(typed_line, &bytes) == SN_ABI_OK && bytes.length == 5 && memcmp(bytes.data,"typed",5) == 0);
    SnAbiValue *typed_lines = NULL, *owned_line = NULL;
    assert(sn_sdk_text_file_read_lines_abi(typed_alias, &typed_lines) == SN_ABI_OK);
    uint64_t line_count = 0;
    assert(sn_abi_v1_value_array_length(typed_lines, &line_count) == SN_ABI_OK && line_count == 2);
    assert(sn_abi_v1_value_array_get(typed_lines, 0, &owned_line) == SN_ABI_OK);
    sn_abi_v1_release(typed_lines);
    assert(sn_sdk_text_file_path_abi(typed_alias, &owned_path) == SN_ABI_OK);
    assert(sn_abi_v1_resource_new_typed("pkg.Other@1", NULL, NULL, 0, &wrong) == SN_ABI_OK);
    preserved_path = owned_path;
    assert(sn_sdk_text_file_path_abi(wrong, &owned_path) == SN_ABI_WRONG_KIND && owned_path == preserved_path);
    opened = 123;
    assert(sn_sdk_text_file_is_open_abi(wrong, &opened) == SN_ABI_WRONG_KIND && opened == 123);
    assert(sn_sdk_text_file_dispose_abi(typed_alias) == SN_ABI_OK);
    assert(sn_sdk_text_file_is_open_abi(typed_alias, &opened) == SN_ABI_OK && opened == 0);
    assert(sn_sdk_text_file_dispose_abi(typed_alias) == SN_ABI_OK);
    sn_abi_v1_release(typed_alias);
    assert(sn_abi_v1_bytes(owned_path, &bytes) == SN_ABI_OK && bytes.length == strlen(path));
    assert(sn_abi_v1_bytes(owned_line, &bytes) == SN_ABI_OK && bytes.length == 6 && memcmp(bytes.data,"second",6) == 0);
    sn_abi_v1_release(owned_line);
    sn_abi_v1_release(owned_path); sn_abi_v1_release(typed_line); sn_abi_v1_release(wrong);
    assert(remove(path) == 0);
    puts("SDK native TextFile: pass");
    return 0;
}
