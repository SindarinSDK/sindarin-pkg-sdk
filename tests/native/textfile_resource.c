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
    puts("SDK native TextFile: pass");
    return 0;
}
