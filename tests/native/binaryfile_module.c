#include <assert.h>
#include <stdlib.h>
#include <string.h>
#define SN_SDK_BINARYFILE_STANDALONE 1
#include "binaryfile.native.h"

static void check_bytes(SnArray *array, const unsigned char *wanted, size_t length)
{
    assert(array && array->elem_size == 1 && array->elem_tag == SN_TAG_BYTE);
    assert(array->len == (long long)length);
    assert(!length || !memcmp(array->data, wanted, length));
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        assert(!strcmp(argv[1], "nil-path"));
        sn_binary_file_open(NULL);
        return 99;
    }
    const unsigned char wanted[] = {0, 128, 255, 42};
    SnArray *data = sn_array_new(1, 4);
    data->elem_tag = SN_TAG_BYTE;
    for (size_t i = 0; i < sizeof(wanted); i++) sn_array_push(data, &wanted[i]);
    sn_sdk_binary_file_write_all_static("binary.dat", data);
    SnSdkBinaryFileRecord *file = sn_sdk_binary_file_open("binary.dat");
    SnSdkBinaryFileRecord *alias = sn_sdk_binary_file_retain(file);
    assert(file == alias && sn_sdk_binary_file_refs(alias) == 2);
    assert(file->fp && file->is_open && !strcmp(file->path, "binary.dat"));
    sn_sdk_binary_file_release(file);
    assert(sn_sdk_binary_file_refs(alias) == 1 && sn_binary_file_get_size(alias) == 4);
    assert(sn_binary_file_has_bytes(alias) && !sn_binary_file_is_eof(alias));
    assert(sn_binary_file_read_byte(alias) == 0);
    SnArray *held = sn_sdk_binary_file_read_bytes(alias, 2);
    check_bytes(held, wanted + 1, 2);
    assert(sn_binary_file_position(alias) == 3);
    SnArray *remaining = sn_sdk_binary_file_read_remaining(alias);
    check_bytes(remaining, wanted + 3, 1);
    assert(sn_binary_file_is_eof(alias) && !sn_binary_file_has_bytes(alias));
    sn_binary_file_rewind(alias);
    void *original_data = data->data;
    memset(data->data, 77, 4);
    assert(sn_binary_file_read_into(alias, data) == 4);
    assert(data->data == original_data);
    check_bytes(data, wanted, 4);
    sn_binary_file_seek(alias, 1);
    sn_binary_file_write_byte(alias, 128);
    sn_binary_file_seek(alias, 0);
    sn_binary_file_write_bytes(alias, data);
    sn_binary_file_flush(alias);
    char *path = sn_sdk_binary_file_get_path(alias);
    char *name = sn_sdk_binary_file_get_name(alias);
    sn_sdk_binary_file_dispose(alias);
    sn_binary_file_dispose(alias);
    assert(!alias->fp && !alias->is_open);
    sn_sdk_binary_file_release(alias);
    check_bytes(held, wanted + 1, 2);
    check_bytes(remaining, wanted + 3, 1);
    assert(!strcmp(path, "binary.dat") && !strcmp(name, "binary.dat"));
    free(path); free(name);
    sn_array_free(held); sn_array_free(remaining);
    sn_sdk_binary_file_copy("binary.dat", "copy.dat");
    sn_sdk_binary_file_move("copy.dat", "moved.dat");
    assert(!sn_sdk_binary_file_exists("copy.dat") && sn_sdk_binary_file_exists("moved.dat"));
    SnArray *copy = sn_sdk_binary_file_read_all_static("moved.dat");
    check_bytes(copy, wanted, 4); sn_array_free(copy);
    sn_sdk_binary_file_delete("moved.dat");
    sn_binary_file_delete("binary.dat");
    sn_binary_file_write_all_static("empty.dat", NULL);
    file = sn_binary_file_open("empty.dat");
    copy = sn_binary_file_read_remaining(file);
    check_bytes(copy, NULL, 0); sn_array_free(copy);
    sn_sdk_binary_file_release(file); /* Final release also closes an open file. */
    sn_binary_file_delete("empty.dat");
    sn_array_free(data);
    file = sn_sdk_binary_file_create();
    assert(file && sn_sdk_binary_file_refs(file) == 1);
    assert(!file->fp && !file->path && !file->is_open);
    sn_sdk_binary_file_release(file);
    sn_sdk_binary_file_release(NULL);
    assert(!sn_sdk_binary_file_retain(NULL) && !sn_sdk_binary_file_refs(NULL));
    puts("SDK native BinaryFile: pass");
    return 0;
}
