#include <assert.h>
#include <string.h>
#include "sn_array.h"
#include "bytes.native.h"

static void check_bytes(SnArray *array, const unsigned char *wanted, size_t length)
{
    assert(array && array->elem_size == 1 && array->elem_tag == SN_TAG_BYTE);
    assert(array->len == (long long)length);
    assert(!length || !memcmp(array->data, wanted, length));
    sn_array_free(array);
}
int main(void)
{
    const unsigned char wanted[] = {0, 128, 255};
    char hex[] = "0080fF";
    SnArray *held = sn_sdk_bytes_from_hex(hex);
    memset(hex, '0', sizeof(hex) - 1);
    check_bytes(held, wanted, sizeof(wanted));
    check_bytes(sn_bytes_from_hex("0080FF"), wanted, sizeof(wanted));
    check_bytes(sn_bytes_from_base64("AID/"), wanted, sizeof(wanted));
    check_bytes(sn_sdk_bytes_from_base64("AID/"), wanted, sizeof(wanted));
    check_bytes(sn_bytes_from_hex(NULL), NULL, 0);
    check_bytes(sn_sdk_bytes_from_hex(""), NULL, 0);
    check_bytes(sn_bytes_from_base64(NULL), NULL, 0);
    check_bytes(sn_sdk_bytes_from_base64(""), NULL, 0);
    puts("SDK native Bytes: pass");
    return 0;
}
