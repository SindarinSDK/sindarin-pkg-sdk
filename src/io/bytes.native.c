#include "sn_array.h"
#include "bytes.native.h"
#include "bytes.sn.c"

SnArray *sn_sdk_bytes_from_hex(char *text) { return sn_bytes_from_hex(text); }
SnArray *sn_sdk_bytes_from_base64(char *text) { return sn_bytes_from_base64(text); }
