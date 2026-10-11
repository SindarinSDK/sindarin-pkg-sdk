#ifndef SN_SDK_BYTES_NATIVE_H
#define SN_SDK_BYTES_NATIVE_H

#ifdef __cplusplus
struct SnArray;
typedef struct SnArray SnSdkByteArray;
extern "C" {
#else
/* Earlier supported C runtimes used an anonymous SnArray typedef. Retain
 * source compatibility while exposing an opaque, named type to C++ clients. */
#include "sn_array.h"
typedef SnArray SnSdkByteArray;
#endif
/* Owned canonical C arrays; inputs are borrowed C strings. The decoder logic
 * remains in bytes.sn.c, shared with existing application compilation. */
SnSdkByteArray *sn_bytes_from_hex(char *text);
SnSdkByteArray *sn_bytes_from_base64(char *text);
/* Separate adapter backing names keep the original SDK symbols available to
 * the independently compiled, unchanged Sindarin facade. */
SnSdkByteArray *sn_sdk_bytes_from_hex(char *text);
SnSdkByteArray *sn_sdk_bytes_from_base64(char *text);
#ifdef __cplusplus
}
#endif
#endif
