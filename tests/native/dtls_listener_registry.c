#include <assert.h>
#include <stdlib.h>
#include "sn_minimal.h"

/* The public native layout/constructors normally come from the compiler. */
typedef struct { int __rc__; long long socket_fd; unsigned char *ssl_ptr; unsigned char *remote_addr; } __sn__DtlsConnection;
typedef struct { int __rc__; long long socket_fd; long long bound_port; } __sn__DtlsListener;
static __sn__DtlsConnection *__sn__DtlsConnection__new(void) {
    __sn__DtlsConnection *value = calloc(1, sizeof(*value)); assert(value); value->__rc__ = 1; return value;
}
static __sn__DtlsListener *__sn__DtlsListener__new(void) {
    __sn__DtlsListener *value = calloc(1, sizeof(*value)); assert(value); value->__rc__ = 1; return value;
}
#include "../../src/net/dtls.sn.c"

int main(void) {
    for (int i = 0; i < 40; i++) {
        __sn__DtlsListener *listener = sn_dtls_listener_bind(":0", "tests/net/test_dtls_cert.pem", "tests/net/test_dtls_key.pem");
        assert(listener && sn_dtls_listener_get_port(listener) > 0);
        assert(dtls_find_listener_data(listener) != NULL && g_dtls_ld_count == 1);
        sn_dtls_listener_close(listener);
        assert(dtls_find_listener_data(listener) == NULL && g_dtls_ld_count == 0);
        sn_dtls_listener_close(listener);
        free(listener);
    }
    return 0;
}
