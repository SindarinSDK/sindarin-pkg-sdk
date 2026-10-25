#ifndef SN_SDK_TLS_NATIVE_H
#define SN_SDK_TLS_NATIVE_H

#include "sn_array.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* These public layouts match the unchanged Sindarin native records. */
typedef struct {
    int __rc__;
    long long socket_fd;
    long long ssl_ptr;
    unsigned char *remote_addr;
} SnSdkTlsStreamRecord;

typedef struct {
    int __rc__;
    long long socket_fd;
    long long bound_port;
} SnSdkTlsListenerRecord;

#ifdef __cplusplus
extern "C" {
#endif
SnSdkTlsStreamRecord *sn_sdk_tls_stream_create(void);
SnSdkTlsStreamRecord *sn_sdk_tls_stream_retain(SnSdkTlsStreamRecord *stream);
void sn_sdk_tls_stream_release(SnSdkTlsStreamRecord *stream);
int sn_sdk_tls_stream_refs(SnSdkTlsStreamRecord *stream);
SnSdkTlsListenerRecord *sn_sdk_tls_listener_create(void);
SnSdkTlsListenerRecord *sn_sdk_tls_listener_retain(SnSdkTlsListenerRecord *listener);
void sn_sdk_tls_listener_release(SnSdkTlsListenerRecord *listener);
int sn_sdk_tls_listener_refs(SnSdkTlsListenerRecord *listener);

SnSdkTlsStreamRecord *sn_tls_stream_connect(char *address);
SnArray *sn_tls_stream_read(SnSdkTlsStreamRecord *stream, long long maximum);
SnArray *sn_tls_stream_read_all(SnSdkTlsStreamRecord *stream);
char *sn_tls_stream_read_line(SnSdkTlsStreamRecord *stream);
long long sn_tls_stream_write(SnSdkTlsStreamRecord *stream, SnArray *data);
void sn_tls_stream_write_line(SnSdkTlsStreamRecord *stream, char *text);
char *sn_tls_stream_get_remote_address(SnSdkTlsStreamRecord *stream);
bool sn_tls_stream_is_valid(SnSdkTlsStreamRecord *stream);
void sn_tls_stream_dispose(SnSdkTlsStreamRecord *stream);
SnSdkTlsListenerRecord *sn_tls_listener_bind(char *address, char *certificate_file, char *key_file);
SnSdkTlsStreamRecord *sn_tls_listener_accept(SnSdkTlsListenerRecord *listener);
SnSdkTlsStreamRecord *sn_tls_listener_accept_or_shutdown(SnSdkTlsListenerRecord *listener, long long signal_fd);
long long sn_tls_listener_get_port(SnSdkTlsListenerRecord *listener);
void sn_tls_listener_dispose(SnSdkTlsListenerRecord *listener);

uint64_t sn_sdk_tls_stream_storage_size(void);
uint64_t sn_sdk_tls_listener_storage_size(void);
uint64_t sn_sdk_tls_stream_field_offset(uint32_t field);
uint64_t sn_sdk_tls_listener_field_offset(uint32_t field);
#ifdef __cplusplus
}
#endif
#endif
