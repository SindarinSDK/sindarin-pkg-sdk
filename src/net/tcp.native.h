#ifndef SN_SDK_TCP_NATIVE_H
#define SN_SDK_TCP_NATIVE_H

#include "sn_array.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* These public layouts match the unchanged Sindarin native records. */
typedef struct {
    int __rc__;
    long long socket_fd;
    unsigned char *remote_addr;
    unsigned char *internal;
} SnSdkTcpStreamRecord;

typedef struct {
    int __rc__;
    long long socket_fd;
    long long bound_port;
} SnSdkTcpListenerRecord;

#ifdef __cplusplus
extern "C" {
#endif
SnSdkTcpStreamRecord *sn_sdk_tcp_stream_create(void);
SnSdkTcpStreamRecord *sn_sdk_tcp_stream_retain(SnSdkTcpStreamRecord *stream);
void sn_sdk_tcp_stream_release(SnSdkTcpStreamRecord *stream);
int sn_sdk_tcp_stream_refs(SnSdkTcpStreamRecord *stream);
SnSdkTcpListenerRecord *sn_sdk_tcp_listener_create(void);
SnSdkTcpListenerRecord *sn_sdk_tcp_listener_retain(SnSdkTcpListenerRecord *listener);
void sn_sdk_tcp_listener_release(SnSdkTcpListenerRecord *listener);
int sn_sdk_tcp_listener_refs(SnSdkTcpListenerRecord *listener);

SnSdkTcpStreamRecord *sn_tcp_stream_connect(char *address);
SnArray *sn_tcp_stream_read(SnSdkTcpStreamRecord *stream, long long maximum);
SnArray *sn_tcp_stream_read_all(SnSdkTcpStreamRecord *stream);
char *sn_tcp_stream_read_line(SnSdkTcpStreamRecord *stream);
long long sn_tcp_stream_write(SnSdkTcpStreamRecord *stream, SnArray *data);
void sn_tcp_stream_write_line(SnSdkTcpStreamRecord *stream, char *text);
char *sn_tcp_stream_get_remote_address(SnSdkTcpStreamRecord *stream);
void sn_tcp_stream_set_timeout(SnSdkTcpStreamRecord *stream, long long timeout_ms);
bool sn_tcp_stream_is_valid(SnSdkTcpStreamRecord *stream);
void sn_tcp_stream_dispose(SnSdkTcpStreamRecord *stream);
SnSdkTcpListenerRecord *sn_tcp_listener_bind(char *address);
SnSdkTcpStreamRecord *sn_tcp_listener_accept(SnSdkTcpListenerRecord *listener);
SnSdkTcpStreamRecord *sn_tcp_listener_accept_or_shutdown(SnSdkTcpListenerRecord *listener, long long signal_fd);
long long sn_tcp_listener_get_port(SnSdkTcpListenerRecord *listener);
void sn_tcp_listener_dispose(SnSdkTcpListenerRecord *listener);

uint64_t sn_sdk_tcp_stream_storage_size(void);
uint64_t sn_sdk_tcp_listener_storage_size(void);
uint64_t sn_sdk_tcp_stream_field_offset(uint32_t field);
uint64_t sn_sdk_tcp_listener_field_offset(uint32_t field);
#ifdef __cplusplus
}
#endif
#endif
