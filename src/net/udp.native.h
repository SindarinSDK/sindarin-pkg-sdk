#ifndef SN_SDK_UDP_NATIVE_H
#define SN_SDK_UDP_NATIVE_H

#include "sn_array.h"
#include <stddef.h>
#include <stdint.h>

/* Package-owned records preserve the existing native field layouts. */
typedef struct {
    int __rc__;
    long long socket_fd;
    long long bound_port;
} SnSdkUdpSocketRecord;

typedef struct {
    int __rc__;
    SnArray *data;
    char *sender;
} SnSdkUdpReceiveResultRecord;

#ifdef __cplusplus
extern "C" {
#endif
SnSdkUdpSocketRecord *sn_sdk_udp_socket_create(void);
SnSdkUdpSocketRecord *sn_sdk_udp_socket_retain(SnSdkUdpSocketRecord *socket);
void sn_sdk_udp_socket_release(SnSdkUdpSocketRecord *socket);
int sn_sdk_udp_socket_refs(SnSdkUdpSocketRecord *socket);
SnSdkUdpReceiveResultRecord *sn_sdk_udp_result_create(void);
SnSdkUdpReceiveResultRecord *sn_sdk_udp_result_retain(SnSdkUdpReceiveResultRecord *result);
void sn_sdk_udp_result_release(SnSdkUdpReceiveResultRecord *result);
int sn_sdk_udp_result_refs(SnSdkUdpReceiveResultRecord *result);

SnSdkUdpSocketRecord *sn_udp_socket_bind(char *address);
long long sn_udp_socket_send_to(SnSdkUdpSocketRecord *socket, SnArray *data, char *address);
SnSdkUdpReceiveResultRecord *sn_udp_socket_receive_from(SnSdkUdpSocketRecord *socket, long long maximum);
long long sn_udp_socket_get_port(SnSdkUdpSocketRecord *socket);
void sn_udp_socket_dispose(SnSdkUdpSocketRecord *socket);
/* Getter results are owned copies, independent of the result record. Release
 * returned arrays with sn_array_free and returned strings with C free. */
SnArray *sn_udp_result_get_data(SnSdkUdpReceiveResultRecord *result);
char *sn_udp_result_get_sender(SnSdkUdpReceiveResultRecord *result);

uint64_t sn_sdk_udp_socket_storage_size(void);
uint64_t sn_sdk_udp_result_storage_size(void);
uint64_t sn_sdk_udp_socket_field_offset(uint32_t field);
uint64_t sn_sdk_udp_result_field_offset(uint32_t field);
#ifdef __cplusplus
}
#endif
#endif
