/* The original UDP operations remain the single C implementation. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define SN_SDK_UDP_STANDALONE 1
#include "sn_minimal.h"
#include "udp.sn.c"

SnSdkUdpSocketRecord *sn_sdk_udp_socket_create(void)
{
    SnSdkUdpSocketRecord *socket = calloc(1, sizeof(*socket));
    if (!socket) abort();
    socket->__rc__ = 1;
    return socket;
}

int sn_sdk_udp_socket_refs(SnSdkUdpSocketRecord *socket)
{
    return socket ? __atomic_load_n(&socket->__rc__, __ATOMIC_RELAXED) : 0;
}

SnSdkUdpSocketRecord *sn_sdk_udp_socket_retain(SnSdkUdpSocketRecord *socket)
{
    if (socket) __atomic_fetch_add(&socket->__rc__, 1, __ATOMIC_RELAXED);
    return socket;
}

void sn_sdk_udp_socket_release(SnSdkUdpSocketRecord *socket)
{
    if (!socket || __atomic_sub_fetch(&socket->__rc__, 1, __ATOMIC_ACQ_REL) != 0) return;
    /* A public default record has zero fields and no registered descriptor.
     * Its default fd must not close stdin. Factory-created sockets own the
     * registered descriptor; explicit dispose removes that registration. */
    if (udp_get_internal(socket)) sn_udp_socket_dispose(socket);
    free(socket);
}

SnSdkUdpReceiveResultRecord *sn_sdk_udp_result_create(void)
{
    SnSdkUdpReceiveResultRecord *result = calloc(1, sizeof(*result));
    if (!result) abort();
    result->__rc__ = 1;
    return result;
}

int sn_sdk_udp_result_refs(SnSdkUdpReceiveResultRecord *result)
{
    return result ? __atomic_load_n(&result->__rc__, __ATOMIC_RELAXED) : 0;
}

SnSdkUdpReceiveResultRecord *sn_sdk_udp_result_retain(SnSdkUdpReceiveResultRecord *result)
{
    if (result) __atomic_fetch_add(&result->__rc__, 1, __ATOMIC_RELAXED);
    return result;
}

void sn_sdk_udp_result_release(SnSdkUdpReceiveResultRecord *result)
{
    if (!result || __atomic_sub_fetch(&result->__rc__, 1, __ATOMIC_ACQ_REL) != 0) return;
    sn_cleanup_array(&result->data);
    free(result->sender);
    free(result);
}

uint64_t sn_sdk_udp_socket_storage_size(void) { return sizeof(SnSdkUdpSocketRecord); }
uint64_t sn_sdk_udp_result_storage_size(void) { return sizeof(SnSdkUdpReceiveResultRecord); }
uint64_t sn_sdk_udp_socket_field_offset(uint32_t field)
{
    return field == 0 ? offsetof(SnSdkUdpSocketRecord, socket_fd)
         : field == 1 ? offsetof(SnSdkUdpSocketRecord, bound_port) : UINT64_MAX;
}
uint64_t sn_sdk_udp_result_field_offset(uint32_t field)
{
    return field == 0 ? offsetof(SnSdkUdpReceiveResultRecord, data)
         : field == 1 ? offsetof(SnSdkUdpReceiveResultRecord, sender) : UINT64_MAX;
}
