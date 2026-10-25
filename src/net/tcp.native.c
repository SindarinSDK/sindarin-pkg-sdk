/* Package-owned allocations share the original TCP implementation and retain
 * the public record layout. Private allocation prefixes distinguish actual
 * factory resources from zero/default records without a global registry. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "sn_minimal.h"
#include "tcp.native.h"

typedef struct {
    bool factory_owned;
    SnSdkTcpStreamRecord record;
} TcpStreamAllocation;
typedef struct {
    bool factory_owned;
    SnSdkTcpListenerRecord record;
} TcpListenerAllocation;

static TcpStreamAllocation *stream_allocation(SnSdkTcpStreamRecord *record)
{
    return (TcpStreamAllocation *)((unsigned char *)record - offsetof(TcpStreamAllocation, record));
}
static TcpListenerAllocation *listener_allocation(SnSdkTcpListenerRecord *record)
{
    return (TcpListenerAllocation *)((unsigned char *)record - offsetof(TcpListenerAllocation, record));
}
static void sn_sdk_tcp_stream_mark_owned(SnSdkTcpStreamRecord *stream)
{
    stream_allocation(stream)->factory_owned = true;
}
static void sn_sdk_tcp_listener_mark_owned(SnSdkTcpListenerRecord *listener)
{
    listener_allocation(listener)->factory_owned = true;
}

#define SN_SDK_TCP_STANDALONE 1
#include "tcp.sn.c"

SnSdkTcpStreamRecord *sn_sdk_tcp_stream_create(void)
{
    TcpStreamAllocation *allocation = calloc(1, sizeof(*allocation));
    if (!allocation) abort();
    allocation->record.__rc__ = 1;
    return &allocation->record;
}
SnSdkTcpStreamRecord *sn_sdk_tcp_stream_retain(SnSdkTcpStreamRecord *stream)
{
    if (stream) __atomic_fetch_add(&stream->__rc__, 1, __ATOMIC_RELAXED);
    return stream;
}
int sn_sdk_tcp_stream_refs(SnSdkTcpStreamRecord *stream)
{
    return stream ? __atomic_load_n(&stream->__rc__, __ATOMIC_RELAXED) : 0;
}
void sn_sdk_tcp_stream_release(SnSdkTcpStreamRecord *stream)
{
    if (!stream || __atomic_sub_fetch(&stream->__rc__, 1, __ATOMIC_ACQ_REL) != 0) return;
    TcpStreamAllocation *allocation = stream_allocation(stream);
    if (allocation->factory_owned) sn_tcp_stream_dispose(stream);
    free(allocation);
}
SnSdkTcpListenerRecord *sn_sdk_tcp_listener_create(void)
{
    TcpListenerAllocation *allocation = calloc(1, sizeof(*allocation));
    if (!allocation) abort();
    allocation->record.__rc__ = 1;
    return &allocation->record;
}
SnSdkTcpListenerRecord *sn_sdk_tcp_listener_retain(SnSdkTcpListenerRecord *listener)
{
    if (listener) __atomic_fetch_add(&listener->__rc__, 1, __ATOMIC_RELAXED);
    return listener;
}
int sn_sdk_tcp_listener_refs(SnSdkTcpListenerRecord *listener)
{
    return listener ? __atomic_load_n(&listener->__rc__, __ATOMIC_RELAXED) : 0;
}
void sn_sdk_tcp_listener_release(SnSdkTcpListenerRecord *listener)
{
    if (!listener || __atomic_sub_fetch(&listener->__rc__, 1, __ATOMIC_ACQ_REL) != 0) return;
    TcpListenerAllocation *allocation = listener_allocation(listener);
    if (allocation->factory_owned) sn_tcp_listener_dispose(listener);
    free(allocation);
}
uint64_t sn_sdk_tcp_stream_storage_size(void) { return sizeof(SnSdkTcpStreamRecord); }
uint64_t sn_sdk_tcp_listener_storage_size(void) { return sizeof(SnSdkTcpListenerRecord); }
uint64_t sn_sdk_tcp_stream_field_offset(uint32_t field)
{
    return field == 0 ? offsetof(SnSdkTcpStreamRecord, socket_fd)
         : field == 1 ? offsetof(SnSdkTcpStreamRecord, remote_addr)
         : field == 2 ? offsetof(SnSdkTcpStreamRecord, internal) : UINT64_MAX;
}
uint64_t sn_sdk_tcp_listener_field_offset(uint32_t field)
{
    return field == 0 ? offsetof(SnSdkTcpListenerRecord, socket_fd)
         : field == 1 ? offsetof(SnSdkTcpListenerRecord, bound_port) : UINT64_MAX;
}
