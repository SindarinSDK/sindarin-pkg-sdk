/* Package-owned allocations share the original TLS implementation and retain
 * the public record layout. Private allocation prefixes distinguish actual
 * factory resources from zero/default records without a global registry. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "sn_minimal.h"
#include "tls.native.h"

typedef struct {
    bool factory_owned;
    SnSdkTlsStreamRecord record;
} TlsStreamAllocation;
typedef struct {
    bool factory_owned;
    SnSdkTlsListenerRecord record;
} TlsListenerAllocation;

static TlsStreamAllocation *stream_allocation(SnSdkTlsStreamRecord *record)
{
    return (TlsStreamAllocation *)((unsigned char *)record - offsetof(TlsStreamAllocation, record));
}
static TlsListenerAllocation *listener_allocation(SnSdkTlsListenerRecord *record)
{
    return (TlsListenerAllocation *)((unsigned char *)record - offsetof(TlsListenerAllocation, record));
}
static void sn_sdk_tls_stream_mark_owned(SnSdkTlsStreamRecord *stream)
{
    stream_allocation(stream)->factory_owned = true;
}
static void sn_sdk_tls_listener_mark_owned(SnSdkTlsListenerRecord *listener)
{
    listener_allocation(listener)->factory_owned = true;
}

#define SN_SDK_TLS_STANDALONE 1
#include "tls.sn.c"

SnSdkTlsStreamRecord *sn_sdk_tls_stream_create(void)
{
    TlsStreamAllocation *allocation = calloc(1, sizeof(*allocation));
    if (!allocation) abort();
    allocation->record.__rc__ = 1;
    return &allocation->record;
}
SnSdkTlsStreamRecord *sn_sdk_tls_stream_retain(SnSdkTlsStreamRecord *stream)
{
    if (stream) __atomic_fetch_add(&stream->__rc__, 1, __ATOMIC_RELAXED);
    return stream;
}
int sn_sdk_tls_stream_refs(SnSdkTlsStreamRecord *stream)
{
    return stream ? __atomic_load_n(&stream->__rc__, __ATOMIC_RELAXED) : 0;
}
void sn_sdk_tls_stream_release(SnSdkTlsStreamRecord *stream)
{
    if (!stream || __atomic_sub_fetch(&stream->__rc__, 1, __ATOMIC_ACQ_REL) != 0) return;
    TlsStreamAllocation *allocation = stream_allocation(stream);
    if (allocation->factory_owned) sn_tls_stream_dispose(stream);
    free(stream->remote_addr);
    free(allocation);
}
SnSdkTlsListenerRecord *sn_sdk_tls_listener_create(void)
{
    TlsListenerAllocation *allocation = calloc(1, sizeof(*allocation));
    if (!allocation) abort();
    allocation->record.__rc__ = 1;
    return &allocation->record;
}
SnSdkTlsListenerRecord *sn_sdk_tls_listener_retain(SnSdkTlsListenerRecord *listener)
{
    if (listener) __atomic_fetch_add(&listener->__rc__, 1, __ATOMIC_RELAXED);
    return listener;
}
int sn_sdk_tls_listener_refs(SnSdkTlsListenerRecord *listener)
{
    return listener ? __atomic_load_n(&listener->__rc__, __ATOMIC_RELAXED) : 0;
}
void sn_sdk_tls_listener_release(SnSdkTlsListenerRecord *listener)
{
    if (!listener || __atomic_sub_fetch(&listener->__rc__, 1, __ATOMIC_ACQ_REL) != 0) return;
    TlsListenerAllocation *allocation = listener_allocation(listener);
    if (allocation->factory_owned) sn_tls_listener_dispose(listener);
    free(allocation);
}
uint64_t sn_sdk_tls_stream_storage_size(void) { return sizeof(SnSdkTlsStreamRecord); }
uint64_t sn_sdk_tls_listener_storage_size(void) { return sizeof(SnSdkTlsListenerRecord); }
uint64_t sn_sdk_tls_stream_field_offset(uint32_t field)
{
    return field == 0 ? offsetof(SnSdkTlsStreamRecord, socket_fd)
         : field == 1 ? offsetof(SnSdkTlsStreamRecord, ssl_ptr)
         : field == 2 ? offsetof(SnSdkTlsStreamRecord, remote_addr) : UINT64_MAX;
}
uint64_t sn_sdk_tls_listener_field_offset(uint32_t field)
{
    return field == 0 ? offsetof(SnSdkTlsListenerRecord, socket_fd)
         : field == 1 ? offsetof(SnSdkTlsListenerRecord, bound_port) : UINT64_MAX;
}
