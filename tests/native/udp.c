#include "udp.native.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#endif

static void exercise_parallel(void) {
    for (int i=0;i<32;i++) {
        SnSdkUdpSocketRecord *socket=sn_udp_socket_bind(":0");
        assert(sn_udp_socket_get_port(socket)>0);
        SnSdkUdpSocketRecord *alias=sn_sdk_udp_socket_retain(socket);
        assert(alias==socket && sn_sdk_udp_socket_refs(socket)==2);
        sn_sdk_udp_socket_release(socket);
        assert(sn_sdk_udp_socket_refs(alias)==1);
        sn_sdk_udp_socket_release(alias);
    }
}
#ifdef _WIN32
static DWORD WINAPI worker(void *argument) { (void)argument;exercise_parallel();return 0; }
#else
static void *worker(void *argument) { (void)argument;exercise_parallel();return NULL; }
#endif

int main(void) {
    assert(sn_sdk_udp_socket_storage_size()==sizeof(SnSdkUdpSocketRecord));
    assert(sn_sdk_udp_result_storage_size()==sizeof(SnSdkUdpReceiveResultRecord));
    assert(sn_sdk_udp_socket_field_offset(0)==offsetof(SnSdkUdpSocketRecord,socket_fd));
    assert(sn_sdk_udp_socket_field_offset(1)==offsetof(SnSdkUdpSocketRecord,bound_port));
    assert(sn_sdk_udp_result_field_offset(0)==offsetof(SnSdkUdpReceiveResultRecord,data));
    assert(sn_sdk_udp_result_field_offset(1)==offsetof(SnSdkUdpReceiveResultRecord,sender));
    assert(sn_sdk_udp_result_field_offset(2)==UINT64_MAX);
#ifndef _WIN32
    int stdin_before=fcntl(0,F_GETFD);
#endif
    SnSdkUdpSocketRecord *empty=sn_sdk_udp_socket_create();
    assert(empty->socket_fd==0 && empty->bound_port==0 && sn_sdk_udp_socket_refs(empty)==1);
    sn_sdk_udp_socket_release(empty);
#ifndef _WIN32
    assert(fcntl(0,F_GETFD)==stdin_before);
#endif
    SnSdkUdpReceiveResultRecord *nothing=sn_sdk_udp_result_create();
    assert(!nothing->data && !nothing->sender && sn_sdk_udp_result_refs(nothing)==1);
    sn_sdk_udp_result_release(nothing);
    sn_sdk_udp_socket_release(NULL);sn_sdk_udp_result_release(NULL);
    assert(sn_sdk_udp_socket_refs(NULL)==0 && sn_sdk_udp_result_refs(NULL)==0);
    SnArray *absent=sn_udp_result_get_data(NULL);
    char *absent_sender=sn_udp_result_get_sender(NULL);
    assert(absent->len==0 && !strcmp(absent_sender,""));
    sn_cleanup_array(&absent);free(absent_sender);
    SnSdkUdpReceiveResultRecord *empty_receive=sn_udp_socket_receive_from(NULL,0);
    assert(empty_receive->data->len==0 && !strcmp(empty_receive->sender,""));
    sn_sdk_udp_result_release(empty_receive);
    assert(sn_udp_socket_send_to(NULL,NULL,NULL)==0 && sn_udp_socket_get_port(NULL)==0);
    sn_udp_socket_dispose(NULL);

    SnSdkUdpSocketRecord *server=sn_udp_socket_bind(":0"),*client=sn_udp_socket_bind(":0");
    assert(server && client && server!=client);
    long long server_fd=server->socket_fd;
    char address[80];snprintf(address,sizeof(address),"127.0.0.1:%lld",sn_udp_socket_get_port(server));
    unsigned char values[]={0,255,65,128,10};
    SnArray *payload=sn_array_new(1,5);payload->elem_tag=SN_TAG_BYTE;
    for (size_t i=0;i<sizeof(values);i++)sn_array_push(payload,&values[i]);
    assert(sn_udp_socket_send_to(client,payload,address)==5);
    SnSdkUdpReceiveResultRecord *result=sn_udp_socket_receive_from(server,1024);
    assert(result && result->data && result->data->len==5 && result->sender);
    SnSdkUdpReceiveResultRecord *alias=sn_sdk_udp_result_retain(result);
    assert(alias==result && sn_sdk_udp_result_refs(result)==2);
    sn_sdk_udp_result_release(result);
    SnArray *received=sn_udp_result_get_data(alias);char *sender=sn_udp_result_get_sender(alias);
    sn_sdk_udp_result_release(alias);
    assert(received->len==5 && memcmp(received->data,values,5)==0);
    assert(strncmp(sender,"127.0.0.1:",10)==0);
    sn_cleanup_array(&received);sn_cleanup_array(&payload);free(sender);
    sn_udp_socket_dispose(client);sn_udp_socket_dispose(client);sn_sdk_udp_socket_release(client);
    sn_sdk_udp_socket_release(server);
#ifndef _WIN32
    errno=0;assert(fcntl((int)server_fd,F_GETFD)==-1 && errno==EBADF);
#else
    (void)server_fd;
#endif
#ifdef _WIN32
    HANDLE threads[8];
    for (int i=0;i<8;i++){threads[i]=CreateThread(NULL,0,worker,NULL,0,NULL);assert(threads[i]);}
    assert(WaitForMultipleObjects(8,threads,TRUE,INFINITE)==WAIT_OBJECT_0);
    for (int i=0;i<8;i++)CloseHandle(threads[i]);
#else
    pthread_t threads[8];
    for (int i=0;i<8;i++)assert(pthread_create(&threads[i],NULL,worker,NULL)==0);
    for (int i=0;i<8;i++)assert(pthread_join(threads[i],NULL)==0);
#endif
    puts("SDK canonical UDP: pass");return 0;
}
