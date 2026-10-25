#include "tcp.native.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static void exercise_parallel(void)
{
    for (int i=0;i<32;i++) {
        SnSdkTcpListenerRecord *listener=sn_tcp_listener_bind(":0");
        assert(sn_tcp_listener_get_port(listener)>0);
        assert(sn_sdk_tcp_listener_retain(listener)==listener);
        assert(sn_sdk_tcp_listener_refs(listener)==2);
        sn_sdk_tcp_listener_release(listener);
        assert(sn_sdk_tcp_listener_refs(listener)==1);
        sn_sdk_tcp_listener_release(listener);
    }
}
#ifdef _WIN32
static DWORD WINAPI worker(void *argument) { (void)argument;exercise_parallel();return 0; }
#else
static void *worker(void *argument) { (void)argument;exercise_parallel();return NULL; }
#endif

static SnArray *bytes(const unsigned char *data, size_t count)
{
    SnArray *array=sn_array_new(1,(long long)count);array->elem_tag=SN_TAG_BYTE;
    for (size_t i=0;i<count;i++)sn_array_push(array,data+i);
    return array;
}
static SnArray *read_exact(SnSdkTcpStreamRecord *stream, long long count)
{
    SnArray *result=bytes(NULL,0);
    while (result->len<count) {
        SnArray *part=sn_tcp_stream_read(stream,count-result->len);
        assert(part && part->len>0);
        for (long long i=0;i<part->len;i++)sn_array_push(result,(unsigned char *)part->data+i);
        sn_array_free(part);
    }
    return result;
}
static void assert_closed_socket(long long descriptor)
{
#ifdef _WIN32
    int kind=0,length=sizeof(kind);
    assert(getsockopt((SOCKET)descriptor,SOL_SOCKET,SO_TYPE,(char *)&kind,&length)==SOCKET_ERROR);
    assert(WSAGetLastError()==WSAENOTSOCK);
#else
    assert(fcntl((int)descriptor,F_GETFD)==-1 && errno==EBADF);
#endif
}
static void roundtrip(void)
{
    SnSdkTcpListenerRecord *listener=sn_tcp_listener_bind(":0");
    long long listener_fd=listener->socket_fd;
    char address[80];snprintf(address,sizeof(address),"127.0.0.1:%lld",sn_tcp_listener_get_port(listener));
    SnSdkTcpStreamRecord *client=sn_tcp_stream_connect(address);
    SnSdkTcpStreamRecord *server=sn_tcp_listener_accept(listener);
    assert(client && server && sn_tcp_stream_is_valid(client) && sn_tcp_stream_is_valid(server));
    long long server_fd=server->socket_fd;
    char *remote=sn_tcp_stream_get_remote_address(server);
    assert(remote && !strncmp(remote,"127.0.0.1:",10));
    SnSdkTcpStreamRecord *alias=sn_sdk_tcp_stream_retain(server);
    assert(alias==server && sn_sdk_tcp_stream_refs(server)==2);
    sn_sdk_tcp_stream_release(server);
    assert(sn_sdk_tcp_stream_refs(alias)==1);
    sn_tcp_stream_set_timeout(alias,2000);
    sn_tcp_stream_write_line(client,"alpha");
    const unsigned char values[]={0,128,255,10,42};
    SnArray *payload=bytes(values,sizeof(values));
    long long sent=0;
    while (sent<payload->len) {
        SnArray *part=sn_array_slice(payload,sent,payload->len);
        long long written=sn_tcp_stream_write(client,part);sn_array_free(part);
        assert(written>0);sent+=written;
    }
    sn_tcp_stream_dispose(client);sn_tcp_stream_dispose(client);
    assert(!sn_tcp_stream_is_valid(client));sn_sdk_tcp_stream_release(client);
    char *line=sn_tcp_stream_read_line(alias);assert(!strcmp(line,"alpha"));
    SnArray *first=read_exact(alias,3),*rest=sn_tcp_stream_read_all(alias);
    assert(first->len==3 && !memcmp(first->data,values,3));
    assert(rest->len==2 && !memcmp(rest->data,values+3,2));
    sn_sdk_tcp_stream_release(alias);
    /* Owned snapshots survive the backing stream and both alias credits. */
    assert(!strcmp(line,"alpha") && !strncmp(remote,"127.0.0.1:",10));
    assert(((unsigned char *)first->data)[1]==128 && ((unsigned char *)rest->data)[1]==42);
    free(line);free(remote);sn_array_free(payload);sn_array_free(first);sn_array_free(rest);
    sn_sdk_tcp_listener_release(listener);
    assert_closed_socket(server_fd);
    assert_closed_socket(listener_fd);
}

static void shutdown_signal(void)
{
#ifdef _WIN32
    SOCKET signal_socket=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    assert(signal_socket!=INVALID_SOCKET);
#else
    int signal_socket=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    assert(signal_socket>=0);
#endif
    struct sockaddr_in address={0};address.sin_family=AF_INET;
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    assert(bind(signal_socket,(struct sockaddr *)&address,sizeof(address))==0);
#ifdef _WIN32
    int address_length=sizeof(address);
#else
    socklen_t address_length=sizeof(address);
#endif
    assert(getsockname(signal_socket,(struct sockaddr *)&address,&address_length)==0);
    assert(sendto(signal_socket,"x",1,0,(struct sockaddr *)&address,sizeof(address))==1);
    SnSdkTcpListenerRecord *listener=sn_tcp_listener_bind(":0");
    SnSdkTcpStreamRecord *sentinel=sn_tcp_listener_accept_or_shutdown(listener,(long long)signal_socket);
    assert(sentinel && !sn_tcp_stream_is_valid(sentinel));
    sn_sdk_tcp_stream_release(sentinel);sn_sdk_tcp_listener_release(listener);
#ifdef _WIN32
    assert(closesocket(signal_socket)==0);
#else
    assert(close(signal_socket)==0);
#endif
}
#ifndef _WIN32
static void disconnected_write(void)
{
    int descriptors[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,descriptors)==0);
    close(descriptors[1]);
    pid_t child=fork();assert(child>=0);
    if (child==0) {
        signal(SIGPIPE,SIG_DFL);
        SnSdkTcpStreamRecord *stream=sn_sdk_tcp_stream_create();stream->socket_fd=descriptors[0];
        unsigned char value=7;SnArray *payload=bytes(&value,1);
        long long written=sn_tcp_stream_write(stream,payload);
        sn_tcp_stream_write_line(stream,"ignored");
        sn_array_free(payload);sn_sdk_tcp_stream_release(stream);close(descriptors[0]);
        _exit(written==-1?0:1);
    }
    int status=0;assert(waitpid(child,&status,0)==child);close(descriptors[0]);
    if (WIFSIGNALED(status))fprintf(stderr,"TCP write child terminated by signal %d\n",WTERMSIG(status));
    assert(WIFEXITED(status) && WEXITSTATUS(status)==0);
}
#endif

int main(void)
{
    assert(sn_sdk_tcp_stream_storage_size()==sizeof(SnSdkTcpStreamRecord));
    assert(sn_sdk_tcp_listener_storage_size()==sizeof(SnSdkTcpListenerRecord));
    assert(sn_sdk_tcp_stream_field_offset(0)==offsetof(SnSdkTcpStreamRecord,socket_fd));
    assert(sn_sdk_tcp_stream_field_offset(1)==offsetof(SnSdkTcpStreamRecord,remote_addr));
    assert(sn_sdk_tcp_stream_field_offset(2)==offsetof(SnSdkTcpStreamRecord,internal));
    assert(sn_sdk_tcp_stream_field_offset(3)==UINT64_MAX);
    assert(sn_sdk_tcp_listener_field_offset(0)==offsetof(SnSdkTcpListenerRecord,socket_fd));
    assert(sn_sdk_tcp_listener_field_offset(1)==offsetof(SnSdkTcpListenerRecord,bound_port));
    assert(sn_sdk_tcp_listener_field_offset(2)==UINT64_MAX);
#ifndef _WIN32
    int stdin_before=fcntl(0,F_GETFD);
#endif
    SnSdkTcpStreamRecord *empty=sn_sdk_tcp_stream_create();
    assert(empty->socket_fd==0 && !empty->remote_addr && !empty->internal && sn_sdk_tcp_stream_refs(empty)==1);
    sn_sdk_tcp_stream_release(empty);
    SnSdkTcpListenerRecord *zero=sn_sdk_tcp_listener_create();
    assert(zero->socket_fd==0 && zero->bound_port==0);sn_sdk_tcp_listener_release(zero);
#ifndef _WIN32
    assert(fcntl(0,F_GETFD)==stdin_before);
#endif
    assert(!sn_sdk_tcp_stream_retain(NULL) && !sn_sdk_tcp_listener_retain(NULL));
    assert(!sn_sdk_tcp_stream_refs(NULL) && !sn_sdk_tcp_listener_refs(NULL));
    sn_sdk_tcp_stream_release(NULL);sn_sdk_tcp_listener_release(NULL);
    assert(!sn_tcp_stream_is_valid(NULL) && sn_tcp_listener_get_port(NULL)==0);
    sn_tcp_stream_set_timeout(NULL,0);sn_tcp_stream_dispose(NULL);sn_tcp_listener_dispose(NULL);
    assert(sn_tcp_stream_write(NULL,NULL)==0);sn_tcp_stream_write_line(NULL,NULL);
    SnArray *absent=sn_tcp_stream_read(NULL,4);assert(absent->len==0);sn_array_free(absent);
    char *missing=sn_tcp_stream_get_remote_address(NULL);assert(!strcmp(missing,""));free(missing);
#ifdef _WIN32
    HANDLE threads[4];
    for (int i=0;i<4;i++) { threads[i]=CreateThread(NULL,0,worker,NULL,0,NULL);assert(threads[i]); }
    assert(WaitForMultipleObjects(4,threads,TRUE,30000)==WAIT_OBJECT_0);
    for (int i=0;i<4;i++)CloseHandle(threads[i]);
#else
    pthread_t threads[4];
    for (int i=0;i<4;i++)assert(pthread_create(&threads[i],NULL,worker,NULL)==0);
    for (int i=0;i<4;i++)assert(pthread_join(threads[i],NULL)==0);
#endif
    for (int i=0;i<16;i++)roundtrip();
    shutdown_signal();
#ifndef _WIN32
    disconnected_write();
#endif
    puts("SDK canonical TCP: pass");
    return 0;
}
