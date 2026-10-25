#include "tls.native.h"
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
#include <sys/socket.h>
#include <unistd.h>
#endif

#define CHECK(test) do { if (!(test)) { fprintf(stderr,"TLS check failed at %d: %s\n",__LINE__,#test); abort(); } } while (0)

static void closed_socket(long long fd)
{
#ifdef _WIN32
    int kind=0,length=sizeof(kind);
    CHECK(getsockopt((SOCKET)fd,SOL_SOCKET,SO_TYPE,(char *)&kind,&length)==SOCKET_ERROR);
    CHECK(WSAGetLastError()==WSAENOTSOCK);
#else
    CHECK(fcntl((int)fd,F_GETFD)==-1 && errno==EBADF);
#endif
}

static SnArray *bytes(const unsigned char *data,size_t count)
{
    SnArray *result=sn_array_new(1,(long long)count);result->elem_tag=SN_TAG_BYTE;
    for(size_t i=0;i<count;i++)sn_array_push(result,data+i);
    return result;
}

struct Credentials { char *certificate; char *key; };
static void parallel_factories(struct Credentials *credentials)
{
    for(int i=0;i<32;i++) {
        SnSdkTlsListenerRecord *listener=sn_tls_listener_bind("127.0.0.1:0",credentials->certificate,credentials->key);
        CHECK(sn_tls_listener_get_port(listener)>0);
        CHECK(sn_sdk_tls_listener_retain(listener)==listener && sn_sdk_tls_listener_refs(listener)==2);
        sn_sdk_tls_listener_release(listener);CHECK(sn_sdk_tls_listener_refs(listener)==1);
        sn_tls_listener_dispose(listener);sn_tls_listener_dispose(listener);
        CHECK(listener->socket_fd==-1);
        /* Other workers can immediately reuse a closed descriptor number.
         * Kernel closure checks belong to the sequential roundtrips below. */
        sn_sdk_tls_listener_release(listener);
    }
}
#ifdef _WIN32
static DWORD WINAPI factory_worker(void *argument) { parallel_factories(argument);return 0; }
#else
static void *factory_worker(void *argument) { parallel_factories(argument);return NULL; }
#endif

static void shutdown_wakeup(struct Credentials *credentials)
{
    SnSdkTlsListenerRecord *listener=sn_tls_listener_bind("127.0.0.1:0",credentials->certificate,credentials->key);
#ifdef _WIN32
    SOCKET wake=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);CHECK(wake!=INVALID_SOCKET);
#else
    int wake=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);CHECK(wake>=0);
#endif
    struct sockaddr_in address={0};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    CHECK(bind(wake,(struct sockaddr *)&address,sizeof(address))==0);
#ifdef _WIN32
    int length=sizeof(address);
#else
    socklen_t length=sizeof(address);
#endif
    CHECK(getsockname(wake,(struct sockaddr *)&address,&length)==0);
    CHECK(sendto(wake,"x",1,0,(struct sockaddr *)&address,sizeof(address))==1);
    SnSdkTlsStreamRecord *sentinel=sn_tls_listener_accept_or_shutdown(listener,(long long)wake);
    CHECK(sentinel && !sn_tls_stream_is_valid(sentinel));sn_sdk_tls_stream_release(sentinel);
    sn_sdk_tls_listener_release(listener);
#ifdef _WIN32
    CHECK(closesocket(wake)==0);
#else
    CHECK(close(wake)==0);
#endif
}

static void serve(SnSdkTlsListenerRecord *listener)
{
    long long listener_fd=listener->socket_fd;
    SnSdkTlsStreamRecord *stream=sn_tls_listener_accept(listener);
    CHECK(stream && sn_tls_stream_is_valid(stream));
    /* SSL keeps its context alive after the listener's last owner leaves. */
    sn_sdk_tls_listener_release(listener);closed_socket(listener_fd);
    char *remote=sn_tls_stream_get_remote_address(stream);
    CHECK(remote && !strncmp(remote,"127.0.0.1:",10));
    char *line=sn_tls_stream_read_line(stream);CHECK(line && !strcmp(line,"ping"));
    const unsigned char payload[]={0,128,255,42};
    SnArray *data=bytes(payload,sizeof(payload));
    CHECK(sn_tls_stream_write(stream,data)==4);
    sn_tls_stream_write_line(stream,"\xc3\xa9\xe6\xbc\xa2");
    CHECK(sn_sdk_tls_stream_retain(stream)==stream && sn_sdk_tls_stream_refs(stream)==2);
    sn_sdk_tls_stream_release(stream);CHECK(sn_sdk_tls_stream_refs(stream)==1);
    long long fd=stream->socket_fd;sn_sdk_tls_stream_release(stream);closed_socket(fd);
    CHECK(!strcmp(line,"ping") && !strncmp(remote,"127.0.0.1:",10));
    free(line);free(remote);sn_array_free(data);
}
#ifdef _WIN32
static DWORD WINAPI server(void *argument) { serve(argument);return 0; }
#else
static void *server(void *argument) { serve(argument);return NULL; }
#endif

int main(int argc,char **argv)
{
    CHECK(argc==3);
    CHECK(sn_sdk_tls_stream_storage_size()==sizeof(SnSdkTlsStreamRecord));
    CHECK(sn_sdk_tls_listener_storage_size()==sizeof(SnSdkTlsListenerRecord));
    CHECK(sn_sdk_tls_stream_field_offset(0)==offsetof(SnSdkTlsStreamRecord,socket_fd));
    CHECK(sn_sdk_tls_stream_field_offset(1)==offsetof(SnSdkTlsStreamRecord,ssl_ptr));
    CHECK(sn_sdk_tls_stream_field_offset(2)==offsetof(SnSdkTlsStreamRecord,remote_addr));
#ifndef _WIN32
    int input=fcntl(0,F_GETFD);
#endif
    SnSdkTlsStreamRecord *empty=sn_sdk_tls_stream_create();
    CHECK(empty && empty->socket_fd==0 && empty->ssl_ptr==0 && !empty->remote_addr);
    sn_sdk_tls_stream_release(empty);
    SnSdkTlsListenerRecord *zero=sn_sdk_tls_listener_create();
    CHECK(zero && zero->socket_fd==0 && zero->bound_port==0);sn_sdk_tls_listener_release(zero);
#ifndef _WIN32
    CHECK(fcntl(0,F_GETFD)==input);
#endif
    CHECK(!sn_sdk_tls_stream_retain(NULL) && !sn_sdk_tls_listener_retain(NULL));
    sn_sdk_tls_stream_release(NULL);sn_sdk_tls_listener_release(NULL);
    CHECK(sn_sdk_tls_stream_refs(NULL)==0 && sn_sdk_tls_listener_refs(NULL)==0);
    CHECK(!sn_tls_stream_is_valid(NULL) && sn_tls_listener_get_port(NULL)==0);
    SnArray *nothing=sn_tls_stream_read(NULL,8);CHECK(nothing && nothing->len==0);sn_array_free(nothing);
    nothing=sn_tls_stream_read_all(NULL);CHECK(nothing && nothing->len==0);sn_array_free(nothing);
    char *text=sn_tls_stream_read_line(NULL);CHECK(text && !*text);free(text);
    text=sn_tls_stream_get_remote_address(NULL);CHECK(text && !*text);free(text);
    CHECK(sn_tls_stream_write(NULL,NULL)==0);sn_tls_stream_write_line(NULL,"ignored");
    sn_tls_stream_dispose(NULL);sn_tls_listener_dispose(NULL);
    struct Credentials credentials={argv[1],argv[2]};
#ifdef _WIN32
    HANDLE workers[4];
    for(int i=0;i<4;i++) { workers[i]=CreateThread(NULL,0,factory_worker,&credentials,0,NULL);CHECK(workers[i]); }
    for(int i=0;i<4;i++) { CHECK(WaitForSingleObject(workers[i],10000)==WAIT_OBJECT_0);CHECK(CloseHandle(workers[i])); }
#else
    pthread_t workers[4];
    for(int i=0;i<4;i++)CHECK(pthread_create(&workers[i],NULL,factory_worker,&credentials)==0);
    for(int i=0;i<4;i++)CHECK(pthread_join(workers[i],NULL)==0);
#endif
    shutdown_wakeup(&credentials);
    for(int iteration=0;iteration<4;iteration++) {
        SnSdkTlsListenerRecord *listener=sn_tls_listener_bind("127.0.0.1:0",argv[1],argv[2]);
        CHECK(listener && sn_sdk_tls_listener_refs(listener)==1);
        char address[80];snprintf(address,sizeof(address),"localhost:%lld",sn_tls_listener_get_port(listener));
#ifdef _WIN32
        HANDLE thread=CreateThread(NULL,0,server,listener,0,NULL);CHECK(thread!=NULL);
#else
        pthread_t thread;CHECK(pthread_create(&thread,NULL,server,listener)==0);
#endif
        SnSdkTlsStreamRecord *stream=sn_tls_stream_connect(address);CHECK(sn_tls_stream_is_valid(stream));
        char *remote=sn_tls_stream_get_remote_address(stream);CHECK(!strcmp(remote,address));
        sn_tls_stream_write_line(stream,"ping");
        const unsigned char wanted[]={0,128,255,42};
        SnArray *received=bytes(NULL,0);
        while(received->len<4) {
            SnArray *part=sn_tls_stream_read(stream,4-received->len);CHECK(part && part->len>0);
            for(long long i=0;i<part->len;i++)sn_array_push(received,(unsigned char *)part->data+i);
            sn_array_free(part);
        }
        char *line=sn_tls_stream_read_line(stream);CHECK(!strcmp(line,"\xc3\xa9\xe6\xbc\xa2"));
        SnArray *eof=sn_tls_stream_read_all(stream);CHECK(eof && eof->len==0);
        long long fd=stream->socket_fd;
        sn_tls_stream_dispose(stream);sn_tls_stream_dispose(stream);CHECK(!sn_tls_stream_is_valid(stream));
        sn_sdk_tls_stream_release(stream);closed_socket(fd);
        CHECK(received->len==4 && !memcmp(received->data,wanted,4) && !strcmp(remote,address));
        free(remote);free(line);sn_array_free(received);sn_array_free(eof);
#ifdef _WIN32
        CHECK(WaitForSingleObject(thread,10000)==WAIT_OBJECT_0);CHECK(CloseHandle(thread));
#else
        CHECK(pthread_join(thread,NULL)==0);
#endif
    }
    puts("SDK canonical TLS: pass");
    return 0;
}
