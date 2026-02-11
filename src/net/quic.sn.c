/* ==============================================================================
 * sdk/net/quic.sn.c - Self-contained QUIC Implementation using ngtcp2 + OpenSSL
 * ==============================================================================
 * Provides QUIC transport: client connections, server/listener, bidirectional
 * and unidirectional streams, 0-RTT early data, connection migration, and
 * configurable flow control.
 *
 * Architecture:
 *   - One I/O thread per connection handles packet processing and timers
 *   - Mutex per connection protects ngtcp2_conn state
 *   - Per-stream condition variable for blocking read operations
 *   - Arena allocation for user-visible data
 *   - Blocking API: connect/read/accept all block until complete
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Include runtime for proper memory management */
#include "runtime/array/runtime_array_v2.h"
#include "runtime/string/runtime_string_v2.h"

/* ngtcp2 includes */
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

/* OpenSSL includes */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* Platform-specific includes */
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <wincrypt.h>
    #include <process.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "crypt32.lib")

    typedef SOCKET socket_t;
    #define INVALID_SOCKET_VAL INVALID_SOCKET
    #define CLOSE_SOCKET(s) closesocket(s)
    #define GET_SOCKET_ERROR() WSAGetLastError()
    #define POLL WSAPoll

    typedef HANDLE sn_thread_t;
    typedef CRITICAL_SECTION mutex_t;
    typedef CONDITION_VARIABLE cond_t;

    #define MUTEX_INIT(m) InitializeCriticalSection(m)
    #define MUTEX_LOCK(m) EnterCriticalSection(m)
    #define MUTEX_UNLOCK(m) LeaveCriticalSection(m)
    #define MUTEX_DESTROY(m) DeleteCriticalSection(m)
    #define COND_INIT(c) InitializeConditionVariable(c)
    #define COND_WAIT(c, m) SleepConditionVariableCS(c, m, INFINITE)
    #define COND_TIMEDWAIT(c, m, ms) SleepConditionVariableCS(c, m, ms)
    #define COND_SIGNAL(c) WakeConditionVariable(c)
    #define COND_BROADCAST(c) WakeAllConditionVariable(c)
    #define COND_DESTROY(c) /* no-op on Windows */

#elif defined(__APPLE__)
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <poll.h>
    #include <pthread.h>
    #include <Security/Security.h>

    typedef int socket_t;
    #define INVALID_SOCKET_VAL (-1)
    #define CLOSE_SOCKET(s) close(s)
    #define GET_SOCKET_ERROR() errno
    #define POLL poll

    typedef pthread_t sn_thread_t;
    typedef pthread_mutex_t mutex_t;
    typedef pthread_cond_t cond_t;

    #define MUTEX_INIT(m) pthread_mutex_init(m, NULL)
    #define MUTEX_LOCK(m) pthread_mutex_lock(m)
    #define MUTEX_UNLOCK(m) pthread_mutex_unlock(m)
    #define MUTEX_DESTROY(m) pthread_mutex_destroy(m)
    #define COND_INIT(c) pthread_cond_init(c, NULL)
    #define COND_WAIT(c, m) pthread_cond_wait(c, m)
    #define COND_SIGNAL(c) pthread_cond_signal(c)
    #define COND_BROADCAST(c) pthread_cond_broadcast(c)
    #define COND_DESTROY(c) pthread_cond_destroy(c)

#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <poll.h>
    #include <pthread.h>

    typedef int socket_t;
    #define INVALID_SOCKET_VAL (-1)
    #define CLOSE_SOCKET(s) close(s)
    #define GET_SOCKET_ERROR() errno
    #define POLL poll

    typedef pthread_t sn_thread_t;
    typedef pthread_mutex_t mutex_t;
    typedef pthread_cond_t cond_t;

    #define MUTEX_INIT(m) pthread_mutex_init(m, NULL)
    #define MUTEX_LOCK(m) pthread_mutex_lock(m)
    #define MUTEX_UNLOCK(m) pthread_mutex_unlock(m)
    #define MUTEX_DESTROY(m) pthread_mutex_destroy(m)
    #define COND_INIT(c) pthread_cond_init(c, NULL)
    #define COND_WAIT(c, m) pthread_cond_wait(c, m)
    #define COND_SIGNAL(c) pthread_cond_signal(c)
    #define COND_BROADCAST(c) pthread_cond_broadcast(c)
    #define COND_DESTROY(c) pthread_cond_destroy(c)
#endif

/* ============================================================================
 * WinSock Initialization (Windows only)
 * ============================================================================ */

#ifdef _WIN32
static int winsock_initialized = 0;

static void ensure_winsock_initialized(void) {
    if (!winsock_initialized) {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            fprintf(stderr, "QUIC: WSAStartup failed: %d\n", result);
            exit(1);
        }
        winsock_initialized = 1;
    }
}
#else
#define ensure_winsock_initialized() ((void)0)
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

#define QUIC_MAX_PACKET_SIZE  1200
#define QUIC_MAX_STREAMS      128
#define QUIC_RECV_BUF_SIZE    65536
#define QUIC_STREAM_BUF_SIZE  65536
#define QUIC_DEFAULT_MAX_BIDI_STREAMS  100
#define QUIC_DEFAULT_MAX_UNI_STREAMS   100
#define QUIC_DEFAULT_MAX_STREAM_WINDOW 262144   /* 256 KB */
#define QUIC_DEFAULT_MAX_CONN_WINDOW   1048576  /* 1 MB */
#define QUIC_DEFAULT_IDLE_TIMEOUT_MS   30000    /* 30 seconds */
#define QUIC_MAX_INCOMING_STREAMS      64
#define QUIC_ALPN "\x02hq"   /* HTTP/0.9 over QUIC (h3 would be "\x02h3") */

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

typedef struct RtQuicConfig {
    int max_bidi_streams;
    int max_uni_streams;
    int max_stream_window;
    int max_conn_window;
    int idle_timeout_ms;
} RtQuicConfig;

typedef struct RtQuicStreamBuf {
    uint8_t *data;
    size_t capacity;
    size_t read_pos;
    size_t write_pos;
    bool fin_received;
} RtQuicStreamBuf;

typedef struct RtQuicStream {
    int64_t stream_id;
    void *conn_ptr;             /* back-pointer to RtQuicConnection */
    RtQuicStreamBuf recv_buf;
    mutex_t stream_mutex;
    cond_t read_cond;
    bool closed;
    bool write_closed;
    bool is_uni;
} RtQuicStream;

typedef struct RtQuicConnection {
    void *conn_ptr;             /* ngtcp2_conn* */
    socket_t socket_fd;

    /* ngtcp2 connection handle */
    ngtcp2_conn *qconn;

    /* SSL */
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
    ngtcp2_crypto_conn_ref conn_ref;

    /* Remote address */
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;
    char *remote_addr_str;

    /* Local address */
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;

    /* Streams */
    RtQuicStream *streams[QUIC_MAX_STREAMS];
    int stream_count;

    /* Incoming stream queue (for acceptStream) */
    int64_t incoming_streams[QUIC_MAX_INCOMING_STREAMS];
    int incoming_head;
    int incoming_tail;
    int incoming_count;
    cond_t accept_stream_cond;

    /* Connection state */
    mutex_t conn_mutex;
    cond_t handshake_cond;
    bool handshake_complete;
    bool closed;
    bool is_server;

    /* I/O thread */
    sn_thread_t io_thread;
    bool io_running;

    /* Resumption token */
    uint8_t *resumption_token;
    size_t resumption_token_len;

    /* Arena for allocations */
    RtArenaV2 *arena;
} RtQuicConnection;

typedef struct RtQuicListener {
    socket_t socket_fd;
    int bound_port;

    SSL_CTX *ssl_ctx;

    /* Accepted connections queue */
    RtQuicConnection *accept_queue[QUIC_MAX_INCOMING_STREAMS];
    int accept_head;
    int accept_tail;
    int accept_count;
    mutex_t accept_mutex;
    cond_t accept_cond;

    /* Existing server connections (by DCID) */
    RtQuicConnection *connections[QUIC_MAX_STREAMS];
    int connection_count;
    mutex_t conn_list_mutex;

    /* Listener thread */
    sn_thread_t listen_thread;
    bool running;

    /* Config */
    RtQuicConfig config;

    /* Local address */
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;

    /* Arena */
    RtArenaV2 *arena;
} RtQuicListener;

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

static void quic_io_thread_func(RtQuicConnection *conn);
static void quic_listener_thread_func(RtQuicListener *listener);
static int quic_flush_tx(RtQuicConnection *conn);
static RtQuicStream *quic_find_or_create_stream(RtQuicConnection *conn, int64_t stream_id);
static ngtcp2_tstamp quic_timestamp(void);
static void quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx);
static int quic_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                          uint8_t *token, size_t cidlen, void *user_data);
static int quic_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
                                     int64_t stream_id, uint64_t offset,
                                     const uint8_t *data, size_t datalen, void *user_data,
                                     void *stream_user_data);
static int quic_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data);
static int quic_stream_close_cb(ngtcp2_conn *conn, uint32_t flags,
                                 int64_t stream_id, uint64_t app_error_code,
                                 void *user_data, void *stream_user_data);
static int quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data);
static void load_certificates(SSL_CTX *ctx);

/* ============================================================================
 * OpenSSL Initialization
 * ============================================================================ */

static int openssl_initialized = 0;

static void ensure_openssl_initialized(void) {
    if (!openssl_initialized) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
#else
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                        OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
        ngtcp2_crypto_ossl_init();
        openssl_initialized = 1;
    }
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

static ngtcp2_tstamp quic_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}

static void quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    (void)rand_ctx;
    RAND_bytes(dest, (int)destlen);
}

static int quic_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                          uint8_t *token, size_t cidlen, void *user_data) {
    (void)conn;
    (void)user_data;
    RAND_bytes(cid->data, (int)cidlen);
    cid->datalen = cidlen;
    RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

static void set_socket_nonblocking(socket_t sock) {
#ifdef _WIN32
    unsigned long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

/* Send a QUIC packet on the connection's socket.
 * Client sockets are connected, so we use send() to avoid EISCONN on macOS/BSD.
 * Server sockets are unconnected (shared listener socket), so we use sendto(). */
static ssize_t quic_send_packet(RtQuicConnection *conn, const uint8_t *buf, size_t len) {
    if (conn->is_server) {
        return sendto(conn->socket_fd, (const char *)buf, len, 0,
                      (struct sockaddr *)&conn->remote_addr, conn->remote_addrlen);
    } else {
        return send(conn->socket_fd, (const char *)buf, len, 0);
    }
}

static int parse_address(const char *address, char *host, size_t hostlen, char *port, size_t portlen) {
    const char *colon = NULL;

    if (address[0] == '[') {
        /* IPv6: [host]:port */
        const char *bracket = strchr(address, ']');
        if (!bracket) return -1;
        size_t len = bracket - address - 1;
        if (len >= hostlen) return -1;
        memcpy(host, address + 1, len);
        host[len] = '\0';
        if (bracket[1] == ':') {
            colon = bracket + 1;
        }
    } else {
        colon = strrchr(address, ':');
        if (colon) {
            size_t len = colon - address;
            if (len >= hostlen) return -1;
            memcpy(host, address, len);
            host[len] = '\0';
        } else {
            strncpy(host, address, hostlen - 1);
            host[hostlen - 1] = '\0';
        }
    }

    if (colon && colon[1] != '\0') {
        strncpy(port, colon + 1, portlen - 1);
        port[portlen - 1] = '\0';
    } else {
        strncpy(port, "443", portlen - 1);
        port[portlen - 1] = '\0';
    }

    return 0;
}

static char *format_address(struct sockaddr_storage *addr, socklen_t addrlen, RtArenaV2 *arena) {
    char host[NI_MAXHOST];
    char port[NI_MAXSERV];
    (void)addrlen;
    if (getnameinfo((struct sockaddr *)addr, addrlen, host, sizeof(host),
                    port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        return NULL;
    }
    size_t len = strlen(host) + strlen(port) + 2;
    char *result = (char *)rt_arena_alloc(arena, len);
    snprintf(result, len, "%s:%s", host, port);
    return result;
}

/* ============================================================================
 * Stream Buffer Operations
 * ============================================================================ */

static void stream_buf_init(RtQuicStreamBuf *buf) {
    buf->data = (uint8_t *)malloc(QUIC_STREAM_BUF_SIZE);
    buf->capacity = QUIC_STREAM_BUF_SIZE;
    buf->read_pos = 0;
    buf->write_pos = 0;
    buf->fin_received = false;
}

static void stream_buf_destroy(RtQuicStreamBuf *buf) {
    free(buf->data);
    buf->data = NULL;
}

static size_t stream_buf_available(RtQuicStreamBuf *buf) {
    return buf->write_pos - buf->read_pos;
}

static void stream_buf_compact(RtQuicStreamBuf *buf) {
    if (buf->read_pos > 0) {
        size_t avail = stream_buf_available(buf);
        if (avail > 0) {
            memmove(buf->data, buf->data + buf->read_pos, avail);
        }
        buf->write_pos = avail;
        buf->read_pos = 0;
    }
}

static int stream_buf_append(RtQuicStreamBuf *buf, const uint8_t *data, size_t len) {
    if (buf->write_pos + len > buf->capacity) {
        stream_buf_compact(buf);
        if (buf->write_pos + len > buf->capacity) {
            /* Grow buffer */
            size_t new_cap = buf->capacity * 2;
            while (new_cap < buf->write_pos + len) new_cap *= 2;
            uint8_t *new_data = (uint8_t *)realloc(buf->data, new_cap);
            if (!new_data) return -1;
            buf->data = new_data;
            buf->capacity = new_cap;
        }
    }
    memcpy(buf->data + buf->write_pos, data, len);
    buf->write_pos += len;
    return 0;
}

/* ============================================================================
 * ngtcp2 Callbacks
 * ============================================================================ */

static int quic_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
                                     int64_t stream_id, uint64_t offset,
                                     const uint8_t *data, size_t datalen,
                                     void *user_data, void *stream_user_data) {
    (void)conn;
    (void)offset;
    (void)stream_user_data;
    RtQuicConnection *qc = (RtQuicConnection *)user_data;

    RtQuicStream *stream = quic_find_or_create_stream(qc, stream_id);
    if (!stream) return 0;

    MUTEX_LOCK(&stream->stream_mutex);
    if (datalen > 0) {
        stream_buf_append(&stream->recv_buf, data, datalen);
    }
    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
        stream->recv_buf.fin_received = true;
    }
    COND_SIGNAL(&stream->read_cond);
    MUTEX_UNLOCK(&stream->stream_mutex);

    ngtcp2_conn_extend_max_stream_offset(qc->qconn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(qc->qconn, datalen);

    return 0;
}

static int quic_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    (void)conn;
    RtQuicConnection *qc = (RtQuicConnection *)user_data;

    /* Create stream entry */
    quic_find_or_create_stream(qc, stream_id);

    /* Add to incoming queue */
    if (qc->incoming_count < QUIC_MAX_INCOMING_STREAMS) {
        qc->incoming_streams[qc->incoming_tail] = stream_id;
        qc->incoming_tail = (qc->incoming_tail + 1) % QUIC_MAX_INCOMING_STREAMS;
        qc->incoming_count++;
        COND_SIGNAL(&qc->accept_stream_cond);
    }

    return 0;
}

static int quic_stream_close_cb(ngtcp2_conn *conn, uint32_t flags,
                                 int64_t stream_id, uint64_t app_error_code,
                                 void *user_data, void *stream_user_data) {
    (void)conn;
    (void)flags;
    (void)app_error_code;
    (void)stream_user_data;
    RtQuicConnection *qc = (RtQuicConnection *)user_data;

    for (int i = 0; i < qc->stream_count; i++) {
        if (qc->streams[i] && qc->streams[i]->stream_id == stream_id) {
            MUTEX_LOCK(&qc->streams[i]->stream_mutex);
            qc->streams[i]->closed = true;
            qc->streams[i]->recv_buf.fin_received = true;
            COND_SIGNAL(&qc->streams[i]->read_cond);
            MUTEX_UNLOCK(&qc->streams[i]->stream_mutex);
            break;
        }
    }

    return 0;
}

static int quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    RtQuicConnection *qc = (RtQuicConnection *)user_data;

    qc->handshake_complete = true;
    COND_SIGNAL(&qc->handshake_cond);

    /* Extract session ticket for 0-RTT */
    SSL_SESSION *session = SSL_get1_session(qc->ssl);
    if (session) {
        unsigned char *buf = NULL;
        size_t len = 0;
        /* Serialize session for later use */
        len = i2d_SSL_SESSION(session, &buf);
        if (buf && len > 0) {
            qc->resumption_token = (uint8_t *)malloc(len);
            if (qc->resumption_token) {
                memcpy(qc->resumption_token, buf, len);
                qc->resumption_token_len = len;
            }
            OPENSSL_free(buf);
        }
        SSL_SESSION_free(session);
    }

    return 0;
}

/* Note: recv_retry uses ngtcp2_crypto_recv_retry_cb from the library */

/* ============================================================================
 * Stream Management
 * ============================================================================ */

static RtQuicStream *quic_find_or_create_stream(RtQuicConnection *conn, int64_t stream_id) {
    /* Search existing streams */
    for (int i = 0; i < conn->stream_count; i++) {
        if (conn->streams[i] && conn->streams[i]->stream_id == stream_id) {
            return conn->streams[i];
        }
    }

    /* Create new stream */
    if (conn->stream_count >= QUIC_MAX_STREAMS) return NULL;

    RtQuicStream *stream = (RtQuicStream *)calloc(1, sizeof(RtQuicStream));
    if (!stream) return NULL;

    stream->stream_id = stream_id;
    stream->conn_ptr = conn;
    stream_buf_init(&stream->recv_buf);
    MUTEX_INIT(&stream->stream_mutex);
    COND_INIT(&stream->read_cond);
    stream->closed = false;
    stream->write_closed = false;
    /* Unidirectional streams: bit 1 of stream_id indicates uni */
    stream->is_uni = (stream_id & 0x2) != 0;

    conn->streams[conn->stream_count++] = stream;
    return stream;
}

static void quic_stream_free(RtQuicStream *stream) {
    if (!stream) return;
    stream_buf_destroy(&stream->recv_buf);
    MUTEX_DESTROY(&stream->stream_mutex);
    COND_DESTROY(&stream->read_cond);
    free(stream);
}

/* ============================================================================
 * Certificate Loading (same pattern as TLS/DTLS)
 * ============================================================================ */

#ifdef _WIN32
static void load_windows_certs(SSL_CTX *ctx) {
    HCERTSTORE store = CertOpenSystemStore(0, "ROOT");
    if (!store) return;
    X509_STORE *x509_store = SSL_CTX_get_cert_store(ctx);
    PCCERT_CONTEXT cert_ctx = NULL;
    while ((cert_ctx = CertEnumCertificatesInStore(store, cert_ctx)) != NULL) {
        const unsigned char *cert_data = cert_ctx->pbCertEncoded;
        X509 *x509 = d2i_X509(NULL, &cert_data, cert_ctx->cbCertEncoded);
        if (x509) {
            X509_STORE_add_cert(x509_store, x509);
            X509_free(x509);
        }
    }
    CertCloseStore(store, 0);
}
#elif defined(__APPLE__)
static void load_macos_certs(SSL_CTX *ctx) {
    CFArrayRef certs = NULL;
    OSStatus status = SecTrustCopyAnchorCertificates(&certs);
    if (status != errSecSuccess || !certs) return;
    X509_STORE *x509_store = SSL_CTX_get_cert_store(ctx);
    CFIndex count = CFArrayGetCount(certs);
    for (CFIndex i = 0; i < count; i++) {
        SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
        CFDataRef data = SecCertificateCopyData(cert);
        if (data) {
            const unsigned char *ptr = CFDataGetBytePtr(data);
            X509 *x509 = d2i_X509(NULL, &ptr, CFDataGetLength(data));
            if (x509) {
                X509_STORE_add_cert(x509_store, x509);
                X509_free(x509);
            }
            CFRelease(data);
        }
    }
    CFRelease(certs);
}
#endif

static void load_certificates(SSL_CTX *ctx) {
    const char *sn_certs = getenv("SN_CERTS");
    if (sn_certs && strlen(sn_certs) > 0) {
        /* Try as file first, then as directory */
        if (SSL_CTX_load_verify_locations(ctx, sn_certs, NULL) == 1) return;
        if (SSL_CTX_load_verify_locations(ctx, NULL, sn_certs) == 1) return;
    }
#ifdef _WIN32
    load_windows_certs(ctx);
#elif defined(__APPLE__)
    load_macos_certs(ctx);
#else
    SSL_CTX_set_default_verify_paths(ctx);
#endif
}

/* ============================================================================
 * SSL Setup for QUIC (ngtcp2 v1.20 API)
 * ============================================================================ */

/* Connection ref callback - returns ngtcp2_conn from SSL app_data */
static ngtcp2_conn *quic_get_conn_cb(ngtcp2_crypto_conn_ref *conn_ref) {
    RtQuicConnection *qc = (RtQuicConnection *)conn_ref->user_data;
    return qc->qconn;
}

static int quic_ssl_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                                    const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl;
    (void)arg;
    /* Select "hq" ALPN */
    if (SSL_select_next_proto((unsigned char **)out, outlen,
                              (const unsigned char *)QUIC_ALPN, sizeof(QUIC_ALPN) - 1,
                              in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *create_client_ssl_ctx(void) {
    ensure_openssl_initialized();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* Load CA certs for verification */
    load_certificates(ctx);

    /* If SN_CERTS is set, verify peer; otherwise skip verification
     * (allows self-signed certs in testing) */
    const char *sn_certs = getenv("SN_CERTS");
    if (sn_certs && strlen(sn_certs) > 0) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    return ctx;
}

static SSL_CTX *create_server_ssl_ctx(const char *cert_file, const char *key_file) {
    ensure_openssl_initialized();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* Load server cert and key */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) != 1) {
        fprintf(stderr, "QUIC: Failed to load certificate: %s\n", cert_file);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "QUIC: Failed to load private key: %s\n", key_file);
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* ALPN negotiation */
    SSL_CTX_set_alpn_select_cb(ctx, quic_ssl_alpn_select_cb, NULL);

    /* Session tickets for 0-RTT */
    SSL_CTX_set_max_early_data(ctx, UINT32_MAX);

    return ctx;
}

static SSL *create_client_ssl(SSL_CTX *ctx, const char *hostname, RtQuicConnection *conn) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return NULL;

    /* Set hostname for SNI */
    SSL_set_tlsext_host_name(ssl, hostname);

    /* Set ALPN */
    SSL_set_alpn_protos(ssl, (const unsigned char *)QUIC_ALPN, sizeof(QUIC_ALPN) - 1);

    /* Configure SSL for ngtcp2 QUIC client */
    ngtcp2_crypto_ossl_configure_client_session(ssl);

    /* Set conn_ref as app data for ngtcp2 crypto callbacks */
    conn->conn_ref.get_conn = quic_get_conn_cb;
    conn->conn_ref.user_data = conn;
    SSL_set_app_data(ssl, &conn->conn_ref);

    SSL_set_connect_state(ssl);

    return ssl;
}

static SSL *create_server_ssl(SSL_CTX *ctx, RtQuicConnection *conn) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return NULL;

    /* Configure SSL for ngtcp2 QUIC server */
    ngtcp2_crypto_ossl_configure_server_session(ssl);

    /* Set conn_ref as app data for ngtcp2 crypto callbacks */
    conn->conn_ref.get_conn = quic_get_conn_cb;
    conn->conn_ref.user_data = conn;
    SSL_set_app_data(ssl, &conn->conn_ref);

    SSL_set_accept_state(ssl);

    return ssl;
}

/* ============================================================================
 * I/O Thread (per connection)
 * ============================================================================ */

static int quic_flush_tx(RtQuicConnection *conn) {
    uint8_t buf[QUIC_MAX_PACKET_SIZE];
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi;

    for (;;) {
        ngtcp2_vec datav;
        int64_t stream_id = -1;
        int fin = 0;

        /* Try to find a stream with pending write data - for now just send ack-eliciting */
        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            conn->qconn, &ps.path, &pi,
            buf, sizeof(buf),
            NULL, /* pdatalen */
            NGTCP2_WRITE_STREAM_FLAG_NONE,
            stream_id, &datav, 0, quic_timestamp());

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE) continue;
            return (int)nwrite;
        }
        if (nwrite == 0) break;

        /* Send packet (socket is connected, use send not sendto to avoid
         * EISCONN on macOS/BSD which rejects sendto with address on connected sockets) */
        ssize_t sent = send(conn->socket_fd, (const char *)buf, (size_t)nwrite, 0);
        if (sent < 0) {
            /* EAGAIN/EWOULDBLOCK is ok */
#ifdef _WIN32
            if (GET_SOCKET_ERROR() == WSAEWOULDBLOCK) break;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
#endif
            return -1;
        }
    }

    return 0;
}

static void *quic_io_thread_entry(void *arg) {
    RtQuicConnection *conn = (RtQuicConnection *)arg;
    quic_io_thread_func(conn);
    return NULL;
}

static void quic_io_thread_func(RtQuicConnection *conn) {
    uint8_t buf[QUIC_RECV_BUF_SIZE];
    struct pollfd pfd;
    pfd.fd = conn->socket_fd;
    pfd.events = POLLIN;

    while (conn->io_running && !conn->closed) {
        /* Calculate timeout from ngtcp2 expiry */
        ngtcp2_tstamp now = quic_timestamp();
        ngtcp2_tstamp expiry;

        MUTEX_LOCK(&conn->conn_mutex);
        expiry = ngtcp2_conn_get_expiry(conn->qconn);
        MUTEX_UNLOCK(&conn->conn_mutex);

        int timeout_ms;
        if (expiry <= now) {
            timeout_ms = 0;
        } else {
            ngtcp2_tstamp diff = expiry - now;
            timeout_ms = (int)(diff / NGTCP2_MILLISECONDS);
            if (timeout_ms > 1000) timeout_ms = 1000;
        }
        if (timeout_ms < 1) timeout_ms = 1;

        int ret = POLL(&pfd, 1, timeout_ms);

        MUTEX_LOCK(&conn->conn_mutex);

        if (conn->closed) {
            MUTEX_UNLOCK(&conn->conn_mutex);
            break;
        }

        if (ret > 0 && (pfd.revents & POLLIN)) {
            /* Read incoming packet */
            struct sockaddr_storage from_addr;
            socklen_t from_len = sizeof(from_addr);

            ssize_t nread = recvfrom(conn->socket_fd, (char *)buf, sizeof(buf), 0,
                                     (struct sockaddr *)&from_addr, &from_len);

            if (nread > 0) {
                ngtcp2_path path;
                memset(&path, 0, sizeof(path));
                path.local.addr = (struct sockaddr *)&conn->local_addr;
                path.local.addrlen = conn->local_addrlen;
                path.remote.addr = (struct sockaddr *)&from_addr;
                path.remote.addrlen = from_len;

                ngtcp2_pkt_info pi;
                memset(&pi, 0, sizeof(pi));

                int rv = ngtcp2_conn_read_pkt(conn->qconn, &path, &pi,
                                               buf, (size_t)nread, quic_timestamp());
                if (rv < 0) {
                    if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
                        conn->closed = true;
                        COND_BROADCAST(&conn->handshake_cond);
                        COND_BROADCAST(&conn->accept_stream_cond);
                        MUTEX_UNLOCK(&conn->conn_mutex);
                        break;
                    }
                }
            }
        }

        /* Handle timer expiry */
        now = quic_timestamp();
        expiry = ngtcp2_conn_get_expiry(conn->qconn);
        if (expiry <= now) {
            int rv = ngtcp2_conn_handle_expiry(conn->qconn, now);
            if (rv < 0) {
                conn->closed = true;
                COND_BROADCAST(&conn->handshake_cond);
                MUTEX_UNLOCK(&conn->conn_mutex);
                break;
            }
        }

        /* Flush any pending TX */
        quic_flush_tx(conn);

        MUTEX_UNLOCK(&conn->conn_mutex);
    }
}

/* ============================================================================
 * Connection Creation (Client)
 * ============================================================================ */

static RtQuicConnection *quic_connection_create(RtArenaV2 *arena, const char *address,
                                                 RtQuicConfig *config, bool early,
                                                 const uint8_t *token, size_t token_len) {
    ensure_winsock_initialized();

    char host[256], port[16];
    if (parse_address(address, host, sizeof(host), port, sizeof(port)) != 0) {
        fprintf(stderr, "QUIC: Invalid address: %s\n", address);
        return NULL;
    }

    /* Resolve address */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        fprintf(stderr, "QUIC: Failed to resolve: %s\n", host);
        return NULL;
    }

    /* Create UDP socket */
    socket_t sock = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET_VAL) {
        freeaddrinfo(res);
        fprintf(stderr, "QUIC: Failed to create socket\n");
        return NULL;
    }

    /* Connect socket (for convenience - filters incoming packets) */
    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
        CLOSE_SOCKET(sock);
        freeaddrinfo(res);
        fprintf(stderr, "QUIC: Failed to connect socket\n");
        return NULL;
    }

    set_socket_nonblocking(sock);

    /* Get local address */
    struct sockaddr_storage local_addr;
    socklen_t local_len = sizeof(local_addr);
    getsockname(sock, (struct sockaddr *)&local_addr, &local_len);

    /* Allocate connection from arena. rt_arena_alloc uses pinned allocations
     * that will never be moved by the compactor, which is required because
     * RtQuicConnection contains pthread_mutex_t and pthread_cond_t. */
    RtQuicConnection *conn = (RtQuicConnection *)rt_arena_alloc(arena, sizeof(RtQuicConnection));
    memset(conn, 0, sizeof(RtQuicConnection));
    conn->arena = arena;
    conn->socket_fd = sock;
    conn->is_server = false;

    memcpy(&conn->remote_addr, res->ai_addr, res->ai_addrlen);
    conn->remote_addrlen = (socklen_t)res->ai_addrlen;
    memcpy(&conn->local_addr, &local_addr, local_len);
    conn->local_addrlen = local_len;
    conn->remote_addr_str = format_address(&conn->remote_addr, conn->remote_addrlen, arena);

    freeaddrinfo(res);

    /* Initialize synchronization */
    MUTEX_INIT(&conn->conn_mutex);
    COND_INIT(&conn->handshake_cond);
    COND_INIT(&conn->accept_stream_cond);

    /* Use provided config or defaults */
    RtQuicConfig cfg;
    if (config) {
        cfg = *config;
    } else {
        cfg.max_bidi_streams = QUIC_DEFAULT_MAX_BIDI_STREAMS;
        cfg.max_uni_streams = QUIC_DEFAULT_MAX_UNI_STREAMS;
        cfg.max_stream_window = QUIC_DEFAULT_MAX_STREAM_WINDOW;
        cfg.max_conn_window = QUIC_DEFAULT_MAX_CONN_WINDOW;
        cfg.idle_timeout_ms = QUIC_DEFAULT_IDLE_TIMEOUT_MS;
    }

    /* Setup ngtcp2 callbacks (using crypto helper callbacks) */
    ngtcp2_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    /* Crypto callbacks from ngtcp2_crypto library */
    callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
    /* Application callbacks */
    callbacks.recv_stream_data = quic_recv_stream_data_cb;
    callbacks.stream_open = quic_stream_open_cb;
    callbacks.stream_close = quic_stream_close_cb;
    callbacks.handshake_completed = quic_handshake_completed_cb;
    callbacks.rand = quic_rand_cb;
    callbacks.get_new_connection_id = quic_get_new_connection_id_cb;

    /* Setup transport params */
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = cfg.max_bidi_streams;
    params.initial_max_streams_uni = cfg.max_uni_streams;
    params.initial_max_stream_data_bidi_local = cfg.max_stream_window;
    params.initial_max_stream_data_bidi_remote = cfg.max_stream_window;
    params.initial_max_stream_data_uni = cfg.max_stream_window;
    params.initial_max_data = cfg.max_conn_window;
    if (cfg.idle_timeout_ms > 0) {
        params.max_idle_timeout = (uint64_t)cfg.idle_timeout_ms * NGTCP2_MILLISECONDS;
    }

    /* Generate connection IDs */
    ngtcp2_cid scid, dcid;
    scid.datalen = 16;
    RAND_bytes(scid.data, (int)scid.datalen);
    dcid.datalen = 16;
    RAND_bytes(dcid.data, (int)dcid.datalen);

    /* Create path */
    ngtcp2_path path;
    memset(&path, 0, sizeof(path));
    path.local.addr = (struct sockaddr *)&conn->local_addr;
    path.local.addrlen = conn->local_addrlen;
    path.remote.addr = (struct sockaddr *)&conn->remote_addr;
    path.remote.addrlen = conn->remote_addrlen;

    /* Setup ngtcp2 settings */
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = quic_timestamp();
    settings.max_tx_udp_payload_size = QUIC_MAX_PACKET_SIZE;

    /* Create ngtcp2 client connection */
    int rv = ngtcp2_conn_client_new(&conn->qconn, &dcid, &scid, &path,
                                     NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                     &params, NULL, conn);
    if (rv != 0) {
        fprintf(stderr, "QUIC: Failed to create ngtcp2 connection: %s\n", ngtcp2_strerror(rv));
        CLOSE_SOCKET(sock);
        return NULL;
    }

    conn->conn_ptr = conn->qconn;

    /* Create SSL context and connection */
    conn->ssl_ctx = create_client_ssl_ctx();
    if (!conn->ssl_ctx) {
        fprintf(stderr, "QUIC: Failed to create SSL context\n");
        ngtcp2_conn_del(conn->qconn);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    conn->ssl = create_client_ssl(conn->ssl_ctx, host, conn);
    if (!conn->ssl) {
        fprintf(stderr, "QUIC: Failed to create SSL\n");
        SSL_CTX_free(conn->ssl_ctx);
        ngtcp2_conn_del(conn->qconn);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    /* Create ngtcp2 crypto ossl context and set as native handle */
    if (ngtcp2_crypto_ossl_ctx_new(&conn->ossl_ctx, conn->ssl) != 0) {
        fprintf(stderr, "QUIC: Failed to create ossl ctx\n");
        SSL_free(conn->ssl);
        SSL_CTX_free(conn->ssl_ctx);
        ngtcp2_conn_del(conn->qconn);
        CLOSE_SOCKET(sock);
        return NULL;
    }
    ngtcp2_conn_set_tls_native_handle(conn->qconn, conn->ossl_ctx);

    /* Restore session for 0-RTT if token provided */
    if (early && token && token_len > 0) {
        const unsigned char *p = token;
        SSL_SESSION *session = d2i_SSL_SESSION(NULL, &p, (long)token_len);
        if (session) {
            SSL_set_session(conn->ssl, session);
            SSL_SESSION_free(session);
        }
    }

    /* Start I/O thread */
    conn->io_running = true;

#ifdef _WIN32
    conn->io_thread = (HANDLE)_beginthreadex(NULL, 0,
        (unsigned (__stdcall *)(void *))quic_io_thread_entry, conn, 0, NULL);
#else
    pthread_create(&conn->io_thread, NULL, quic_io_thread_entry, conn);
#endif

    /* Perform initial flush to send client hello */
    MUTEX_LOCK(&conn->conn_mutex);
    quic_flush_tx(conn);
    MUTEX_UNLOCK(&conn->conn_mutex);

    /* Wait for handshake to complete */
    MUTEX_LOCK(&conn->conn_mutex);
    while (!conn->handshake_complete && !conn->closed) {
        COND_WAIT(&conn->handshake_cond, &conn->conn_mutex);
    }
    MUTEX_UNLOCK(&conn->conn_mutex);

    if (conn->closed && !conn->handshake_complete) {
        fprintf(stderr, "QUIC: Handshake failed\n");
        conn->io_running = false;
#ifndef _WIN32
        pthread_join(conn->io_thread, NULL);
#endif
        SSL_free(conn->ssl);
        SSL_CTX_free(conn->ssl_ctx);
        ngtcp2_conn_del(conn->qconn);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    return conn;
}

/* ============================================================================
 * Connection Creation (Server-side, called from listener)
 * ============================================================================ */

static RtQuicConnection *quic_server_connection_create(RtArenaV2 *arena, socket_t sock,
                                                        SSL_CTX *ssl_ctx,
                                                        struct sockaddr_storage *remote,
                                                        socklen_t remote_len,
                                                        struct sockaddr_storage *local,
                                                        socklen_t local_len,
                                                        const uint8_t *pkt, size_t pktlen,
                                                        const ngtcp2_pkt_hd *hd,
                                                        RtQuicConfig *config) {
    /* Allocate connection from arena. rt_arena_alloc uses pinned allocations
     * that will never be moved by the compactor. */
    RtQuicConnection *conn = (RtQuicConnection *)rt_arena_alloc(arena, sizeof(RtQuicConnection));
    memset(conn, 0, sizeof(RtQuicConnection));
    conn->arena = arena;
    conn->is_server = true;

    /* Server connections share the listener's socket */
    conn->socket_fd = sock;
    memcpy(&conn->remote_addr, remote, remote_len);
    conn->remote_addrlen = remote_len;
    memcpy(&conn->local_addr, local, local_len);
    conn->local_addrlen = local_len;
    conn->remote_addr_str = format_address(&conn->remote_addr, conn->remote_addrlen, arena);

    MUTEX_INIT(&conn->conn_mutex);
    COND_INIT(&conn->handshake_cond);
    COND_INIT(&conn->accept_stream_cond);

    RtQuicConfig cfg;
    if (config) {
        cfg = *config;
    } else {
        cfg.max_bidi_streams = QUIC_DEFAULT_MAX_BIDI_STREAMS;
        cfg.max_uni_streams = QUIC_DEFAULT_MAX_UNI_STREAMS;
        cfg.max_stream_window = QUIC_DEFAULT_MAX_STREAM_WINDOW;
        cfg.max_conn_window = QUIC_DEFAULT_MAX_CONN_WINDOW;
        cfg.idle_timeout_ms = QUIC_DEFAULT_IDLE_TIMEOUT_MS;
    }

    /* Setup ngtcp2 callbacks for server (using crypto helper callbacks) */
    ngtcp2_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    /* Crypto callbacks from ngtcp2_crypto library */
    callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    /* Application callbacks */
    callbacks.recv_stream_data = quic_recv_stream_data_cb;
    callbacks.stream_open = quic_stream_open_cb;
    callbacks.stream_close = quic_stream_close_cb;
    callbacks.handshake_completed = quic_handshake_completed_cb;
    callbacks.rand = quic_rand_cb;
    callbacks.get_new_connection_id = quic_get_new_connection_id_cb;

    /* Transport params */
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = cfg.max_bidi_streams;
    params.initial_max_streams_uni = cfg.max_uni_streams;
    params.initial_max_stream_data_bidi_local = cfg.max_stream_window;
    params.initial_max_stream_data_bidi_remote = cfg.max_stream_window;
    params.initial_max_stream_data_uni = cfg.max_stream_window;
    params.initial_max_data = cfg.max_conn_window;
    if (cfg.idle_timeout_ms > 0) {
        params.max_idle_timeout = (uint64_t)cfg.idle_timeout_ms * NGTCP2_MILLISECONDS;
    }
    /* Server must set original_dcid from client's initial */
    params.original_dcid = hd->dcid;
    params.original_dcid_present = 1;

    /* Generate server CID */
    ngtcp2_cid scid;
    scid.datalen = 16;
    RAND_bytes(scid.data, (int)scid.datalen);

    /* Path */
    ngtcp2_path path;
    memset(&path, 0, sizeof(path));
    path.local.addr = (struct sockaddr *)&conn->local_addr;
    path.local.addrlen = conn->local_addrlen;
    path.remote.addr = (struct sockaddr *)&conn->remote_addr;
    path.remote.addrlen = conn->remote_addrlen;

    /* Settings */
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = quic_timestamp();
    settings.max_tx_udp_payload_size = QUIC_MAX_PACKET_SIZE;

    /* Create ngtcp2 server connection */
    int rv = ngtcp2_conn_server_new(&conn->qconn, &hd->scid, &scid, &path,
                                     NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                     &params, NULL, conn);
    if (rv != 0) {
        fprintf(stderr, "QUIC: Failed to create server connection: %s\n", ngtcp2_strerror(rv));
        return NULL;
    }

    conn->conn_ptr = conn->qconn;
    conn->ssl_ctx = ssl_ctx; /* Shared with listener */

    /* Create server SSL */
    conn->ssl = create_server_ssl(ssl_ctx, conn);
    if (!conn->ssl) {
        fprintf(stderr, "QUIC: Failed to create server SSL\n");
        ngtcp2_conn_del(conn->qconn);
        return NULL;
    }

    /* Create ngtcp2 crypto ossl context and set as native handle */
    if (ngtcp2_crypto_ossl_ctx_new(&conn->ossl_ctx, conn->ssl) != 0) {
        fprintf(stderr, "QUIC: Failed to create server ossl ctx\n");
        SSL_free(conn->ssl);
        ngtcp2_conn_del(conn->qconn);
        return NULL;
    }
    ngtcp2_conn_set_tls_native_handle(conn->qconn, conn->ossl_ctx);

    /* Process the initial packet */
    ngtcp2_pkt_info pi;
    memset(&pi, 0, sizeof(pi));
    rv = ngtcp2_conn_read_pkt(conn->qconn, &path, &pi, pkt, pktlen, quic_timestamp());
    if (rv < 0) {
        fprintf(stderr, "QUIC: Failed to process initial packet: %s\n", ngtcp2_strerror(rv));
        SSL_free(conn->ssl);
        ngtcp2_conn_del(conn->qconn);
        return NULL;
    }

    /* Server connections do NOT have their own I/O thread.
     * The listener thread handles all packet routing and timer processing.
     * Handshake completion is detected by the listener thread. */
    conn->io_running = false;

    return conn;
}

/* ============================================================================
 * Listener Thread
 * ============================================================================ */

static void *quic_listener_thread_entry(void *arg) {
    RtQuicListener *listener = (RtQuicListener *)arg;
    quic_listener_thread_func(listener);
    return NULL;
}

static void quic_server_flush_tx(RtQuicConnection *conn, socket_t sock) {
    /* Flush TX for a server connection using the listener's socket */
    uint8_t buf[QUIC_MAX_PACKET_SIZE];
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi;

    for (;;) {
        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            conn->qconn, &ps.path, &pi,
            buf, sizeof(buf),
            NULL, NGTCP2_WRITE_STREAM_FLAG_NONE,
            -1, NULL, 0, quic_timestamp());

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE) continue;
            break;
        }
        if (nwrite == 0) break;

        sendto(sock, (const char *)buf, (size_t)nwrite, 0,
               (struct sockaddr *)&conn->remote_addr, conn->remote_addrlen);
    }
}

static void quic_listener_thread_func(RtQuicListener *listener) {
    uint8_t buf[QUIC_RECV_BUF_SIZE];
    struct pollfd pfd;
    pfd.fd = listener->socket_fd;
    pfd.events = POLLIN;

    while (listener->running) {
        /* Calculate minimum timeout across all server connections */
        int timeout_ms = 50; /* Default 50ms for responsiveness */
        ngtcp2_tstamp now = quic_timestamp();

        MUTEX_LOCK(&listener->conn_list_mutex);
        for (int i = 0; i < listener->connection_count; i++) {
            RtQuicConnection *c = listener->connections[i];
            if (!c || c->closed) continue;
            MUTEX_LOCK(&c->conn_mutex);
            ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(c->qconn);
            MUTEX_UNLOCK(&c->conn_mutex);
            if (expiry <= now) {
                timeout_ms = 0;
                break;
            } else {
                int ms = (int)((expiry - now) / NGTCP2_MILLISECONDS);
                if (ms < timeout_ms) timeout_ms = ms;
            }
        }
        MUTEX_UNLOCK(&listener->conn_list_mutex);

        if (timeout_ms < 1) timeout_ms = 1;

        int ret = POLL(&pfd, 1, timeout_ms);

        if (!listener->running) break;

        if (ret > 0 && (pfd.revents & POLLIN)) {
            struct sockaddr_storage from_addr;
            socklen_t from_len = sizeof(from_addr);

            ssize_t nread = recvfrom(listener->socket_fd, (char *)buf, sizeof(buf), 0,
                                     (struct sockaddr *)&from_addr, &from_len);
            if (nread <= 0) goto handle_timers;

            /* Try to route to existing connection */
            bool found = false;
            MUTEX_LOCK(&listener->conn_list_mutex);
            for (int i = 0; i < listener->connection_count; i++) {
                RtQuicConnection *existing = listener->connections[i];
                if (!existing || existing->closed) continue;

                MUTEX_LOCK(&existing->conn_mutex);
                ngtcp2_path path;
                memset(&path, 0, sizeof(path));
                path.local.addr = (struct sockaddr *)&listener->local_addr;
                path.local.addrlen = listener->local_addrlen;
                path.remote.addr = (struct sockaddr *)&from_addr;
                path.remote.addrlen = from_len;

                ngtcp2_pkt_info pi;
                memset(&pi, 0, sizeof(pi));

                int read_rv = ngtcp2_conn_read_pkt(existing->qconn, &path, &pi,
                                                    buf, (size_t)nread, quic_timestamp());
                if (read_rv == 0) {
                    quic_server_flush_tx(existing, listener->socket_fd);
                    found = true;

                    /* Check if handshake just completed - push to accept queue */
                    if (existing->handshake_complete && !existing->io_running) {
                        existing->io_running = true; /* Mark as 'accepted' */
                        MUTEX_UNLOCK(&existing->conn_mutex);
                        MUTEX_UNLOCK(&listener->conn_list_mutex);

                        MUTEX_LOCK(&listener->accept_mutex);
                        if (listener->accept_count < QUIC_MAX_INCOMING_STREAMS) {
                            listener->accept_queue[listener->accept_tail] = existing;
                            listener->accept_tail = (listener->accept_tail + 1) % QUIC_MAX_INCOMING_STREAMS;
                            listener->accept_count++;
                            COND_SIGNAL(&listener->accept_cond);
                        }
                        MUTEX_UNLOCK(&listener->accept_mutex);
                        goto handle_timers;
                    }

                    MUTEX_UNLOCK(&existing->conn_mutex);
                    break;
                }
                MUTEX_UNLOCK(&existing->conn_mutex);
            }
            MUTEX_UNLOCK(&listener->conn_list_mutex);

            if (found) goto handle_timers;

            /* New connection - decode initial header */
            ngtcp2_pkt_hd hd;
            int rv = ngtcp2_accept(&hd, buf, (size_t)nread);
            if (rv < 0) goto handle_timers;

            /* Create new server connection (non-blocking, no I/O thread) */
            RtQuicConnection *new_conn = quic_server_connection_create(
                listener->arena, listener->socket_fd, listener->ssl_ctx,
                &from_addr, from_len,
                &listener->local_addr, listener->local_addrlen,
                buf, (size_t)nread, &hd, &listener->config);

            if (new_conn) {
                /* Flush initial server response (ServerHello etc.) */
                MUTEX_LOCK(&new_conn->conn_mutex);
                quic_server_flush_tx(new_conn, listener->socket_fd);
                MUTEX_UNLOCK(&new_conn->conn_mutex);

                /* Add to connection list for future packet routing */
                MUTEX_LOCK(&listener->conn_list_mutex);
                if (listener->connection_count < QUIC_MAX_STREAMS) {
                    listener->connections[listener->connection_count++] = new_conn;
                }
                MUTEX_UNLOCK(&listener->conn_list_mutex);

                /* If handshake already completed (unlikely for initial), push to accept */
                if (new_conn->handshake_complete) {
                    new_conn->io_running = true;
                    MUTEX_LOCK(&listener->accept_mutex);
                    if (listener->accept_count < QUIC_MAX_INCOMING_STREAMS) {
                        listener->accept_queue[listener->accept_tail] = new_conn;
                        listener->accept_tail = (listener->accept_tail + 1) % QUIC_MAX_INCOMING_STREAMS;
                        listener->accept_count++;
                        COND_SIGNAL(&listener->accept_cond);
                    }
                    MUTEX_UNLOCK(&listener->accept_mutex);
                }
            }
        }

handle_timers:
        /* Handle timer expiry for all server connections */
        now = quic_timestamp();
        MUTEX_LOCK(&listener->conn_list_mutex);
        for (int i = 0; i < listener->connection_count; i++) {
            RtQuicConnection *c = listener->connections[i];
            if (!c || c->closed) continue;
            MUTEX_LOCK(&c->conn_mutex);
            ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(c->qconn);
            if (expiry <= now) {
                int rv = ngtcp2_conn_handle_expiry(c->qconn, now);
                if (rv < 0) {
                    c->closed = true;
                    COND_BROADCAST(&c->accept_stream_cond);
                } else {
                    quic_server_flush_tx(c, listener->socket_fd);
                }
            }
            MUTEX_UNLOCK(&c->conn_mutex);
        }
        MUTEX_UNLOCK(&listener->conn_list_mutex);
    }
}

/* ============================================================================
 * QuicConfig API
 * ============================================================================ */

RtQuicConfig *sn_quic_config_defaults(RtArenaV2 *arena) {
    RtQuicConfig *config = (RtQuicConfig *)rt_arena_alloc(arena, sizeof(RtQuicConfig));
    config->max_bidi_streams = QUIC_DEFAULT_MAX_BIDI_STREAMS;
    config->max_uni_streams = QUIC_DEFAULT_MAX_UNI_STREAMS;
    config->max_stream_window = QUIC_DEFAULT_MAX_STREAM_WINDOW;
    config->max_conn_window = QUIC_DEFAULT_MAX_CONN_WINDOW;
    config->idle_timeout_ms = QUIC_DEFAULT_IDLE_TIMEOUT_MS;
    return config;
}

RtQuicConfig *sn_quic_config_set_max_bidi_streams(RtArenaV2 *arena, RtQuicConfig *config, int n) {
    (void)arena;
    config->max_bidi_streams = n;
    return config;
}

RtQuicConfig *sn_quic_config_set_max_uni_streams(RtArenaV2 *arena, RtQuicConfig *config, int n) {
    (void)arena;
    config->max_uni_streams = n;
    return config;
}

RtQuicConfig *sn_quic_config_set_max_stream_window(RtArenaV2 *arena, RtQuicConfig *config, int bytes) {
    (void)arena;
    config->max_stream_window = bytes;
    return config;
}

RtQuicConfig *sn_quic_config_set_max_conn_window(RtArenaV2 *arena, RtQuicConfig *config, int bytes) {
    (void)arena;
    config->max_conn_window = bytes;
    return config;
}

RtQuicConfig *sn_quic_config_set_idle_timeout(RtArenaV2 *arena, RtQuicConfig *config, int ms) {
    (void)arena;
    config->idle_timeout_ms = ms;
    return config;
}

/* ============================================================================
 * QuicStream API
 * ============================================================================ */

RtHandleV2 *sn_quic_stream_read(RtArenaV2 *arena, RtQuicStream *stream, long maxBytes) {
    if (!stream || maxBytes <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    MUTEX_LOCK(&stream->stream_mutex);

    /* Wait for data or FIN */
    while (stream_buf_available(&stream->recv_buf) == 0 &&
           !stream->recv_buf.fin_received && !stream->closed) {
        COND_WAIT(&stream->read_cond, &stream->stream_mutex);
    }

    size_t avail = stream_buf_available(&stream->recv_buf);
    if (avail == 0) {
        MUTEX_UNLOCK(&stream->stream_mutex);
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    size_t to_read = avail < (size_t)maxBytes ? avail : (size_t)maxBytes;
    RtHandleV2 *result = rt_array_create_generic_v2(arena, to_read, sizeof(unsigned char),
        stream->recv_buf.data + stream->recv_buf.read_pos);
    stream->recv_buf.read_pos += to_read;

    MUTEX_UNLOCK(&stream->stream_mutex);
    return result;
}

RtHandleV2 *sn_quic_stream_read_all(RtArenaV2 *arena, RtQuicStream *stream) {
    if (!stream) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    MUTEX_LOCK(&stream->stream_mutex);

    /* Wait for FIN or close */
    while (!stream->recv_buf.fin_received && !stream->closed) {
        COND_WAIT(&stream->read_cond, &stream->stream_mutex);
    }

    size_t avail = stream_buf_available(&stream->recv_buf);
    RtHandleV2 *result;
    if (avail > 0) {
        result = rt_array_create_generic_v2(arena, avail, sizeof(unsigned char),
            stream->recv_buf.data + stream->recv_buf.read_pos);
        stream->recv_buf.read_pos += avail;
    } else {
        result = rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    MUTEX_UNLOCK(&stream->stream_mutex);
    return result;
}

RtHandleV2 *sn_quic_stream_read_line(RtArenaV2 *arena, RtQuicStream *stream) {
    if (!stream) {
        return rt_arena_v2_strdup(arena, "");
    }

    MUTEX_LOCK(&stream->stream_mutex);

    /* Wait for newline, FIN, or close */
    for (;;) {
        size_t avail = stream_buf_available(&stream->recv_buf);
        uint8_t *start = stream->recv_buf.data + stream->recv_buf.read_pos;

        /* Search for newline */
        for (size_t i = 0; i < avail; i++) {
            if (start[i] == '\n') {
                /* Found newline - return line without it */
                size_t line_len = i;
                /* Strip \r if present */
                if (line_len > 0 && start[line_len - 1] == '\r') line_len--;

                char *temp = (char *)rt_arena_alloc(arena, line_len + 1);
                memcpy(temp, start, line_len);
                temp[line_len] = '\0';
                stream->recv_buf.read_pos += i + 1;
                MUTEX_UNLOCK(&stream->stream_mutex);
                return rt_arena_v2_strdup(arena, temp);
            }
        }

        if (stream->recv_buf.fin_received || stream->closed) {
            /* Return remaining data as last line */
            char *temp = (char *)rt_arena_alloc(arena, avail + 1);
            if (avail > 0) memcpy(temp, start, avail);
            temp[avail] = '\0';
            stream->recv_buf.read_pos += avail;
            MUTEX_UNLOCK(&stream->stream_mutex);
            return rt_arena_v2_strdup(arena, temp);
        }

        COND_WAIT(&stream->read_cond, &stream->stream_mutex);
    }
}

long sn_quic_stream_write(RtQuicStream *stream, unsigned char *data) {
    if (!stream || !data) return 0;
    size_t data_len = rt_v2_data_array_length(data);
    if (data_len == 0) return 0;

    RtQuicConnection *conn = (RtQuicConnection *)stream->conn_ptr;

    MUTEX_LOCK(&conn->conn_mutex);

    if (conn->closed || stream->write_closed) {
        MUTEX_UNLOCK(&conn->conn_mutex);
        return 0;
    }

    /* Write data through ngtcp2 */
    uint8_t buf[QUIC_MAX_PACKET_SIZE];
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi;

    size_t total_written = 0;
    while (total_written < data_len) {
        ngtcp2_vec v;
        v.base = (uint8_t *)data + total_written;
        v.len = data_len - total_written;

        ngtcp2_ssize ndatalen = 0;
        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            conn->qconn, &ps.path, &pi,
            buf, sizeof(buf),
            &ndatalen,
            NGTCP2_WRITE_STREAM_FLAG_NONE,
            stream->stream_id, &v, 1, quic_timestamp());

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE) {
                if (ndatalen > 0) total_written += ndatalen;
                continue;
            }
            break;
        }

        if (ndatalen > 0) total_written += ndatalen;

        if (nwrite > 0) {
            quic_send_packet(conn, buf, (size_t)nwrite);
        }

        if (nwrite == 0) break;
    }

    MUTEX_UNLOCK(&conn->conn_mutex);
    return (long)total_written;
}

void sn_quic_stream_write_line(RtQuicStream *stream, const char *text) {
    if (!stream || !text) return;

    size_t text_len = strlen(text);
    size_t total_len = text_len + 1; /* text + \n */

    uint8_t *buf = (uint8_t *)malloc(total_len);
    memcpy(buf, text, text_len);
    buf[text_len] = '\n';

    RtQuicConnection *conn = (RtQuicConnection *)stream->conn_ptr;
    MUTEX_LOCK(&conn->conn_mutex);

    if (conn->closed || stream->write_closed) {
        MUTEX_UNLOCK(&conn->conn_mutex);
        free(buf);
        return;
    }

    /* Write data through ngtcp2 */
    uint8_t pkt[QUIC_MAX_PACKET_SIZE];
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi;

    size_t total_written = 0;
    while (total_written < total_len) {
        ngtcp2_vec v;
        v.base = buf + total_written;
        v.len = total_len - total_written;

        ngtcp2_ssize ndatalen = 0;
        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            conn->qconn, &ps.path, &pi,
            pkt, sizeof(pkt),
            &ndatalen,
            NGTCP2_WRITE_STREAM_FLAG_NONE,
            stream->stream_id, &v, 1, quic_timestamp());

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE) {
                if (ndatalen > 0) total_written += ndatalen;
                continue;
            }
            break;
        }

        if (ndatalen > 0) total_written += ndatalen;

        if (nwrite > 0) {
            quic_send_packet(conn, pkt, (size_t)nwrite);
        }

        if (nwrite == 0) break;
    }

    MUTEX_UNLOCK(&conn->conn_mutex);
    free(buf);
}

int64_t sn_quic_stream_get_id(RtQuicStream *stream) {
    return stream ? stream->stream_id : -1;
}

bool sn_quic_stream_is_unidirectional(RtQuicStream *stream) {
    return stream ? stream->is_uni : false;
}

void sn_quic_stream_close(RtQuicStream *stream) {
    if (!stream || stream->closed) return;

    RtQuicConnection *conn = (RtQuicConnection *)stream->conn_ptr;

    MUTEX_LOCK(&conn->conn_mutex);

    if (!conn->closed) {
        /* Send FIN on the stream */
        uint8_t buf[QUIC_MAX_PACKET_SIZE];
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi;
        ngtcp2_ssize ndatalen;

        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            conn->qconn, &ps.path, &pi,
            buf, sizeof(buf),
            &ndatalen,
            NGTCP2_WRITE_STREAM_FLAG_FIN,
            stream->stream_id, NULL, 0, quic_timestamp());

        if (nwrite > 0) {
            quic_send_packet(conn, buf, (size_t)nwrite);
        }
    }

    MUTEX_UNLOCK(&conn->conn_mutex);

    MUTEX_LOCK(&stream->stream_mutex);
    stream->write_closed = true;
    stream->closed = true;
    COND_BROADCAST(&stream->read_cond);
    MUTEX_UNLOCK(&stream->stream_mutex);
}

/* ============================================================================
 * QuicConnection API
 * ============================================================================ */

RtQuicConnection *sn_quic_connection_connect(RtArenaV2 *arena, const char *address) {
    return quic_connection_create(arena, address, NULL, false, NULL, 0);
}

RtQuicConnection *sn_quic_connection_connect_with(RtArenaV2 *arena, const char *address,
                                                    RtQuicConfig *config) {
    return quic_connection_create(arena, address, config, false, NULL, 0);
}

RtQuicConnection *sn_quic_connection_connect_early(RtArenaV2 *arena, const char *address,
                                                     unsigned char *token) {
    if (!token || rt_v2_data_array_length(token) == 0) {
        return quic_connection_create(arena, address, NULL, false, NULL, 0);
    }
    return quic_connection_create(arena, address, NULL, true,
                                   (const uint8_t *)token, rt_v2_data_array_length(token));
}

RtQuicStream *sn_quic_connection_open_stream(RtArenaV2 *arena, RtQuicConnection *conn) {
    if (!conn || conn->closed) return NULL;
    (void)arena;

    MUTEX_LOCK(&conn->conn_mutex);

    int64_t stream_id;
    int rv = ngtcp2_conn_open_bidi_stream(conn->qconn, &stream_id, NULL);
    if (rv != 0) {
        MUTEX_UNLOCK(&conn->conn_mutex);
        fprintf(stderr, "QUIC: Failed to open bidi stream: %s\n", ngtcp2_strerror(rv));
        return NULL;
    }

    RtQuicStream *stream = quic_find_or_create_stream(conn, stream_id);
    MUTEX_UNLOCK(&conn->conn_mutex);
    return stream;
}

RtQuicStream *sn_quic_connection_open_uni_stream(RtArenaV2 *arena, RtQuicConnection *conn) {
    if (!conn || conn->closed) return NULL;
    (void)arena;

    MUTEX_LOCK(&conn->conn_mutex);

    int64_t stream_id;
    int rv = ngtcp2_conn_open_uni_stream(conn->qconn, &stream_id, NULL);
    if (rv != 0) {
        MUTEX_UNLOCK(&conn->conn_mutex);
        fprintf(stderr, "QUIC: Failed to open uni stream: %s\n", ngtcp2_strerror(rv));
        return NULL;
    }

    RtQuicStream *stream = quic_find_or_create_stream(conn, stream_id);
    if (stream) stream->is_uni = true;
    MUTEX_UNLOCK(&conn->conn_mutex);
    return stream;
}

RtQuicStream *sn_quic_connection_accept_stream(RtArenaV2 *arena, RtQuicConnection *conn) {
    if (!conn) return NULL;
    (void)arena;

    MUTEX_LOCK(&conn->conn_mutex);

    while (conn->incoming_count == 0 && !conn->closed) {
        COND_WAIT(&conn->accept_stream_cond, &conn->conn_mutex);
    }

    if (conn->closed || conn->incoming_count == 0) {
        MUTEX_UNLOCK(&conn->conn_mutex);
        return NULL;
    }

    int64_t stream_id = conn->incoming_streams[conn->incoming_head];
    conn->incoming_head = (conn->incoming_head + 1) % QUIC_MAX_INCOMING_STREAMS;
    conn->incoming_count--;

    RtQuicStream *stream = quic_find_or_create_stream(conn, stream_id);
    MUTEX_UNLOCK(&conn->conn_mutex);
    return stream;
}

RtHandleV2 *sn_quic_connection_resumption_token(RtArenaV2 *arena, RtQuicConnection *conn) {
    if (!conn || !conn->resumption_token || conn->resumption_token_len == 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    return rt_array_create_generic_v2(arena, conn->resumption_token_len, sizeof(unsigned char), conn->resumption_token);
}

void sn_quic_connection_migrate(RtQuicConnection *conn, const char *newLocalAddress) {
    if (!conn || conn->closed || !newLocalAddress) return;

    char host[256], port[16];
    if (parse_address(newLocalAddress, host, sizeof(host), port, sizeof(port)) != 0) {
        fprintf(stderr, "QUIC: Invalid migration address: %s\n", newLocalAddress);
        return;
    }

    /* Resolve new local address */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(host[0] ? host : NULL, port, &hints, &res) != 0) return;

    /* Create new socket */
    socket_t new_sock = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (new_sock == INVALID_SOCKET_VAL) {
        freeaddrinfo(res);
        return;
    }

    if (bind(new_sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
        CLOSE_SOCKET(new_sock);
        freeaddrinfo(res);
        return;
    }

    /* Connect to remote */
    if (connect(new_sock, (struct sockaddr *)&conn->remote_addr, conn->remote_addrlen) != 0) {
        CLOSE_SOCKET(new_sock);
        freeaddrinfo(res);
        return;
    }

    set_socket_nonblocking(new_sock);

    /* Get actual bound address */
    struct sockaddr_storage new_local;
    socklen_t new_local_len = sizeof(new_local);
    getsockname(new_sock, (struct sockaddr *)&new_local, &new_local_len);

    MUTEX_LOCK(&conn->conn_mutex);

    /* Tell ngtcp2 about migration */
    ngtcp2_path new_path;
    memset(&new_path, 0, sizeof(new_path));
    new_path.local.addr = (struct sockaddr *)&new_local;
    new_path.local.addrlen = new_local_len;
    new_path.remote.addr = (struct sockaddr *)&conn->remote_addr;
    new_path.remote.addrlen = conn->remote_addrlen;

    ngtcp2_addr addr;
    addr.addr = (struct sockaddr *)&new_local;
    addr.addrlen = new_local_len;

    int rv = ngtcp2_conn_initiate_immediate_migration(conn->qconn, &new_path, quic_timestamp());
    if (rv == 0) {
        /* Swap sockets */
        socket_t old_sock = conn->socket_fd;
        conn->socket_fd = new_sock;
        memcpy(&conn->local_addr, &new_local, new_local_len);
        conn->local_addrlen = new_local_len;
        CLOSE_SOCKET(old_sock);

        quic_flush_tx(conn);
    } else {
        CLOSE_SOCKET(new_sock);
    }

    MUTEX_UNLOCK(&conn->conn_mutex);
    freeaddrinfo(res);
}

RtHandleV2 *sn_quic_connection_remote_address(RtArenaV2 *arena, RtQuicConnection *conn) {
    if (!conn || !conn->remote_addr_str) {
        return rt_arena_v2_strdup(arena, "");
    }
    return rt_arena_v2_strdup(arena, conn->remote_addr_str);
}

void sn_quic_connection_close(RtQuicConnection *conn) {
    if (!conn || conn->closed) return;

    MUTEX_LOCK(&conn->conn_mutex);
    conn->closed = true;

    if (conn->qconn) {
        /* Send connection close frame */
        uint8_t buf[QUIC_MAX_PACKET_SIZE];
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi;
        ngtcp2_ccerr ccerr;
        ngtcp2_ccerr_default(&ccerr);

        ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
            conn->qconn, &ps.path, &pi,
            buf, sizeof(buf), &ccerr, quic_timestamp());

        if (nwrite > 0) {
            quic_send_packet(conn, buf, (size_t)nwrite);
        }
    }

    MUTEX_UNLOCK(&conn->conn_mutex);

    /* Signal all waiting threads */
    COND_BROADCAST(&conn->handshake_cond);
    COND_BROADCAST(&conn->accept_stream_cond);

    /* Signal all streams */
    for (int i = 0; i < conn->stream_count; i++) {
        if (conn->streams[i]) {
            MUTEX_LOCK(&conn->streams[i]->stream_mutex);
            conn->streams[i]->closed = true;
            COND_BROADCAST(&conn->streams[i]->read_cond);
            MUTEX_UNLOCK(&conn->streams[i]->stream_mutex);
        }
    }

    /* For server connections, we only mark closed and signal waiters.
     * The listener thread may still be using qconn, SSL, and streams,
     * so cleanup is deferred to sn_quic_listener_close() after the
     * listener thread is joined. */
    if (conn->is_server) {
        return;
    }

    /* Stop and join I/O thread (client connections only) */
    if (conn->io_running) {
        conn->io_running = false;
#ifdef _WIN32
        WaitForSingleObject(conn->io_thread, 5000);
        CloseHandle(conn->io_thread);
#else
        pthread_join(conn->io_thread, NULL);
#endif
    }

    /* Cleanup (client connections only) */
    if (conn->ssl) {
        SSL_set_app_data(conn->ssl, NULL);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->ossl_ctx) {
        ngtcp2_crypto_ossl_ctx_del(conn->ossl_ctx);
        conn->ossl_ctx = NULL;
    }
    if (conn->ssl_ctx) {
        SSL_CTX_free(conn->ssl_ctx);
        conn->ssl_ctx = NULL;
    }
    if (conn->qconn) {
        ngtcp2_conn_del(conn->qconn);
        conn->qconn = NULL;
    }
    if (conn->socket_fd != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(conn->socket_fd);
        conn->socket_fd = INVALID_SOCKET_VAL;
    }

    /* Free streams */
    for (int i = 0; i < conn->stream_count; i++) {
        quic_stream_free(conn->streams[i]);
        conn->streams[i] = NULL;
    }

    /* Free resumption token */
    if (conn->resumption_token) {
        free(conn->resumption_token);
        conn->resumption_token = NULL;
    }

    MUTEX_DESTROY(&conn->conn_mutex);
    COND_DESTROY(&conn->handshake_cond);
    COND_DESTROY(&conn->accept_stream_cond);
    /* Memory is arena-allocated, no need to free */
}

/* ============================================================================
 * QuicListener API
 * ============================================================================ */

static RtQuicListener *quic_listener_create(RtArenaV2 *arena, const char *address,
                                             const char *cert_file, const char *key_file,
                                             RtQuicConfig *config) {
    ensure_winsock_initialized();

    char host[256], port[16];
    if (parse_address(address, host, sizeof(host), port, sizeof(port)) != 0) {
        fprintf(stderr, "QUIC: Invalid bind address: %s\n", address);
        return NULL;
    }

    /* Create SSL context */
    SSL_CTX *ssl_ctx = create_server_ssl_ctx(cert_file, key_file);
    if (!ssl_ctx) return NULL;

    /* Resolve bind address */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(host[0] ? host : NULL, port, &hints, &res) != 0) {
        fprintf(stderr, "QUIC: Failed to resolve bind address\n");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    /* Create and bind socket */
    socket_t sock = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET_VAL) {
        freeaddrinfo(res);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval, sizeof(optval));
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&optval, sizeof(optval));
#endif

    if (bind(sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
        fprintf(stderr, "QUIC: Failed to bind: %s:%s\n", host, port);
        CLOSE_SOCKET(sock);
        freeaddrinfo(res);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    freeaddrinfo(res);
    set_socket_nonblocking(sock);

    /* Get actual bound port */
    struct sockaddr_storage bound_addr;
    socklen_t bound_len = sizeof(bound_addr);
    getsockname(sock, (struct sockaddr *)&bound_addr, &bound_len);

    int bound_port;
    if (bound_addr.ss_family == AF_INET) {
        bound_port = ntohs(((struct sockaddr_in *)&bound_addr)->sin_port);
    } else {
        bound_port = ntohs(((struct sockaddr_in6 *)&bound_addr)->sin6_port);
    }

    /* Create listener struct from arena. rt_arena_alloc uses pinned allocations
     * that will never be moved by the compactor. */
    RtQuicListener *listener = (RtQuicListener *)rt_arena_alloc(arena, sizeof(RtQuicListener));
    memset(listener, 0, sizeof(RtQuicListener));
    listener->arena = arena;
    listener->socket_fd = sock;
    listener->bound_port = bound_port;
    listener->ssl_ctx = ssl_ctx;
    listener->running = true;

    memcpy(&listener->local_addr, &bound_addr, bound_len);
    listener->local_addrlen = bound_len;

    if (config) {
        listener->config = *config;
    } else {
        listener->config.max_bidi_streams = QUIC_DEFAULT_MAX_BIDI_STREAMS;
        listener->config.max_uni_streams = QUIC_DEFAULT_MAX_UNI_STREAMS;
        listener->config.max_stream_window = QUIC_DEFAULT_MAX_STREAM_WINDOW;
        listener->config.max_conn_window = QUIC_DEFAULT_MAX_CONN_WINDOW;
        listener->config.idle_timeout_ms = QUIC_DEFAULT_IDLE_TIMEOUT_MS;
    }

    MUTEX_INIT(&listener->accept_mutex);
    COND_INIT(&listener->accept_cond);
    MUTEX_INIT(&listener->conn_list_mutex);

    /* Start listener thread */
#ifdef _WIN32
    listener->listen_thread = (HANDLE)_beginthreadex(NULL, 0,
        (unsigned (__stdcall *)(void *))quic_listener_thread_entry, listener, 0, NULL);
#else
    pthread_create(&listener->listen_thread, NULL, quic_listener_thread_entry, listener);
#endif

    return listener;
}

RtQuicListener *sn_quic_listener_bind(RtArenaV2 *arena, const char *address,
                                        const char *certFile, const char *keyFile) {
    return quic_listener_create(arena, address, certFile, keyFile, NULL);
}

RtQuicListener *sn_quic_listener_bind_with(RtArenaV2 *arena, const char *address,
                                             const char *certFile, const char *keyFile,
                                             RtQuicConfig *config) {
    return quic_listener_create(arena, address, certFile, keyFile, config);
}

RtQuicConnection *sn_quic_listener_accept(RtArenaV2 *arena, RtQuicListener *listener) {
    if (!listener) return NULL;
    (void)arena;

    MUTEX_LOCK(&listener->accept_mutex);

    while (listener->accept_count == 0 && listener->running) {
        COND_WAIT(&listener->accept_cond, &listener->accept_mutex);
    }

    if (!listener->running || listener->accept_count == 0) {
        MUTEX_UNLOCK(&listener->accept_mutex);
        return NULL;
    }

    RtQuicConnection *conn = listener->accept_queue[listener->accept_head];
    listener->accept_head = (listener->accept_head + 1) % QUIC_MAX_INCOMING_STREAMS;
    listener->accept_count--;

    MUTEX_UNLOCK(&listener->accept_mutex);
    return conn;
}

int sn_quic_listener_get_port(RtQuicListener *listener) {
    return listener ? listener->bound_port : 0;
}

void sn_quic_listener_close(RtQuicListener *listener) {
    if (!listener || !listener->running) return;

    listener->running = false;

    /* Signal accept waiters */
    MUTEX_LOCK(&listener->accept_mutex);
    COND_BROADCAST(&listener->accept_cond);
    MUTEX_UNLOCK(&listener->accept_mutex);

    /* Wait for listener thread */
#ifdef _WIN32
    WaitForSingleObject(listener->listen_thread, 5000);
    CloseHandle(listener->listen_thread);
#else
    pthread_join(listener->listen_thread, NULL);
#endif

    /* Mark all server connections as closed (sn_quic_connection_close for
     * server connections just sets closed=true and signals waiters). */
    MUTEX_LOCK(&listener->conn_list_mutex);
    for (int i = 0; i < listener->connection_count; i++) {
        if (listener->connections[i] && !listener->connections[i]->closed) {
            sn_quic_connection_close(listener->connections[i]);
        }
    }
    MUTEX_UNLOCK(&listener->conn_list_mutex);

    /* Now that listener thread is stopped, do full cleanup for all server
     * connections. This was deferred because the listener thread was using
     * these resources (qconn, SSL, streams). */
    for (int i = 0; i < listener->connection_count; i++) {
        RtQuicConnection *conn = listener->connections[i];
        if (!conn) continue;

        /* Cleanup SSL */
        if (conn->ssl) {
            SSL_set_app_data(conn->ssl, NULL);
            SSL_free(conn->ssl);
            conn->ssl = NULL;
        }
        if (conn->ossl_ctx) {
            ngtcp2_crypto_ossl_ctx_del(conn->ossl_ctx);
            conn->ossl_ctx = NULL;
        }
        /* Server connections share listener's ssl_ctx, don't free it here */

        /* Delete ngtcp2 connection */
        if (conn->qconn) {
            ngtcp2_conn_del(conn->qconn);
            conn->qconn = NULL;
        }

        /* Free streams */
        for (int j = 0; j < conn->stream_count; j++) {
            quic_stream_free(conn->streams[j]);
            conn->streams[j] = NULL;
        }

        /* Free resumption token */
        if (conn->resumption_token) {
            free(conn->resumption_token);
            conn->resumption_token = NULL;
        }

        /* Destroy mutex/cond */
        MUTEX_DESTROY(&conn->conn_mutex);
        COND_DESTROY(&conn->handshake_cond);
        COND_DESTROY(&conn->accept_stream_cond);
        /* Memory is arena-allocated, no need to free */
    }

    /* Cleanup */
    if (listener->ssl_ctx) {
        SSL_CTX_free(listener->ssl_ctx);
        listener->ssl_ctx = NULL;
    }
    if (listener->socket_fd != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(listener->socket_fd);
        listener->socket_fd = INVALID_SOCKET_VAL;
    }

    MUTEX_DESTROY(&listener->accept_mutex);
    COND_DESTROY(&listener->accept_cond);
    MUTEX_DESTROY(&listener->conn_list_mutex);
    /* Memory is arena-allocated, no need to free */
}
