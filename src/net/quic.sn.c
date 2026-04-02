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
 *   - Refcounted Sindarin structs via __sn__X__new() + internal state registries
 *   - Blocking API: connect/read/accept all block until complete
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* No arena runtime — minimal runtime */

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
#define QUIC_PKT_RING_SIZE             256  /* per-connection packet ring for server I/O */
#define QUIC_RETRY_SECRET_LEN          32   /* static secret for Retry token generation */
#define QUIC_RETRY_TOKEN_TIMEOUT       (10ULL * NGTCP2_SECONDS) /* 10s token validity */
#define QUIC_ALPN "\x02hq"   /* HTTP/0.9 over QUIC (h3 would be "\x02h3") */

/* Static secret for Retry token generation/verification (per-process) */
static uint8_t g_retry_secret[QUIC_RETRY_SECRET_LEN];
static int g_retry_secret_initialized = 0;

static void ensure_retry_secret(void) {
    if (!g_retry_secret_initialized) {
        RAND_bytes(g_retry_secret, QUIC_RETRY_SECRET_LEN);
        g_retry_secret_initialized = 1;
    }
}

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

/* QuicConfig: all fields match Sindarin — use compiler-generated typedef */
typedef __sn__QuicConfig RtQuicConfig;

/* Internal buffer for stream data */
typedef struct RtQuicStreamBuf {
    uint8_t *data;
    size_t capacity;
    size_t read_pos;
    size_t write_pos;
    bool fin_received;
} RtQuicStreamBuf;

/* QuicStream: Sindarin exposes stream_id and conn_ptr only */
typedef __sn__QuicStream RtQuicStream;

typedef struct QuicStreamInternal {
    RtQuicStreamBuf recv_buf;
    mutex_t stream_mutex;
    cond_t read_cond;
    bool closed;
    bool write_closed;
    bool is_uni;
} QuicStreamInternal;

/* Routed packet: listener pushes to per-connection ring, I/O thread drains */
typedef struct {
    uint8_t data[QUIC_MAX_PACKET_SIZE];
    size_t len;
    struct sockaddr_storage from_addr;
    socklen_t from_len;
} QuicPacket;

/* QuicConnection: Sindarin exposes conn_ptr and socket_fd only */
typedef __sn__QuicConnection RtQuicConnection;

typedef struct QuicConnectionInternal {
    ngtcp2_conn *qconn;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
    ngtcp2_crypto_conn_ref conn_ref;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;
    char *remote_addr_str;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    RtQuicStream *streams[QUIC_MAX_STREAMS];
    int stream_count;
    int64_t incoming_streams[QUIC_MAX_INCOMING_STREAMS];
    int incoming_head;
    int incoming_tail;
    int incoming_count;
    cond_t accept_stream_cond;
    mutex_t conn_mutex;       /* protects incoming_streams queue + accept_stream_cond */
    cond_t handshake_cond;
    bool handshake_complete;
    bool closed;
    bool is_server;
    sn_thread_t io_thread;
    bool io_running;
    uint8_t *resumption_token;
    size_t resumption_token_len;
    /* Server connection: packet ring (listener → I/O thread).
     * Only pkt_ring_mutex is needed — never held during ngtcp2 calls. */
    QuicPacket *pkt_ring;
    int pkt_ring_head;        /* written by listener */
    int pkt_ring_tail;        /* read by I/O thread */
    mutex_t pkt_ring_mutex;
    cond_t pkt_ring_cond;     /* wakes I/O thread on packet arrival or write */
    socket_t listener_sock;   /* listener's socket for sendto */
    /* Cached SCIDs for lock-free routing by listener thread.
     * Set at connection creation, updated by I/O thread on CID rotation. */
    ngtcp2_cid cached_scids[8];
    int cached_scid_count;
} QuicConnectionInternal;

/* QuicListener: Sindarin exposes socket_fd and bound_port only */
typedef __sn__QuicListener RtQuicListener;

typedef struct QuicListenerInternal {
    SSL_CTX *ssl_ctx;
    RtQuicConnection *accept_queue_conns[QUIC_MAX_INCOMING_STREAMS];
    int accept_head;
    int accept_tail;
    int accept_count;
    mutex_t accept_mutex;
    cond_t accept_cond;
    RtQuicConnection *connections[QUIC_MAX_STREAMS];
    int connection_count;
    mutex_t conn_list_mutex;
    sn_thread_t listen_thread;
    bool running;
    RtQuicConfig config;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
} QuicListenerInternal;

/* ============================================================================
 * Internal State Registries
 * ============================================================================
 * Maps Sindarin-visible struct pointers to their internal state.
 * Same pattern as TcpStreamInternal in tcp.sn.c.
 * ============================================================================ */

/* Stream internal registry */
typedef struct { RtQuicStream *key; QuicStreamInternal *val; } QStreamEntry;
static QStreamEntry g_stream_reg[512];
static int g_stream_reg_count = 0;

static QuicStreamInternal *stream_internal(RtQuicStream *s) {
    if (!s) return NULL;
    /* Primary path: use the embedded internal_ptr if set.
     * This is immune to pointer reuse after free — each stream
     * carries a direct pointer to its own internal state. */
    if (s->internal_ptr) {
        return (QuicStreamInternal *)(uintptr_t)s->internal_ptr;
    }
    /* Legacy fallback: registry lookup by exact pointer match */
    for (int i = 0; i < g_stream_reg_count; i++)
        if (g_stream_reg[i].key == s) return g_stream_reg[i].val;
    /* Last resort: match by (conn_ptr, stream_id) for struct copies */
    for (int i = 0; i < g_stream_reg_count; i++) {
        RtQuicStream *candidate = g_stream_reg[i].key;
        if (candidate->conn_ptr == s->conn_ptr &&
            candidate->stream_id == s->stream_id)
            return g_stream_reg[i].val;
    }
    return NULL;
}
static void stream_register(RtQuicStream *s, QuicStreamInternal *si) {
    /* Replace stale entry at the same pointer address (memory reuse after free) */
    for (int i = 0; i < g_stream_reg_count; i++) {
        if (g_stream_reg[i].key == s) {
            g_stream_reg[i].val = si;
            return;
        }
    }
    g_stream_reg[g_stream_reg_count++] = (QStreamEntry){s, si};
}
static void stream_unregister(RtQuicStream *s) {
    for (int i = 0; i < g_stream_reg_count; i++) {
        if (g_stream_reg[i].key == s) {
            g_stream_reg[i] = g_stream_reg[--g_stream_reg_count];
            return;
        }
    }
}

/* Connection internal registry */
typedef struct { RtQuicConnection *key; QuicConnectionInternal *val; } QConnEntry;
static QConnEntry g_conn_reg[128];
static int g_conn_reg_count = 0;

static QuicConnectionInternal *conn_internal(RtQuicConnection *c) {
    for (int i = 0; i < g_conn_reg_count; i++)
        if (g_conn_reg[i].key == c) return g_conn_reg[i].val;
    return NULL;
}
static void conn_register(RtQuicConnection *c, QuicConnectionInternal *ci) {
    g_conn_reg[g_conn_reg_count++] = (QConnEntry){c, ci};
}
static void conn_unregister(RtQuicConnection *c) {
    for (int i = 0; i < g_conn_reg_count; i++) {
        if (g_conn_reg[i].key == c) {
            g_conn_reg[i] = g_conn_reg[--g_conn_reg_count];
            return;
        }
    }
}

/* Listener internal registry */
typedef struct { RtQuicListener *key; QuicListenerInternal *val; } QListenerEntry;
static QListenerEntry g_listener_reg[16];
static int g_listener_reg_count = 0;

static QuicListenerInternal *listener_internal(RtQuicListener *l) {
    for (int i = 0; i < g_listener_reg_count; i++)
        if (g_listener_reg[i].key == l) return g_listener_reg[i].val;
    return NULL;
}
static void listener_register(RtQuicListener *l, QuicListenerInternal *li) {
    g_listener_reg[g_listener_reg_count++] = (QListenerEntry){l, li};
}
static void listener_unregister(RtQuicListener *l) {
    for (int i = 0; i < g_listener_reg_count; i++) {
        if (g_listener_reg[i].key == l) {
            g_listener_reg[i] = g_listener_reg[--g_listener_reg_count];
            return;
        }
    }
}

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

static void quic_io_thread_func(RtQuicConnection *conn);
static void quic_server_io_thread_func(RtQuicConnection *conn);
static void quic_listener_thread_func(RtQuicListener *listener);
static int quic_flush_tx(RtQuicConnection *conn);
static void quic_server_flush_tx(RtQuicConnection *conn, socket_t sock);
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
    QuicConnectionInternal *ci = conn_internal(conn);
    if (ci->is_server) {
        return sendto(conn->socket_fd, (const char *)buf, len, 0,
                      (struct sockaddr *)&ci->remote_addr, ci->remote_addrlen);
    } else {
        return send(conn->socket_fd, (const char *)buf, len, 0);
    }
}

static int parse_address(char *address, char *host, size_t hostlen, char *port, size_t portlen) {
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

static char *format_address(struct sockaddr_storage *addr, socklen_t addrlen) {
    char host[NI_MAXHOST];
    char port[NI_MAXSERV];
    (void)addrlen;
    if (getnameinfo((struct sockaddr *)addr, addrlen, host, sizeof(host),
                    port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        return NULL;
    }
    size_t len = strlen(host) + strlen(port) + 2;
    char *result = (char *)malloc(len);
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
    QuicConnectionInternal *qci = conn_internal(qc);

    RtQuicStream *stream = quic_find_or_create_stream(qc, stream_id);
    if (!stream) return 0;

    QuicStreamInternal *si = stream_internal(stream);
    MUTEX_LOCK(&si->stream_mutex);
    if (datalen > 0) {
        stream_buf_append(&si->recv_buf, data, datalen);
    }
    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
        si->recv_buf.fin_received = true;
    }
    COND_SIGNAL(&si->read_cond);
    MUTEX_UNLOCK(&si->stream_mutex);

    ngtcp2_conn_extend_max_stream_offset(qci->qconn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(qci->qconn, datalen);

    return 0;
}

static int quic_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    (void)conn;
    RtQuicConnection *qc = (RtQuicConnection *)user_data;
    QuicConnectionInternal *qci = conn_internal(qc);

    /* Create stream entry */
    quic_find_or_create_stream(qc, stream_id);

    /* Add to incoming queue */
    if (qci->incoming_count < QUIC_MAX_INCOMING_STREAMS) {
        qci->incoming_streams[qci->incoming_tail] = stream_id;
        qci->incoming_tail = (qci->incoming_tail + 1) % QUIC_MAX_INCOMING_STREAMS;
        qci->incoming_count++;
        COND_SIGNAL(&qci->accept_stream_cond);
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
    QuicConnectionInternal *qci = conn_internal(qc);

    for (int i = 0; i < qci->stream_count; i++) {
        if (qci->streams[i] && qci->streams[i]->stream_id == stream_id) {
            QuicStreamInternal *si = stream_internal(qci->streams[i]);
            MUTEX_LOCK(&si->stream_mutex);
            si->closed = true;
            si->recv_buf.fin_received = true;
            COND_SIGNAL(&si->read_cond);
            MUTEX_UNLOCK(&si->stream_mutex);
            break;
        }
    }

    return 0;
}

static int quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    RtQuicConnection *qc = (RtQuicConnection *)user_data;
    QuicConnectionInternal *qci = conn_internal(qc);

    qci->handshake_complete = true;
    COND_SIGNAL(&qci->handshake_cond);

    /* Extract session ticket for 0-RTT */
    SSL_SESSION *session = SSL_get1_session(qci->ssl);
    if (session) {
        unsigned char *buf = NULL;
        size_t len = 0;
        /* Serialize session for later use */
        len = i2d_SSL_SESSION(session, &buf);
        if (buf && len > 0) {
            qci->resumption_token = (uint8_t *)malloc(len);
            if (qci->resumption_token) {
                memcpy(qci->resumption_token, buf, len);
                qci->resumption_token_len = len;
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
    QuicConnectionInternal *ci = conn_internal(conn);
    /* Search existing streams */
    for (int i = 0; i < ci->stream_count; i++) {
        if (ci->streams[i] && ci->streams[i]->stream_id == stream_id) {
            return ci->streams[i];
        }
    }

    /* Create new stream */
    if (ci->stream_count >= QUIC_MAX_STREAMS) return NULL;

    RtQuicStream *stream = __sn__QuicStream__new();
    stream->stream_id = stream_id;
    stream->conn_ptr = (long long)(uintptr_t)conn;

    QuicStreamInternal *si = (QuicStreamInternal *)calloc(1, sizeof(QuicStreamInternal));
    stream->internal_ptr = (long long)(uintptr_t)si;
    stream_register(stream, si);
    stream_buf_init(&si->recv_buf);
    MUTEX_INIT(&si->stream_mutex);
    COND_INIT(&si->read_cond);
    si->closed = false;
    si->write_closed = false;
    /* Unidirectional streams: bit 1 of stream_id indicates uni */
    si->is_uni = (stream_id & 0x2) != 0;

    ci->streams[ci->stream_count++] = stream;
    return stream;
}

static void quic_stream_free(RtQuicStream *stream) {
    if (!stream) return;

    /* Null the stream pointer in the owning connection's stream array
     * to prevent use-after-free in quic_find_or_create_stream */
    RtQuicConnection *conn = (RtQuicConnection *)(uintptr_t)stream->conn_ptr;
    if (conn) {
        QuicConnectionInternal *ci = conn_internal(conn);
        if (ci) {
            for (int i = 0; i < ci->stream_count; i++) {
                if (ci->streams[i] == stream) {
                    ci->streams[i] = NULL;
                    break;
                }
            }
        }
    }

    QuicStreamInternal *si = stream_internal(stream);
    if (si) {
        stream_buf_destroy(&si->recv_buf);
        MUTEX_DESTROY(&si->stream_mutex);
        COND_DESTROY(&si->read_cond);
        free(si);
    }
    stream_unregister(stream);
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
    QuicConnectionInternal *ci = conn_internal(qc);
    return ci->qconn;
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
    QuicConnectionInternal *ci = conn_internal(conn);
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return NULL;

    /* Set hostname for SNI */
    SSL_set_tlsext_host_name(ssl, hostname);

    /* Set ALPN */
    SSL_set_alpn_protos(ssl, (const unsigned char *)QUIC_ALPN, sizeof(QUIC_ALPN) - 1);

    /* Configure SSL for ngtcp2 QUIC client */
    ngtcp2_crypto_ossl_configure_client_session(ssl);

    /* Set conn_ref as app data for ngtcp2 crypto callbacks */
    ci->conn_ref.get_conn = quic_get_conn_cb;
    ci->conn_ref.user_data = conn;
    SSL_set_app_data(ssl, &ci->conn_ref);

    SSL_set_connect_state(ssl);

    return ssl;
}

static SSL *create_server_ssl(SSL_CTX *ctx, RtQuicConnection *conn) {
    QuicConnectionInternal *ci = conn_internal(conn);
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return NULL;

    /* Configure SSL for ngtcp2 QUIC server */
    ngtcp2_crypto_ossl_configure_server_session(ssl);

    /* Set conn_ref as app data for ngtcp2 crypto callbacks */
    ci->conn_ref.get_conn = quic_get_conn_cb;
    ci->conn_ref.user_data = conn;
    SSL_set_app_data(ssl, &ci->conn_ref);

    SSL_set_accept_state(ssl);

    return ssl;
}

/* ============================================================================
 * I/O Thread (per connection)
 * ============================================================================ */

static int quic_flush_tx(RtQuicConnection *conn) {
    QuicConnectionInternal *ci = conn_internal(conn);
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
            ci->qconn, &ps.path, &pi,
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
    QuicConnectionInternal *ci = conn_internal(conn);
    uint8_t buf[QUIC_RECV_BUF_SIZE];
    struct pollfd pfd;
    pfd.fd = conn->socket_fd;
    pfd.events = POLLIN;

    while (ci->io_running && !ci->closed) {
        /* Calculate timeout from ngtcp2 expiry */
        ngtcp2_tstamp now = quic_timestamp();
        ngtcp2_tstamp expiry;

        MUTEX_LOCK(&ci->conn_mutex);
        expiry = ngtcp2_conn_get_expiry(ci->qconn);
        MUTEX_UNLOCK(&ci->conn_mutex);

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

        MUTEX_LOCK(&ci->conn_mutex);

        if (ci->closed) {
            MUTEX_UNLOCK(&ci->conn_mutex);
            break;
        }

        if (ret > 0 && (pfd.revents & POLLIN)) {
            /* Read incoming packet */
            struct sockaddr_storage from_addr;
            socklen_t from_len = sizeof(from_addr);

            ssize_t nread = recvfrom(conn->socket_fd, (char *)buf, sizeof(buf), 0,
                                     (struct sockaddr *)&from_addr, &from_len);

            if (nread > 0) {
                if (!ci->handshake_complete) {
                    fprintf(stderr, "QUIC: client I/O received %zd bytes (handshake in progress)\n", nread);
                    fflush(stderr);
                }
                ngtcp2_path path;
                memset(&path, 0, sizeof(path));
                path.local.addr = (struct sockaddr *)&ci->local_addr;
                path.local.addrlen = ci->local_addrlen;
                path.remote.addr = (struct sockaddr *)&from_addr;
                path.remote.addrlen = from_len;

                ngtcp2_pkt_info pi;
                memset(&pi, 0, sizeof(pi));

                int incoming_before = ci->incoming_count;
                int rv = ngtcp2_conn_read_pkt(ci->qconn, &path, &pi,
                                               buf, (size_t)nread, quic_timestamp());
                if (ci->incoming_count > incoming_before) {
                }
                if (rv < 0) {
                    if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
                        ci->closed = true;
                        COND_BROADCAST(&ci->handshake_cond);
                        COND_BROADCAST(&ci->accept_stream_cond);
                        MUTEX_UNLOCK(&ci->conn_mutex);
                        break;
                    }
                }
            }
        }

        /* Handle timer expiry */
        now = quic_timestamp();
        expiry = ngtcp2_conn_get_expiry(ci->qconn);
        if (expiry <= now) {
            int rv = ngtcp2_conn_handle_expiry(ci->qconn, now);
            if (rv < 0) {
                ci->closed = true;
                COND_BROADCAST(&ci->handshake_cond);
                MUTEX_UNLOCK(&ci->conn_mutex);
                break;
            }
        }

        /* Flush any pending TX */
        quic_flush_tx(conn);

        MUTEX_UNLOCK(&ci->conn_mutex);
    }
}

/* ============================================================================
 * Server Connection I/O Thread
 * ============================================================================
 * Owns ALL ngtcp2 calls for a server connection. Packets arrive via the
 * pkt_ring (pushed by listener thread). Application writes still use
 * conn_mutex briefly for writev_stream, but the I/O thread handles
 * read_pkt, handle_expiry, and flush — no other thread calls these.
 * ============================================================================ */

static void *quic_server_io_thread_entry(void *arg) {
    RtQuicConnection *conn = (RtQuicConnection *)arg;
    quic_server_io_thread_func(conn);
    return NULL;
}

static void quic_server_io_thread_func(RtQuicConnection *conn) {
    QuicConnectionInternal *ci = conn_internal(conn);
    QuicPacket pkt_local;

    while (ci->io_running && !ci->closed) {
        bool had_work = false;

        /* 1. Drain packet ring — copy under pkt_ring_mutex, process under conn_mutex */
        for (;;) {
            bool got_pkt = false;
            MUTEX_LOCK(&ci->pkt_ring_mutex);
            if (ci->pkt_ring_head != ci->pkt_ring_tail) {
                pkt_local = ci->pkt_ring[ci->pkt_ring_tail];
                ci->pkt_ring_tail = (ci->pkt_ring_tail + 1) % QUIC_PKT_RING_SIZE;
                got_pkt = true;
            }
            MUTEX_UNLOCK(&ci->pkt_ring_mutex);

            if (!got_pkt) break;
            had_work = true;

            MUTEX_LOCK(&ci->conn_mutex);
            if (ci->closed) {
                MUTEX_UNLOCK(&ci->conn_mutex);
                return;
            }
            ngtcp2_path path;
            memset(&path, 0, sizeof(path));
            path.local.addr = (struct sockaddr *)&ci->local_addr;
            path.local.addrlen = ci->local_addrlen;
            path.remote.addr = (struct sockaddr *)&pkt_local.from_addr;
            path.remote.addrlen = pkt_local.from_len;

            ngtcp2_pkt_info pi;
            memset(&pi, 0, sizeof(pi));

            int rv = ngtcp2_conn_read_pkt(ci->qconn, &path, &pi,
                                           pkt_local.data, pkt_local.len, quic_timestamp());
            if (rv < 0) {
                if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
                    ci->closed = true;
                    COND_BROADCAST(&ci->accept_stream_cond);
                    MUTEX_UNLOCK(&ci->conn_mutex);
                    return;
                }
            }
            /* Flush after processing each packet */
            quic_server_flush_tx(conn, ci->listener_sock);
            MUTEX_UNLOCK(&ci->conn_mutex);
        }

        /* 2. Handle timer expiry + flush TX */
        MUTEX_LOCK(&ci->conn_mutex);
        if (ci->closed) {
            MUTEX_UNLOCK(&ci->conn_mutex);
            return;
        }

        ngtcp2_tstamp now = quic_timestamp();
        ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(ci->qconn);
        if (expiry <= now) {
            int rv = ngtcp2_conn_handle_expiry(ci->qconn, now);
            if (rv < 0) {
                ci->closed = true;
                COND_BROADCAST(&ci->accept_stream_cond);
                MUTEX_UNLOCK(&ci->conn_mutex);
                return;
            }
        }
        quic_server_flush_tx(conn, ci->listener_sock);

        now = quic_timestamp();
        expiry = ngtcp2_conn_get_expiry(ci->qconn);
        MUTEX_UNLOCK(&ci->conn_mutex);

        /* 3. Wait for packets or timeout */
        int timeout_ms;
        if (had_work) {
            timeout_ms = 0;
        } else if (expiry <= now) {
            timeout_ms = 1;
        } else {
            timeout_ms = (int)((expiry - now) / NGTCP2_MILLISECONDS);
            if (timeout_ms > 50) timeout_ms = 50;
            if (timeout_ms < 1) timeout_ms = 1;
        }

        MUTEX_LOCK(&ci->pkt_ring_mutex);
        if (ci->pkt_ring_head == ci->pkt_ring_tail && !ci->closed) {
#ifdef _WIN32
            COND_TIMEDWAIT(&ci->pkt_ring_cond, &ci->pkt_ring_mutex, timeout_ms);
#else
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += (long)timeout_ms * 1000000L;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec += ts.tv_nsec / 1000000000L;
                ts.tv_nsec %= 1000000000L;
            }
            pthread_cond_timedwait(&ci->pkt_ring_cond, &ci->pkt_ring_mutex, &ts);
#endif
        }
        MUTEX_UNLOCK(&ci->pkt_ring_mutex);
    }
}

/* ============================================================================
 * Connection Creation (Client)
 * ============================================================================ */

static RtQuicConnection *quic_connection_create(char *address,
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

    /* Allocate Sindarin struct via compiler-generated __new() */
    RtQuicConnection *conn = __sn__QuicConnection__new();
    QuicConnectionInternal *ci = (QuicConnectionInternal *)calloc(1, sizeof(QuicConnectionInternal));
    conn_register(conn, ci);

    conn->socket_fd = (long long)sock;
    ci->is_server = false;

    memcpy(&ci->remote_addr, res->ai_addr, res->ai_addrlen);
    ci->remote_addrlen = (socklen_t)res->ai_addrlen;
    memcpy(&ci->local_addr, &local_addr, local_len);
    ci->local_addrlen = local_len;
    ci->remote_addr_str = format_address(&ci->remote_addr, ci->remote_addrlen);

    freeaddrinfo(res);

    /* Initialize synchronization */
    MUTEX_INIT(&ci->conn_mutex);
    COND_INIT(&ci->handshake_cond);
    COND_INIT(&ci->accept_stream_cond);

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
    path.local.addr = (struct sockaddr *)&ci->local_addr;
    path.local.addrlen = ci->local_addrlen;
    path.remote.addr = (struct sockaddr *)&ci->remote_addr;
    path.remote.addrlen = ci->remote_addrlen;

    /* Setup ngtcp2 settings */
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = quic_timestamp();
    settings.max_tx_udp_payload_size = QUIC_MAX_PACKET_SIZE;

    /* Create ngtcp2 client connection */
    int rv = ngtcp2_conn_client_new(&ci->qconn, &dcid, &scid, &path,
                                     NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                     &params, NULL, conn);
    if (rv != 0) {
        fprintf(stderr, "QUIC: Failed to create ngtcp2 connection: %s\n", ngtcp2_strerror(rv));
        CLOSE_SOCKET(sock);
        return NULL;
    }

    conn->conn_ptr = (long long)(uintptr_t)ci->qconn;

    /* Create SSL context and connection */
    ci->ssl_ctx = create_client_ssl_ctx();
    if (!ci->ssl_ctx) {
        fprintf(stderr, "QUIC: Failed to create SSL context\n");
        ngtcp2_conn_del(ci->qconn);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    ci->ssl = create_client_ssl(ci->ssl_ctx, host, conn);
    if (!ci->ssl) {
        fprintf(stderr, "QUIC: Failed to create SSL\n");
        SSL_CTX_free(ci->ssl_ctx);
        ngtcp2_conn_del(ci->qconn);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    /* Create ngtcp2 crypto ossl context and set as native handle */
    if (ngtcp2_crypto_ossl_ctx_new(&ci->ossl_ctx, ci->ssl) != 0) {
        fprintf(stderr, "QUIC: Failed to create ossl ctx\n");
        SSL_free(ci->ssl);
        SSL_CTX_free(ci->ssl_ctx);
        ngtcp2_conn_del(ci->qconn);
        CLOSE_SOCKET(sock);
        return NULL;
    }
    ngtcp2_conn_set_tls_native_handle(ci->qconn, ci->ossl_ctx);

    /* Restore session for 0-RTT if token provided */
    if (early && token && token_len > 0) {
        const unsigned char *p = token;
        SSL_SESSION *session = d2i_SSL_SESSION(NULL, &p, (long)token_len);
        if (session) {
            SSL_set_session(ci->ssl, session);
            SSL_SESSION_free(session);
        }
    }

    /* Start I/O thread */
    ci->io_running = true;

#ifdef _WIN32
    ci->io_thread = (HANDLE)_beginthreadex(NULL, 0,
        (unsigned (__stdcall *)(void *))quic_io_thread_entry, conn, 0, NULL);
#else
    pthread_create(&ci->io_thread, NULL, quic_io_thread_entry, conn);
#endif

    /* Perform initial flush to send client hello */
    MUTEX_LOCK(&ci->conn_mutex);
    quic_flush_tx(conn);
    MUTEX_UNLOCK(&ci->conn_mutex);

    /* Wait for handshake to complete */
    MUTEX_LOCK(&ci->conn_mutex);
    while (!ci->handshake_complete && !ci->closed) {
        COND_WAIT(&ci->handshake_cond, &ci->conn_mutex);
    }
    MUTEX_UNLOCK(&ci->conn_mutex);

    if (ci->closed && !ci->handshake_complete) {
        fprintf(stderr, "QUIC: Handshake failed\n");
        ci->io_running = false;
#ifndef _WIN32
        pthread_join(ci->io_thread, NULL);
#endif
        SSL_free(ci->ssl);
        SSL_CTX_free(ci->ssl_ctx);
        ngtcp2_conn_del(ci->qconn);
        CLOSE_SOCKET(sock);
        return NULL;
    }

    return conn;
}

/* ============================================================================
 * Connection Creation (Server-side, called from listener)
 * ============================================================================ */

static RtQuicConnection *quic_server_connection_create(socket_t sock,
                                                   SSL_CTX *ssl_ctx,
                                                   struct sockaddr_storage *remote,
                                                   socklen_t remote_len,
                                                   struct sockaddr_storage *local,
                                                   socklen_t local_len,
                                                   const uint8_t *pkt, size_t pktlen,
                                                   const ngtcp2_pkt_hd *hd,
                                                   RtQuicConfig *config,
                                                   const ngtcp2_cid *odcid,
                                                   const uint8_t *token,
                                                   size_t tokenlen) {
    /* Allocate Sindarin struct via compiler-generated __new() */
    RtQuicConnection *conn = __sn__QuicConnection__new();
    QuicConnectionInternal *ci = (QuicConnectionInternal *)calloc(1, sizeof(QuicConnectionInternal));
    conn_register(conn, ci);

    ci->is_server = true;

    /* Server connections share the listener's socket */
    conn->socket_fd = (long long)sock;
    memcpy(&ci->remote_addr, remote, remote_len);
    ci->remote_addrlen = remote_len;
    memcpy(&ci->local_addr, local, local_len);
    ci->local_addrlen = local_len;
    ci->remote_addr_str = format_address(&ci->remote_addr, ci->remote_addrlen);

    MUTEX_INIT(&ci->conn_mutex);
    COND_INIT(&ci->handshake_cond);
    COND_INIT(&ci->accept_stream_cond);

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
    /* Server CID: after Retry, use the DCID from the retried Initial (which
     * IS the Retry SCID the client is addressing). Otherwise generate fresh. */
    ngtcp2_cid scid;
    if (odcid) {
        scid = hd->dcid;  /* Client's DCID = Retry SCID → use as our SCID */
    } else {
        scid.datalen = 16;
        RAND_bytes(scid.data, (int)scid.datalen);
    }

    /* Server must set original_dcid.  After Retry, this is the DCID from
     * the ORIGINAL Initial (before Retry), extracted from the verified token. */
    if (odcid) {
        params.original_dcid = *odcid;
        params.retry_scid = scid;
        params.retry_scid_present = 1;
    } else {
        params.original_dcid = hd->dcid;
    }
    params.original_dcid_present = 1;

    /* Path */
    ngtcp2_path path;
    memset(&path, 0, sizeof(path));
    path.local.addr = (struct sockaddr *)&ci->local_addr;
    path.local.addrlen = ci->local_addrlen;
    path.remote.addr = (struct sockaddr *)&ci->remote_addr;
    path.remote.addrlen = ci->remote_addrlen;

    /* Settings */
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = quic_timestamp();
    settings.max_tx_udp_payload_size = QUIC_MAX_PACKET_SIZE;
    if (token && tokenlen > 0) {
        settings.token = token;
        settings.tokenlen = tokenlen;
        settings.token_type = NGTCP2_TOKEN_TYPE_RETRY;
    }

    /* Create ngtcp2 server connection */
    int rv = ngtcp2_conn_server_new(&ci->qconn, &hd->scid, &scid, &path,
                                     NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                     &params, NULL, conn);
    if (rv != 0) {
        fprintf(stderr, "QUIC: Failed to create server connection: %s\n", ngtcp2_strerror(rv));
        return NULL;
    }

    conn->conn_ptr = (long long)(uintptr_t)ci->qconn;
    ci->ssl_ctx = ssl_ctx; /* Shared with listener */

    /* Create server SSL */
    ci->ssl = create_server_ssl(ssl_ctx, conn);
    if (!ci->ssl) {
        fprintf(stderr, "QUIC: Failed to create server SSL\n");
        ngtcp2_conn_del(ci->qconn);
        return NULL;
    }

    /* Create ngtcp2 crypto ossl context and set as native handle */
    if (ngtcp2_crypto_ossl_ctx_new(&ci->ossl_ctx, ci->ssl) != 0) {
        fprintf(stderr, "QUIC: Failed to create server ossl ctx\n");
        SSL_free(ci->ssl);
        ngtcp2_conn_del(ci->qconn);
        return NULL;
    }
    ngtcp2_conn_set_tls_native_handle(ci->qconn, ci->ossl_ctx);

    /* Process the initial packet */
    ngtcp2_pkt_info pi;
    memset(&pi, 0, sizeof(pi));
    rv = ngtcp2_conn_read_pkt(ci->qconn, &path, &pi, pkt, pktlen, quic_timestamp());
    if (rv < 0) {
        fprintf(stderr, "QUIC: Failed to process initial packet: %s (code=%d)\n", ngtcp2_strerror(rv), rv);
        SSL_free(ci->ssl);
        ngtcp2_conn_del(ci->qconn);
        free(ci->pkt_ring);
        return NULL;
    }

    /* Initialize packet ring buffer for I/O thread */
    ci->pkt_ring = (QuicPacket *)calloc(QUIC_PKT_RING_SIZE, sizeof(QuicPacket));
    ci->pkt_ring_head = 0;
    ci->pkt_ring_tail = 0;
    MUTEX_INIT(&ci->pkt_ring_mutex);
    COND_INIT(&ci->pkt_ring_cond);
    ci->listener_sock = sock;

    /* Cache SCIDs for lock-free routing */
    {
        ngtcp2_cid scids_buf[8];
        size_t ns = ngtcp2_conn_get_scid(ci->qconn, scids_buf);
        for (size_t s = 0; s < ns && s < 8; s++)
            ci->cached_scids[s] = scids_buf[s];
        ci->cached_scid_count = (int)(ns < 8 ? ns : 8);
    }

    /* Flush initial server response (ServerHello etc.) */
    quic_server_flush_tx(conn, sock);

    /* Spawn per-connection I/O thread immediately.
     * All subsequent ngtcp2 calls happen on this thread. */
    ci->io_running = true;
#ifdef _WIN32
    ci->io_thread = (HANDLE)_beginthreadex(NULL, 0,
        (unsigned int (__stdcall *)(void *))quic_server_io_thread_entry,
        conn, 0, NULL);
#else
    pthread_create(&ci->io_thread, NULL, quic_server_io_thread_entry, conn);
    pthread_detach(ci->io_thread);
#endif

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
    QuicConnectionInternal *ci = conn_internal(conn);
    /* Flush TX for a server connection using the listener's socket */
    uint8_t buf[QUIC_MAX_PACKET_SIZE];
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi;

    for (;;) {
        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            ci->qconn, &ps.path, &pi,
            buf, sizeof(buf),
            NULL, NGTCP2_WRITE_STREAM_FLAG_NONE,
            -1, NULL, 0, quic_timestamp());

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE) continue;
            break;
        }
        if (nwrite == 0) break;

        sendto(sock, (const char *)buf, (size_t)nwrite, 0,
               (struct sockaddr *)&ci->remote_addr, ci->remote_addrlen);
    }
}

static void quic_listener_thread_func(RtQuicListener *listener) {
    QuicListenerInternal *li = listener_internal(listener);
    uint8_t buf[QUIC_RECV_BUF_SIZE];
    struct pollfd pfd;
    pfd.fd = listener->socket_fd;
    pfd.events = POLLIN;

    ensure_retry_secret();

    while (li->running) {
        int ret = POLL(&pfd, 1, 50);
        if (!li->running) break;

        if (ret > 0 && (pfd.revents & POLLIN)) {
            struct sockaddr_storage from_addr;
            socklen_t from_len = sizeof(from_addr);

            ssize_t nread = recvfrom(listener->socket_fd, (char *)buf, sizeof(buf), 0,
                                     (struct sockaddr *)&from_addr, &from_len);
            if (nread <= 0) continue;
            if ((size_t)nread > QUIC_MAX_PACKET_SIZE) continue;

            /* Extract DCID from packet to route to the correct connection */
            ngtcp2_version_cid vc;
            int vc_rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)nread, 16);

            if (vc_rv != 0 && vc_rv != 1) continue;
            if (vc.dcidlen > NGTCP2_MAX_CIDLEN) continue;

            ngtcp2_cid pkt_dcid;
            ngtcp2_cid_init(&pkt_dcid, vc.dcid, vc.dcidlen);

            /* Route to existing connection via cached SCIDs (lock-free) */
            bool routed = false;
            RtQuicConnection *route_conns[QUIC_MAX_STREAMS];
            int route_count = 0;
            MUTEX_LOCK(&li->conn_list_mutex);
            for (int i = 0; i < li->connection_count && i < QUIC_MAX_STREAMS; i++) {
                route_conns[i] = li->connections[i];
            }
            route_count = li->connection_count;
            MUTEX_UNLOCK(&li->conn_list_mutex);

            for (int i = 0; i < route_count; i++) {
                RtQuicConnection *existing = route_conns[i];
                if (!existing) continue;
                QuicConnectionInternal *eci = conn_internal(existing);
                if (eci->closed) continue;

                /* Match DCID against cached SCIDs — no conn_mutex needed */
                bool match = false;
                int nscids = eci->cached_scid_count;
                for (int s = 0; s < nscids && s < 8; s++) {
                    if (ngtcp2_cid_eq(&pkt_dcid, &eci->cached_scids[s])) {
                        match = true;
                        break;
                    }
                }
                if (!match) continue;

                /* Push to connection's packet ring — I/O thread will process */
                MUTEX_LOCK(&eci->pkt_ring_mutex);
                int next = (eci->pkt_ring_head + 1) % QUIC_PKT_RING_SIZE;
                if (next != eci->pkt_ring_tail) {
                    QuicPacket *slot = &eci->pkt_ring[eci->pkt_ring_head];
                    memcpy(slot->data, buf, (size_t)nread);
                    slot->len = (size_t)nread;
                    memcpy(&slot->from_addr, &from_addr, from_len);
                    slot->from_len = from_len;
                    eci->pkt_ring_head = next;
                }
                COND_SIGNAL(&eci->pkt_ring_cond);
                MUTEX_UNLOCK(&eci->pkt_ring_mutex);
                routed = true;
                break;
            }

            if (routed) continue;

            /* Not routed — must be a new Initial packet */
            ngtcp2_pkt_hd hd;
            int rv = ngtcp2_accept(&hd, buf, (size_t)nread);
            if (rv < 0) continue;

            /* Stateless Retry: if no Retry token, send one and continue */
            ngtcp2_cid odcid;
            const uint8_t *token_ptr = NULL;
            size_t token_len = 0;

            if (hd.tokenlen == 0 || hd.token[0] != NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2) {
                /* No valid Retry token — send stateless Retry packet */
                ngtcp2_cid retry_scid;
                retry_scid.datalen = 16;
                RAND_bytes(retry_scid.data, (int)retry_scid.datalen);

                uint8_t retry_token[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2];
                ngtcp2_ssize tokenlen = ngtcp2_crypto_generate_retry_token2(
                    retry_token, g_retry_secret, QUIC_RETRY_SECRET_LEN,
                    hd.version,
                    (const ngtcp2_sockaddr *)&from_addr, from_len,
                    &retry_scid, &hd.dcid, quic_timestamp());
                if (tokenlen < 0) continue;

                uint8_t retry_pkt[QUIC_MAX_PACKET_SIZE];
                ngtcp2_ssize retry_nwrite = ngtcp2_crypto_write_retry(
                    retry_pkt, sizeof(retry_pkt), hd.version,
                    &hd.scid, &retry_scid, &hd.dcid,
                    retry_token, (size_t)tokenlen);
                if (retry_nwrite < 0) continue;

                ssize_t retry_sent = sendto(listener->socket_fd, (const char *)retry_pkt, (size_t)retry_nwrite, 0,
                       (struct sockaddr *)&from_addr, from_len);
                fprintf(stderr, "QUIC: sent Retry packet (%zd bytes, sent=%zd) to client\n", (ssize_t)retry_nwrite, retry_sent);
                fflush(stderr);
                continue;
            }

            /* Verify Retry token */
            fprintf(stderr, "QUIC: verifying Retry token (tokenlen=%zu)\n", hd.tokenlen);
            fflush(stderr);
            rv = ngtcp2_crypto_verify_retry_token2(
                &odcid, hd.token, hd.tokenlen,
                g_retry_secret, QUIC_RETRY_SECRET_LEN,
                hd.version,
                (const ngtcp2_sockaddr *)&from_addr, from_len,
                &hd.dcid, QUIC_RETRY_TOKEN_TIMEOUT, quic_timestamp());
            if (rv != 0) continue;

            token_ptr = hd.token;
            token_len = hd.tokenlen;

            /* Create server connection with verified token.
             * This spawns a per-connection I/O thread that owns all ngtcp2 calls. */
            RtQuicConnection *new_conn = quic_server_connection_create(
                listener->socket_fd, li->ssl_ctx,
                &from_addr, from_len,
                &li->local_addr, li->local_addrlen,
                buf, (size_t)nread, &hd, &li->config,
                &odcid, token_ptr, token_len);

            if (new_conn) {
                QuicConnectionInternal *nci = conn_internal(new_conn);

                /* Add to connection list for future packet routing */
                MUTEX_LOCK(&li->conn_list_mutex);
                if (li->connection_count < QUIC_MAX_STREAMS) {
                    li->connections[li->connection_count++] = new_conn;
                }
                MUTEX_UNLOCK(&li->conn_list_mutex);

                /* Push to accept queue (handshake may complete quickly via I/O thread) */
                MUTEX_LOCK(&li->accept_mutex);
                if (li->accept_count < QUIC_MAX_INCOMING_STREAMS) {
                    li->accept_queue_conns[li->accept_tail] = new_conn;
                    li->accept_tail = (li->accept_tail + 1) % QUIC_MAX_INCOMING_STREAMS;
                    li->accept_count++;
                    COND_SIGNAL(&li->accept_cond);
                }
                MUTEX_UNLOCK(&li->accept_mutex);
            }
        }
        /* No timer handling — each connection's I/O thread handles its own timers */
    }
}

/* ============================================================================
 * QuicConfig API
 * ============================================================================ */

__sn__QuicConfig *sn_quic_config_defaults(void) {
    RtQuicConfig *config = __sn__QuicConfig__new();
    config->max_bidi_streams = QUIC_DEFAULT_MAX_BIDI_STREAMS;
    config->max_uni_streams = QUIC_DEFAULT_MAX_UNI_STREAMS;
    config->max_stream_window = QUIC_DEFAULT_MAX_STREAM_WINDOW;
    config->max_conn_window = QUIC_DEFAULT_MAX_CONN_WINDOW;
    config->idle_timeout_ms = QUIC_DEFAULT_IDLE_TIMEOUT_MS;
    return config;
}

__sn__QuicConfig *sn_quic_config_set_max_bidi_streams(__sn__QuicConfig *config, int n) {
    if (config == NULL) return NULL;
    config->max_bidi_streams = n;
    RtQuicConfig *ret = __sn__QuicConfig__new();
    memcpy(ret, config, sizeof(RtQuicConfig));
    return ret;
}

__sn__QuicConfig *sn_quic_config_set_max_uni_streams(__sn__QuicConfig *config, int n) {
    if (config == NULL) return NULL;
    config->max_uni_streams = n;
    RtQuicConfig *ret = __sn__QuicConfig__new();
    memcpy(ret, config, sizeof(RtQuicConfig));
    return ret;
}

__sn__QuicConfig *sn_quic_config_set_max_stream_window(__sn__QuicConfig *config, int bytes) {
    if (config == NULL) return NULL;
    config->max_stream_window = bytes;
    RtQuicConfig *ret = __sn__QuicConfig__new();
    memcpy(ret, config, sizeof(RtQuicConfig));
    return ret;
}

__sn__QuicConfig *sn_quic_config_set_max_conn_window(__sn__QuicConfig *config, int bytes) {
    if (config == NULL) return NULL;
    config->max_conn_window = bytes;
    RtQuicConfig *ret = __sn__QuicConfig__new();
    memcpy(ret, config, sizeof(RtQuicConfig));
    return ret;
}

__sn__QuicConfig *sn_quic_config_set_idle_timeout(__sn__QuicConfig *config, int ms) {
    if (config == NULL) return NULL;
    config->idle_timeout_ms = ms;
    RtQuicConfig *ret = __sn__QuicConfig__new();
    memcpy(ret, config, sizeof(RtQuicConfig));
    return ret;
}

/* ============================================================================
 * QuicStream API
 * ============================================================================ */

SnArray *sn_quic_stream_read(__sn__QuicStream *stream, long long maxBytes) {
    if (!stream || maxBytes <= 0) {
        { SnArray *empty = sn_array_new(sizeof(unsigned char), 0); empty->elem_tag = SN_TAG_BYTE; return empty; }
    }
    RtQuicStream *_stream = (RtQuicStream *)stream;
    QuicStreamInternal *si = stream_internal(_stream);

    MUTEX_LOCK(&si->stream_mutex);

    /* Wait for data or FIN */
    while (stream_buf_available(&si->recv_buf) == 0 &&
           !si->recv_buf.fin_received && !si->closed) {
        COND_WAIT(&si->read_cond, &si->stream_mutex);
    }

    size_t avail = stream_buf_available(&si->recv_buf);
    if (avail == 0) {
        MUTEX_UNLOCK(&si->stream_mutex);
        { SnArray *empty = sn_array_new(sizeof(unsigned char), 0); empty->elem_tag = SN_TAG_BYTE; return empty; }
    }

    size_t to_read = avail < (size_t)maxBytes ? avail : (size_t)maxBytes;
    SnArray *result = sn_array_new(sizeof(unsigned char), (long long)to_read);
    result->elem_tag = SN_TAG_BYTE;
    { unsigned char *src = (unsigned char *)si->recv_buf.data + si->recv_buf.read_pos; for (size_t _i = 0; _i < (size_t)to_read; _i++) sn_array_push(result, &src[_i]); }
    si->recv_buf.read_pos += to_read;

    MUTEX_UNLOCK(&si->stream_mutex);
    return result;
}

SnArray *sn_quic_stream_read_exact(__sn__QuicStream *stream, long long nBytes) {
    if (!stream || nBytes <= 0) {
        SnArray *empty = sn_array_new(sizeof(unsigned char), 0);
        empty->elem_tag = SN_TAG_BYTE;
        return empty;
    }
    RtQuicStream *_stream = (RtQuicStream *)stream;
    QuicStreamInternal *si = stream_internal(_stream);

    SnArray *result = sn_array_new(sizeof(unsigned char), nBytes);
    result->elem_tag = SN_TAG_BYTE;
    size_t remaining = (size_t)nBytes;

    MUTEX_LOCK(&si->stream_mutex);
    while (remaining > 0) {
        /* Wait for data or terminal condition */
        while (stream_buf_available(&si->recv_buf) == 0 &&
               !si->recv_buf.fin_received && !si->closed) {
            COND_WAIT(&si->read_cond, &si->stream_mutex);
        }

        size_t avail = stream_buf_available(&si->recv_buf);
        if (avail == 0) break;  /* Stream closed — return short */

        size_t to_read = avail < remaining ? avail : remaining;
        unsigned char *src = (unsigned char *)si->recv_buf.data + si->recv_buf.read_pos;
        for (size_t i = 0; i < to_read; i++)
            sn_array_push(result, &src[i]);
        si->recv_buf.read_pos += to_read;
        remaining -= to_read;
    }
    MUTEX_UNLOCK(&si->stream_mutex);
    return result;
}

SnArray *sn_quic_stream_read_all(__sn__QuicStream *stream) {
    if (!stream) {
        { SnArray *empty = sn_array_new(sizeof(unsigned char), 0); empty->elem_tag = SN_TAG_BYTE; return empty; }
    }
    RtQuicStream *_stream = (RtQuicStream *)stream;
    QuicStreamInternal *si = stream_internal(_stream);

    MUTEX_LOCK(&si->stream_mutex);

    /* Wait for FIN or close */
    while (!si->recv_buf.fin_received && !si->closed) {
        COND_WAIT(&si->read_cond, &si->stream_mutex);
    }

    size_t avail = stream_buf_available(&si->recv_buf);
    SnArray *result;
    if (avail > 0) {
        result = sn_array_new(sizeof(unsigned char), (long long)avail);
        result->elem_tag = SN_TAG_BYTE;
        { unsigned char *src = (unsigned char *)si->recv_buf.data + si->recv_buf.read_pos; for (size_t _i = 0; _i < (size_t)avail; _i++) sn_array_push(result, &src[_i]); }
        si->recv_buf.read_pos += avail;
    } else {
        result = sn_array_new(sizeof(unsigned char), (long long)0);
        result->elem_tag = SN_TAG_BYTE;
        { unsigned char *src = (unsigned char *)NULL; for (size_t _i = 0; _i < (size_t)0; _i++) sn_array_push(result, &src[_i]); }
    }

    MUTEX_UNLOCK(&si->stream_mutex);
    return result;
}

char *sn_quic_stream_read_line(__sn__QuicStream *stream) {
    if (!stream) {
        return strdup("");
    }
    RtQuicStream *_stream = (RtQuicStream *)stream;
    QuicStreamInternal *si = stream_internal(_stream);

    MUTEX_LOCK(&si->stream_mutex);

    /* Wait for newline, FIN, or close */
    for (;;) {
        size_t avail = stream_buf_available(&si->recv_buf);
        uint8_t *start = si->recv_buf.data + si->recv_buf.read_pos;

        /* Search for newline */
        for (size_t i = 0; i < avail; i++) {
            if (start[i] == '\n') {
                /* Found newline - return line without it */
                size_t line_len = i;
                /* Strip \r if present */
                if (line_len > 0 && start[line_len - 1] == '\r') line_len--;

                char *temp = (char *)malloc(line_len + 1);
                memcpy(temp, start, line_len);
                temp[line_len] = '\0';
                si->recv_buf.read_pos += i + 1;
                MUTEX_UNLOCK(&si->stream_mutex);
                { char *ret = strdup(temp); free(temp); return ret; }
            }
        }

        if (si->recv_buf.fin_received || si->closed) {
            /* Return remaining data as last line */
            char *temp = (char *)malloc(avail + 1);
            if (avail > 0) memcpy(temp, start, avail);
            temp[avail] = '\0';
            si->recv_buf.read_pos += avail;
            MUTEX_UNLOCK(&si->stream_mutex);
            { char *ret = strdup(temp); free(temp); return ret; }
        }

        COND_WAIT(&si->read_cond, &si->stream_mutex);
    }
}

long long sn_quic_stream_write(__sn__QuicStream *stream, SnArray *data) {
    if (!stream || !data) return 0;
    RtQuicStream *_stream = (RtQuicStream *)stream;
    QuicStreamInternal *si = stream_internal(_stream);
    if (!si) return 0;
    size_t data_len = (size_t)data->len;
    if (data_len == 0) return 0;

    RtQuicConnection *conn = (RtQuicConnection *)(uintptr_t)_stream->conn_ptr;
    QuicConnectionInternal *ci = conn_internal(conn);

    MUTEX_LOCK(&ci->conn_mutex);

    if (ci->closed || si->write_closed) {
        MUTEX_UNLOCK(&ci->conn_mutex);
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
        v.base = (uint8_t *)data->data + total_written;
        v.len = data_len - total_written;

        ngtcp2_ssize ndatalen = 0;
        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            ci->qconn, &ps.path, &pi,
            buf, sizeof(buf),
            &ndatalen,
            NGTCP2_WRITE_STREAM_FLAG_NONE,
            _stream->stream_id, &v, 1, quic_timestamp());

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

        if (nwrite == 0) {
            if (ci->is_server && total_written < data_len) {
                /* Yield mutex so listener thread can process incoming packets
                 * (may need ACKs or flow control updates before ngtcp2 can write) */
                MUTEX_UNLOCK(&ci->conn_mutex);
                usleep(1000);
                MUTEX_LOCK(&ci->conn_mutex);
                if (ci->closed) break;
                continue;
            }
            break;
        }
    }

    /* Flush pending TX.  Server connections skip the flush loop to avoid
     * holding conn_mutex while the listener thread needs it for incoming
     * packet processing.  The listener's timer loop flushes periodically. */
    if (!ci->is_server) {
        for (;;) {
            ngtcp2_ssize nw = ngtcp2_conn_writev_stream(
                ci->qconn, &ps.path, &pi,
                buf, sizeof(buf),
                NULL, NGTCP2_WRITE_STREAM_FLAG_NONE,
                -1, NULL, 0, quic_timestamp());
            if (nw < 0) break;
            if (nw == 0) break;
            quic_send_packet(conn, buf, (size_t)nw);
        }
    }

    MUTEX_UNLOCK(&ci->conn_mutex);
    return (long)total_written;
}

void sn_quic_stream_write_line(__sn__QuicStream *stream, char *text) {
    if (!stream || !text) return;
    RtQuicStream *_stream = (RtQuicStream *)stream;
    QuicStreamInternal *si = stream_internal(_stream);

    size_t text_len = strlen(text);
    size_t total_len = text_len + 1; /* text + \n */

    uint8_t *buf = (uint8_t *)malloc(total_len);
    memcpy(buf, text, text_len);
    buf[text_len] = '\n';

    RtQuicConnection *conn = (RtQuicConnection *)(uintptr_t)_stream->conn_ptr;
    QuicConnectionInternal *ci = conn_internal(conn);
    MUTEX_LOCK(&ci->conn_mutex);

    if (ci->closed || si->write_closed) {
        MUTEX_UNLOCK(&ci->conn_mutex);
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
            ci->qconn, &ps.path, &pi,
            pkt, sizeof(pkt),
            &ndatalen,
            NGTCP2_WRITE_STREAM_FLAG_NONE,
            _stream->stream_id, &v, 1, quic_timestamp());

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

        if (nwrite == 0) {
            if (ci->is_server && total_written < total_len) {
                MUTEX_UNLOCK(&ci->conn_mutex);
                usleep(1000);
                MUTEX_LOCK(&ci->conn_mutex);
                if (ci->closed) break;
                continue;
            }
            break;
        }
    }

    /* Flush pending TX — skip for server (listener thread flushes in timer loop) */
    if (!ci->is_server) {
        for (;;) {
            ngtcp2_ssize nw = ngtcp2_conn_writev_stream(
                ci->qconn, &ps.path, &pi,
                pkt, sizeof(pkt),
                NULL, NGTCP2_WRITE_STREAM_FLAG_NONE,
                -1, NULL, 0, quic_timestamp());
            if (nw < 0) break;
            if (nw == 0) break;
            quic_send_packet(conn, pkt, (size_t)nw);
        }
    }

    MUTEX_UNLOCK(&ci->conn_mutex);
    free(buf);
}

long long sn_quic_stream_get_id(__sn__QuicStream *stream) {
    if (!stream) return -1;
    RtQuicStream *_stream = (RtQuicStream *)stream;
    return _stream->stream_id;
}

bool sn_quic_stream_is_unidirectional(__sn__QuicStream *stream) {
    if (!stream) return false;
    RtQuicStream *_stream = (RtQuicStream *)stream;
    QuicStreamInternal *si = stream_internal(_stream);
    return si->is_uni;
}

void sn_quic_stream_close(__sn__QuicStream *stream) {
    if (!stream) return;
    RtQuicStream *_stream = (RtQuicStream *)stream;
    QuicStreamInternal *si = stream_internal(_stream);
    if (si->closed) return;

    RtQuicConnection *conn = (RtQuicConnection *)(uintptr_t)_stream->conn_ptr;
    QuicConnectionInternal *ci = conn_internal(conn);

    MUTEX_LOCK(&ci->conn_mutex);

    if (!ci->closed) {
        /* Send FIN on the stream */
        uint8_t buf[QUIC_MAX_PACKET_SIZE];
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi;
        ngtcp2_ssize ndatalen;

        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            ci->qconn, &ps.path, &pi,
            buf, sizeof(buf),
            &ndatalen,
            NGTCP2_WRITE_STREAM_FLAG_FIN,
            _stream->stream_id, NULL, 0, quic_timestamp());

        if (nwrite > 0) {
            quic_send_packet(conn, buf, (size_t)nwrite);
        }
    }

    MUTEX_UNLOCK(&ci->conn_mutex);

    /* Remove from connection's stream array to prevent use-after-free
     * when the Sindarin runtime frees the RtQuicStream via refcount. */
    for (int i = 0; i < ci->stream_count; i++) {
        if (ci->streams[i] == _stream) {
            ci->streams[i] = NULL;
            break;
        }
    }

    MUTEX_LOCK(&si->stream_mutex);
    si->write_closed = true;
    si->closed = true;
    COND_BROADCAST(&si->read_cond);
    MUTEX_UNLOCK(&si->stream_mutex);
}

/* ============================================================================
 * QuicConnection API
 * ============================================================================ */

__sn__QuicConnection *sn_quic_connection_connect(char *address) {
    return (__sn__QuicConnection *)quic_connection_create(address, NULL, false, NULL, 0);
}

__sn__QuicConnection *sn_quic_connection_connect_with(char *address,
                                              __sn__QuicConfig *config) {
    if (config == NULL) return NULL;
    RtQuicConfig *_config = (RtQuicConfig *)config;
    return (__sn__QuicConnection *)quic_connection_create(address, _config, false, NULL, 0);
}

__sn__QuicConnection *sn_quic_connection_connect_early(char *address,
                                               SnArray *token) {
    if (!token || token->len == 0) {
        return (__sn__QuicConnection *)quic_connection_create(address, NULL, false, NULL, 0);
    }
    return (__sn__QuicConnection *)quic_connection_create(address, NULL, true,
                                   (const uint8_t *)token->data, token->len);
}

__sn__QuicStream *sn_quic_connection_open_stream(__sn__QuicConnection *conn) {
    if (conn == NULL) return NULL;
    RtQuicConnection *_conn = (RtQuicConnection *)conn;
    QuicConnectionInternal *ci = conn_internal(_conn);
    if (ci->closed) return NULL;

    MUTEX_LOCK(&ci->conn_mutex);

    int64_t stream_id;
    int rv = ngtcp2_conn_open_bidi_stream(ci->qconn, &stream_id, NULL);
    if (rv != 0) {
        MUTEX_UNLOCK(&ci->conn_mutex);
        fprintf(stderr, "QUIC: Failed to open bidi stream: %s (is_server=%d)\n", ngtcp2_strerror(rv), ci->is_server);
        return NULL;
    }

    RtQuicStream *stream = quic_find_or_create_stream(_conn, stream_id);
    MUTEX_UNLOCK(&ci->conn_mutex);
    return stream ? (__sn__QuicStream *)stream : NULL;
}

__sn__QuicStream *sn_quic_connection_open_uni_stream(__sn__QuicConnection *conn) {
    if (conn == NULL) return NULL;
    RtQuicConnection *_conn = (RtQuicConnection *)conn;
    QuicConnectionInternal *ci = conn_internal(_conn);
    if (ci->closed) return NULL;

    MUTEX_LOCK(&ci->conn_mutex);

    int64_t stream_id;
    int rv = ngtcp2_conn_open_uni_stream(ci->qconn, &stream_id, NULL);
    if (rv != 0) {
        MUTEX_UNLOCK(&ci->conn_mutex);
        fprintf(stderr, "QUIC: Failed to open uni stream: %s\n", ngtcp2_strerror(rv));
        return NULL;
    }

    RtQuicStream *stream = quic_find_or_create_stream(_conn, stream_id);
    if (stream) {
        QuicStreamInternal *si = stream_internal(stream);
        si->is_uni = true;
    }
    MUTEX_UNLOCK(&ci->conn_mutex);
    return stream ? (__sn__QuicStream *)stream : NULL;
}

__sn__QuicStream *sn_quic_connection_accept_stream(__sn__QuicConnection *conn) {
    if (conn == NULL) return NULL;
    RtQuicConnection *_conn = (RtQuicConnection *)conn;
    QuicConnectionInternal *ci = conn_internal(_conn);

    MUTEX_LOCK(&ci->conn_mutex);

    while (ci->incoming_count == 0 && !ci->closed) {
        COND_WAIT(&ci->accept_stream_cond, &ci->conn_mutex);
    }

    if (ci->closed || ci->incoming_count == 0) {
        MUTEX_UNLOCK(&ci->conn_mutex);
        return NULL;
    }

    int64_t stream_id = ci->incoming_streams[ci->incoming_head];
    ci->incoming_head = (ci->incoming_head + 1) % QUIC_MAX_INCOMING_STREAMS;
    ci->incoming_count--;

    RtQuicStream *stream = quic_find_or_create_stream(_conn, stream_id);
    MUTEX_UNLOCK(&ci->conn_mutex);
    return stream ? (__sn__QuicStream *)stream : NULL;
}

SnArray *sn_quic_connection_resumption_token(__sn__QuicConnection *conn) {
    if (conn == NULL) { SnArray *empty = sn_array_new(sizeof(unsigned char), 0); empty->elem_tag = SN_TAG_BYTE; return empty; }
    RtQuicConnection *_conn = (RtQuicConnection *)conn;
    QuicConnectionInternal *ci = conn_internal(_conn);
    if (!ci->resumption_token || ci->resumption_token_len == 0) {
        { SnArray *empty = sn_array_new(sizeof(unsigned char), 0); empty->elem_tag = SN_TAG_BYTE; return empty; }
    }

    { SnArray *tok = sn_array_new(sizeof(unsigned char), (long long)ci->resumption_token_len);
    tok->elem_tag = SN_TAG_BYTE;
    for (size_t _i = 0; _i < ci->resumption_token_len; _i++) sn_array_push(tok, &ci->resumption_token[_i]);
    return tok; }
}

void sn_quic_connection_migrate(__sn__QuicConnection *conn, char *newLocalAddress) {
    if (conn == NULL) return;
    RtQuicConnection *_conn = (RtQuicConnection *)conn;
    QuicConnectionInternal *ci = conn_internal(_conn);
    if (ci->closed || !newLocalAddress) return;

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
    if (connect(new_sock, (struct sockaddr *)&ci->remote_addr, ci->remote_addrlen) != 0) {
        CLOSE_SOCKET(new_sock);
        freeaddrinfo(res);
        return;
    }

    set_socket_nonblocking(new_sock);

    /* Get actual bound address */
    struct sockaddr_storage new_local;
    socklen_t new_local_len = sizeof(new_local);
    getsockname(new_sock, (struct sockaddr *)&new_local, &new_local_len);

    MUTEX_LOCK(&ci->conn_mutex);

    /* Tell ngtcp2 about migration */
    ngtcp2_path new_path;
    memset(&new_path, 0, sizeof(new_path));
    new_path.local.addr = (struct sockaddr *)&new_local;
    new_path.local.addrlen = new_local_len;
    new_path.remote.addr = (struct sockaddr *)&ci->remote_addr;
    new_path.remote.addrlen = ci->remote_addrlen;

    ngtcp2_addr addr;
    addr.addr = (struct sockaddr *)&new_local;
    addr.addrlen = new_local_len;

    int rv = ngtcp2_conn_initiate_immediate_migration(ci->qconn, &new_path, quic_timestamp());
    if (rv == 0) {
        /* Swap sockets */
        socket_t old_sock = (socket_t)_conn->socket_fd;
        _conn->socket_fd = (long long)new_sock;
        memcpy(&ci->local_addr, &new_local, new_local_len);
        ci->local_addrlen = new_local_len;
        CLOSE_SOCKET(old_sock);

        quic_flush_tx(_conn);
    } else {
        CLOSE_SOCKET(new_sock);
    }

    MUTEX_UNLOCK(&ci->conn_mutex);
    freeaddrinfo(res);
}

char *sn_quic_connection_remote_address(__sn__QuicConnection *conn) {
    if (conn == NULL) return strdup("");
    RtQuicConnection *_conn = (RtQuicConnection *)conn;
    QuicConnectionInternal *ci = conn_internal(_conn);
    if (!ci->remote_addr_str) {
        return strdup("");
    }
    return strdup(ci->remote_addr_str);
}

void sn_quic_connection_close(__sn__QuicConnection *conn) {
    if (conn == NULL) return;
    RtQuicConnection *_conn = (RtQuicConnection *)conn;
    QuicConnectionInternal *ci = conn_internal(_conn);
    if (ci->closed) return;

    MUTEX_LOCK(&ci->conn_mutex);
    ci->closed = true;

    if (ci->qconn) {
        /* Send connection close frame */
        uint8_t buf[QUIC_MAX_PACKET_SIZE];
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi;
        ngtcp2_ccerr ccerr;
        ngtcp2_ccerr_default(&ccerr);

        ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
            ci->qconn, &ps.path, &pi,
            buf, sizeof(buf), &ccerr, quic_timestamp());

        if (nwrite > 0) {
            quic_send_packet(_conn, buf, (size_t)nwrite);
        }
    }

    MUTEX_UNLOCK(&ci->conn_mutex);

    /* Signal all waiting threads */
    COND_BROADCAST(&ci->handshake_cond);
    COND_BROADCAST(&ci->accept_stream_cond);

    /* Signal all streams */
    for (int i = 0; i < ci->stream_count; i++) {
        if (ci->streams[i]) {
            QuicStreamInternal *si = stream_internal(ci->streams[i]);
            MUTEX_LOCK(&si->stream_mutex);
            si->closed = true;
            COND_BROADCAST(&si->read_cond);
            MUTEX_UNLOCK(&si->stream_mutex);
        }
    }

    /* For server connections, we only mark closed and signal waiters.
     * The listener thread may still be using qconn, SSL, and streams,
     * so cleanup is deferred to sn_quic_listener_close() after the
     * listener thread is joined. */
    if (ci->is_server) {
        return;
    }

    /* Save OS resources before destroying */
    SSL *ssl = ci->ssl;
    ngtcp2_crypto_ossl_ctx *ossl_ctx = ci->ossl_ctx;
    SSL_CTX *ssl_ctx = ci->ssl_ctx;
    ngtcp2_conn *qconn = ci->qconn;
    socket_t sock = (socket_t)_conn->socket_fd;
    uint8_t *token = ci->resumption_token;
    bool io_was_running = ci->io_running;
    sn_thread_t io_thread = ci->io_thread;
    int stream_count = ci->stream_count;
    RtQuicStream *streams_copy[QUIC_MAX_STREAMS];
    for (int i = 0; i < stream_count; i++) streams_copy[i] = ci->streams[i];

    /* Stop and join I/O thread (client connections only) */
    if (io_was_running) {
        ci->io_running = false;
#ifdef _WIN32
        WaitForSingleObject(io_thread, 5000);
        CloseHandle(io_thread);
#else
        pthread_join(io_thread, NULL);
#endif
    }

    /* Cleanup OS resources (client connections only) */
    if (ssl) {
        SSL_set_app_data(ssl, NULL);
        SSL_free(ssl);
    }
    if (ossl_ctx) {
        ngtcp2_crypto_ossl_ctx_del(ossl_ctx);
    }
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    if (qconn) {
        ngtcp2_conn_del(qconn);
    }
    if (sock != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(sock);
    }

    /* Free streams */
    for (int i = 0; i < stream_count; i++) {
        quic_stream_free(streams_copy[i]);
    }

    /* Free resumption token (allocated with malloc) */
    if (token) {
        free(token);
    }

    MUTEX_DESTROY(&ci->conn_mutex);
    COND_DESTROY(&ci->handshake_cond);
    COND_DESTROY(&ci->accept_stream_cond);

    /* Free internal state and unregister */
    free(ci);
    conn_unregister(_conn);
}

/* ============================================================================
 * QuicListener API
 * ============================================================================ */

static __sn__QuicListener *quic_listener_create(char *address,
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

    /* Allocate Sindarin struct via compiler-generated __new() */
    RtQuicListener *listener = __sn__QuicListener__new();
    QuicListenerInternal *li = (QuicListenerInternal *)calloc(1, sizeof(QuicListenerInternal));
    listener_register(listener, li);

    listener->socket_fd = (long long)sock;
    listener->bound_port = bound_port;
    li->ssl_ctx = ssl_ctx;
    li->running = true;

    memcpy(&li->local_addr, &bound_addr, bound_len);
    li->local_addrlen = bound_len;

    if (config) {
        li->config = *config;
    } else {
        li->config.max_bidi_streams = QUIC_DEFAULT_MAX_BIDI_STREAMS;
        li->config.max_uni_streams = QUIC_DEFAULT_MAX_UNI_STREAMS;
        li->config.max_stream_window = QUIC_DEFAULT_MAX_STREAM_WINDOW;
        li->config.max_conn_window = QUIC_DEFAULT_MAX_CONN_WINDOW;
        li->config.idle_timeout_ms = QUIC_DEFAULT_IDLE_TIMEOUT_MS;
    }

    MUTEX_INIT(&li->accept_mutex);
    COND_INIT(&li->accept_cond);
    MUTEX_INIT(&li->conn_list_mutex);

    /* Start listener thread */
#ifdef _WIN32
    li->listen_thread = (HANDLE)_beginthreadex(NULL, 0,
        (unsigned (__stdcall *)(void *))quic_listener_thread_entry, listener, 0, NULL);
#else
    pthread_create(&li->listen_thread, NULL, quic_listener_thread_entry, listener);
#endif

    return listener;
}

__sn__QuicListener *sn_quic_listener_bind(char *address,
                                    char *certFile, char *keyFile) {
    return quic_listener_create(address, certFile, keyFile, NULL);
}

__sn__QuicListener *sn_quic_listener_bind_with(char *address,
                                         char *certFile, char *keyFile,
                                         __sn__QuicConfig *config) {
    if (config == NULL) return NULL;
    RtQuicConfig *_config = (RtQuicConfig *)config;
    return quic_listener_create(address, certFile, keyFile, _config);
}

__sn__QuicConnection *sn_quic_listener_accept(__sn__QuicListener *listener) {
    if (listener == NULL) return NULL;
    RtQuicListener *_listener = (RtQuicListener *)listener;
    QuicListenerInternal *li = listener_internal(_listener);


    MUTEX_LOCK(&li->accept_mutex);

    while (li->accept_count == 0 && li->running) {
        COND_WAIT(&li->accept_cond, &li->accept_mutex);
    }

    if (!li->running || li->accept_count == 0) {
        MUTEX_UNLOCK(&li->accept_mutex);
        return NULL;
    }

    RtQuicConnection *conn_q = li->accept_queue_conns[li->accept_head];
    li->accept_head = (li->accept_head + 1) % QUIC_MAX_INCOMING_STREAMS;
    li->accept_count--;

    MUTEX_UNLOCK(&li->accept_mutex);
    return (__sn__QuicConnection *)conn_q;
}

long long sn_quic_listener_get_port(__sn__QuicListener *listener) {
    if (listener == NULL) return 0;
    RtQuicListener *_listener = (RtQuicListener *)listener;
    return _listener->bound_port;
}

void sn_quic_listener_close(__sn__QuicListener *listener) {
    if (listener == NULL) return;
    RtQuicListener *_listener = (RtQuicListener *)listener;
    QuicListenerInternal *li = listener_internal(_listener);
    if (!li->running) return;

    li->running = false;

    /* Signal accept waiters */
    MUTEX_LOCK(&li->accept_mutex);
    COND_BROADCAST(&li->accept_cond);
    MUTEX_UNLOCK(&li->accept_mutex);

    /* Wait for listener thread */
#ifdef _WIN32
    WaitForSingleObject(li->listen_thread, 5000);
    CloseHandle(li->listen_thread);
#else
    pthread_join(li->listen_thread, NULL);
#endif

    /* Mark all server connections as closed (sn_quic_connection_close for
     * server connections just sets closed=true and signals waiters). */
    MUTEX_LOCK(&li->conn_list_mutex);
    for (int i = 0; i < li->connection_count; i++) {
        if (li->connections[i]) {
            QuicConnectionInternal *cci = conn_internal(li->connections[i]);
            if (!cci->closed) {
                sn_quic_connection_close((__sn__QuicConnection *)li->connections[i]);
            }
        }
    }
    MUTEX_UNLOCK(&li->conn_list_mutex);

    /* Now that listener thread is stopped, do full cleanup for all server
     * connections. This was deferred because the listener thread was using
     * these resources (qconn, SSL, streams). */
    for (int i = 0; i < li->connection_count; i++) {
        RtQuicConnection *sconn = li->connections[i];
        if (!sconn) continue;

        QuicConnectionInternal *cci = conn_internal(sconn);

        /* Save OS resources before destroying */
        SSL *conn_ssl = cci->ssl;
        ngtcp2_crypto_ossl_ctx *conn_ossl_ctx = cci->ossl_ctx;
        ngtcp2_conn *conn_qconn = cci->qconn;
        uint8_t *conn_token = cci->resumption_token;
        int conn_stream_count = cci->stream_count;
        RtQuicStream *conn_streams[QUIC_MAX_STREAMS];
        for (int j = 0; j < conn_stream_count; j++) conn_streams[j] = cci->streams[j];

        /* Cleanup SSL (server connections share listener's ssl_ctx, don't free it) */
        if (conn_ssl) {
            SSL_set_app_data(conn_ssl, NULL);
            SSL_free(conn_ssl);
        }
        if (conn_ossl_ctx) {
            ngtcp2_crypto_ossl_ctx_del(conn_ossl_ctx);
        }

        /* Delete ngtcp2 connection */
        if (conn_qconn) {
            ngtcp2_conn_del(conn_qconn);
        }

        /* Free streams */
        for (int j = 0; j < conn_stream_count; j++) {
            quic_stream_free(conn_streams[j]);
        }

        /* Free resumption token (allocated with malloc) */
        if (conn_token) {
            free(conn_token);
        }

        /* Destroy mutex/cond */
        MUTEX_DESTROY(&cci->conn_mutex);
        COND_DESTROY(&cci->handshake_cond);
        COND_DESTROY(&cci->accept_stream_cond);

        /* Free internal state and unregister */
        free(cci);
        conn_unregister(sconn);
    }

    /* Save listener OS resources before destroying */
    SSL_CTX *ssl_ctx = li->ssl_ctx;
    socket_t sock = (socket_t)_listener->socket_fd;

    /* Cleanup OS resources */
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    if (sock != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(sock);
    }

    MUTEX_DESTROY(&li->accept_mutex);
    COND_DESTROY(&li->accept_cond);
    MUTEX_DESTROY(&li->conn_list_mutex);

    /* Free listener internal state and unregister */
    free(li);
    listener_unregister(_listener);
}
