/* ==============================================================================
 * sdk/net/dtls.sn.c - Self-contained DTLS Connection Implementation
 * ==============================================================================
 * This file provides the C implementation for DtlsConnection using OpenSSL.
 * DTLS (Datagram TLS) provides TLS security over UDP datagrams.
 * It is compiled via @source and linked with Sindarin code.
 *
 * Certificate loading priority:
 *   1. SN_CERTS environment variable (path to PEM file or directory)
 *   2. Platform-native certificate store
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* OpenSSL includes */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* Platform-specific socket includes */
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <wincrypt.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "crypt32.lib")

    typedef SOCKET socket_t;
    #define INVALID_SOCKET_VAL INVALID_SOCKET
    #define SOCKET_ERROR_VAL SOCKET_ERROR
    #define CLOSE_SOCKET(s) closesocket(s)
    #define GET_SOCKET_ERROR() WSAGetLastError()
#elif defined(__APPLE__)
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <Security/Security.h>

    typedef int socket_t;
    #define INVALID_SOCKET_VAL (-1)
    #define SOCKET_ERROR_VAL (-1)
    #define CLOSE_SOCKET(s) close(s)
    #define GET_SOCKET_ERROR() errno
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <errno.h>
    #include <fcntl.h>

    typedef int socket_t;
    #define INVALID_SOCKET_VAL (-1)
    #define SOCKET_ERROR_VAL (-1)
    #define CLOSE_SOCKET(s) close(s)
    #define GET_SOCKET_ERROR() errno
#endif

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

typedef __sn__DtlsConnection RtDtlsConnection;
typedef __sn__DtlsListener RtDtlsListener;

/* ============================================================================
 * OpenSSL Initialization (one-time)
 * ============================================================================ */

static int openssl_initialized = 0;

static void ensure_openssl_initialized(void) {
    if (!openssl_initialized) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
#else
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
        openssl_initialized = 1;
    }
}

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
            fprintf(stderr, "DtlsConnection: WSAStartup failed: %d\n", result);
            exit(1);
        }
        winsock_initialized = 1;
    }
}
#else
#define ensure_winsock_initialized() ((void)0)
#endif

/* ============================================================================
 * Certificate Loading
 * ============================================================================ */

#ifdef _WIN32
static int dtls_load_windows_certs(SSL_CTX *ctx) {
    HCERTSTORE hStore = CertOpenSystemStoreA(0, "ROOT");
    if (hStore == NULL) {
        return 0;
    }

    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    PCCERT_CONTEXT pCert = NULL;
    int count = 0;

    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
        const unsigned char *cert_data = pCert->pbCertEncoded;
        X509 *x509 = d2i_X509(NULL, &cert_data, pCert->cbCertEncoded);
        if (x509 != NULL) {
            if (X509_STORE_add_cert(store, x509) == 1) {
                count++;
            }
            X509_free(x509);
        }
    }

    CertCloseStore(hStore, 0);
    return count;
}
#endif

#ifdef __APPLE__
static int dtls_load_macos_certs(SSL_CTX *ctx) {
    CFArrayRef certs = NULL;
    OSStatus status = SecTrustCopyAnchorCertificates(&certs);
    if (status != errSecSuccess || certs == NULL) {
        return 0;
    }

    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    CFIndex cert_count = CFArrayGetCount(certs);
    int loaded = 0;

    for (CFIndex i = 0; i < cert_count; i++) {
        SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
        CFDataRef der_data = SecCertificateCopyData(cert);
        if (der_data == NULL) continue;

        const unsigned char *ptr = CFDataGetBytePtr(der_data);
        CFIndex length = CFDataGetLength(der_data);

        X509 *x509 = d2i_X509(NULL, &ptr, (long)length);
        if (x509 != NULL) {
            if (X509_STORE_add_cert(store, x509) == 1) {
                loaded++;
            }
            X509_free(x509);
        }

        CFRelease(der_data);
    }

    CFRelease(certs);
    return loaded;
}
#endif

static void dtls_load_certificates(SSL_CTX *ctx) {
    /* Priority 1: SN_CERTS environment variable */
    const char *sn_certs = getenv("SN_CERTS");
    if (sn_certs != NULL && sn_certs[0] != '\0') {
        if (SSL_CTX_load_verify_locations(ctx, sn_certs, NULL) == 1) {
            return;
        }
        if (SSL_CTX_load_verify_locations(ctx, NULL, sn_certs) == 1) {
            return;
        }
        fprintf(stderr, "DtlsConnection: warning: SN_CERTS='%s' could not be loaded, "
                "falling back to system certs\n", sn_certs);
    }

    /* Priority 2: Platform-native certificate store */
#ifdef _WIN32
    int count = dtls_load_windows_certs(ctx);
    if (count == 0) {
        fprintf(stderr, "DtlsConnection: warning: no certificates loaded from Windows store\n");
    }
#elif defined(__APPLE__)
    int count = dtls_load_macos_certs(ctx);
    if (count == 0) {
        SSL_CTX_set_default_verify_paths(ctx);
    }
#else
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        fprintf(stderr, "DtlsConnection: warning: failed to load default certificate paths\n");
    }
#endif
}

/* ============================================================================
 * Address Parsing
 * ============================================================================ */

static int dtls_parse_address(const char *address, char *host, size_t host_len, int *port) {
    if (address == NULL) return 0;

    const char *last_colon = NULL;

    /* Handle IPv6 addresses like [::1]:4433 */
    if (address[0] == '[') {
        const char *bracket = strchr(address, ']');
        if (bracket == NULL) return 0;

        size_t ipv6_len = bracket - address - 1;
        if (ipv6_len >= host_len) return 0;

        memcpy(host, address + 1, ipv6_len);
        host[ipv6_len] = '\0';

        if (bracket[1] == ':') {
            *port = atoi(bracket + 2);
        } else {
            *port = 4433; /* Default DTLS port */
        }
        return 1;
    }

    /* Find the last colon (for host:port format) */
    for (const char *p = address; *p; p++) {
        if (*p == ':') last_colon = p;
    }

    if (last_colon == NULL) {
        size_t len = strlen(address);
        if (len >= host_len) return 0;
        strcpy(host, address);
        *port = 4433;
        return 1;
    }

    size_t len = last_colon - address;
    if (len >= host_len) return 0;

    if (len == 0) {
        strcpy(host, "0.0.0.0");
    } else {
        memcpy(host, address, len);
        host[len] = '\0';
    }

    *port = atoi(last_colon + 1);
    return 1;
}

/* ============================================================================
 * Internal: SSL_CTX storage via a small side allocation
 * ============================================================================
 * We store the SSL_CTX* and a "server_conn" flag in a small malloc'd block,
 * pointed to by a global linked list keyed on the connection pointer.
 * For simplicity, we'll embed the SSL_CTX in the connection's ssl_ptr
 * wrapper — but actually the cleanest approach for the minimal runtime
 * is to just allocate a small "extras" struct and store it via the
 * remote_addr field's preceding bytes. That's too hacky.
 *
 * Best approach: store SSL_CTX* in a tiny struct alongside the SSL*.
 * We'll create a wrapper that holds both.
 */

typedef struct {
    SSL *ssl;
    SSL_CTX *ctx;
    bool owns_socket; /* false for server-accepted connections */
} DtlsSslWrapper;

static DtlsSslWrapper *dtls_ssl_wrapper_new(SSL *ssl, SSL_CTX *ctx, bool owns_socket) {
    DtlsSslWrapper *w = (DtlsSslWrapper *)calloc(1, sizeof(DtlsSslWrapper));
    w->ssl = ssl;
    w->ctx = ctx;
    w->owns_socket = owns_socket;
    return w;
}

/* ============================================================================
 * DtlsConnection Connect
 * ============================================================================ */

__sn__DtlsConnection *sn_dtls_connection_connect(char *address) {
    ensure_winsock_initialized();
    ensure_openssl_initialized();

    if (address == NULL) {
        fprintf(stderr, "DtlsConnection.connect: NULL address\n");
        exit(1);
    }

    char host[256];
    int port;

    if (!dtls_parse_address(address, host, sizeof(host), &port)) {
        fprintf(stderr, "DtlsConnection.connect: invalid address format '%s'\n", address);
        exit(1);
    }

    /* --- UDP Connection --- */

    struct addrinfo hints, *result, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;  /* UDP */

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int status = getaddrinfo(host, port_str, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "DtlsConnection.connect: DNS resolution failed for '%s': %s\n",
                host, gai_strerror(status));
        exit(1);
    }

    socket_t sock = INVALID_SOCKET_VAL;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == INVALID_SOCKET_VAL) continue;

        if (connect(sock, rp->ai_addr, (int)rp->ai_addrlen) != SOCKET_ERROR_VAL) {
            break;
        }

        CLOSE_SOCKET(sock);
        sock = INVALID_SOCKET_VAL;
    }

    freeaddrinfo(result);

    if (sock == INVALID_SOCKET_VAL) {
        fprintf(stderr, "DtlsConnection.connect: UDP socket creation failed for '%s'\n", address);
        exit(1);
    }

    /* --- DTLS Handshake --- */

    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    if (ctx == NULL) {
        CLOSE_SOCKET(sock);
        fprintf(stderr, "DtlsConnection.connect: SSL_CTX_new failed\n");
        exit(1);
    }

    /* Load certificates */
    dtls_load_certificates(ctx);

    /* If SN_CERTS is set, verify peer; otherwise skip verification */
    const char *sn_certs_env = getenv("SN_CERTS");
    if (sn_certs_env != NULL && sn_certs_env[0] != '\0') {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        SSL_CTX_free(ctx);
        CLOSE_SOCKET(sock);
        fprintf(stderr, "DtlsConnection.connect: SSL_new failed\n");
        exit(1);
    }

    /* Set SNI hostname and enable hostname verification (only when verifying) */
    if (sn_certs_env != NULL && sn_certs_env[0] != '\0') {
        SSL_set_tlsext_host_name(ssl, host);
        SSL_set1_host(ssl, host);
    }

    /* Create BIO from connected socket for DTLS */
    BIO *bio = BIO_new_dgram((int)sock, BIO_NOCLOSE);
    if (bio == NULL) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        CLOSE_SOCKET(sock);
        fprintf(stderr, "DtlsConnection.connect: BIO_new_dgram failed\n");
        exit(1);
    }

    /* Set the connected peer address on the BIO */
    {
        struct addrinfo *peer_result;
        struct addrinfo peer_hints;
        memset(&peer_hints, 0, sizeof(peer_hints));
        peer_hints.ai_family = AF_UNSPEC;
        peer_hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(host, port_str, &peer_hints, &peer_result) == 0) {
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, peer_result->ai_addr);
            freeaddrinfo(peer_result);
        }
    }

    SSL_set_bio(ssl, bio, bio);

    /* Set DTLS timeout for retransmission */
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);

    /* Perform DTLS handshake */
    int ssl_result = SSL_connect(ssl);
    if (ssl_result != 1) {
        int ssl_err = SSL_get_error(ssl, ssl_result);
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));

        SSL_free(ssl);
        SSL_CTX_free(ctx);
        CLOSE_SOCKET(sock);

        if (ssl_err == SSL_ERROR_SSL) {
            fprintf(stderr, "DtlsConnection.connect: DTLS handshake failed for '%s': %s\n",
                    address, err_buf);
        } else {
            fprintf(stderr, "DtlsConnection.connect: DTLS handshake failed for '%s' (error %d)\n",
                    address, ssl_err);
        }
        exit(1);
    }

    /* Verify certificate was validated (only when verification is enabled) */
    if (sn_certs_env != NULL && sn_certs_env[0] != '\0') {
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result != X509_V_OK) {
            const char *verify_str = X509_verify_cert_error_string(verify_result);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            CLOSE_SOCKET(sock);
            fprintf(stderr, "DtlsConnection.connect: certificate verification failed for '%s': %s\n",
                    address, verify_str);
            exit(1);
        }
    }

    /* Allocate and return connection */
    __sn__DtlsConnection *conn = (__sn__DtlsConnection *)calloc(1, sizeof(__sn__DtlsConnection));
    if (conn == NULL) {
        fprintf(stderr, "DtlsConnection.connect: allocation failed\n");
        exit(1);
    }

    conn->socket_fd = (long long)sock;
    conn->ssl_ptr = dtls_ssl_wrapper_new(ssl, ctx, true);
    conn->remote_addr = strdup(address);

    return conn;
}

/* ============================================================================
 * DtlsConnection Send/Receive
 * ============================================================================ */

/* Send an encrypted datagram, return bytes sent */
long long sn_dtls_connection_send(__sn__DtlsConnection *conn, SnArray *data) {
    if (conn == NULL || data == NULL) return 0;

    if (data->len == 0) return 0;

    DtlsSslWrapper *w = (DtlsSslWrapper *)conn->ssl_ptr;
    SSL *ssl = w->ssl;
    int bytes_sent = SSL_write(ssl, data->data, (int)data->len);

    if (bytes_sent <= 0) {
        int ssl_err = SSL_get_error(ssl, bytes_sent);
        fprintf(stderr, "DtlsConnection.send: SSL_write failed (error %d)\n", ssl_err);
        exit(1);
    }

    return (long long)bytes_sent;
}

/* Receive an encrypted datagram (up to maxBytes) */
SnArray *sn_dtls_connection_receive(__sn__DtlsConnection *conn, long long maxBytes) {
    if (conn == NULL || maxBytes <= 0) {
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
    }

    DtlsSslWrapper *w = (DtlsSslWrapper *)conn->ssl_ptr;
    SSL *ssl = w->ssl;

    /* Allocate a temporary buffer for receiving */
    unsigned char *temp = (unsigned char *)malloc((size_t)maxBytes);
    if (temp == NULL) {
        fprintf(stderr, "DtlsConnection.receive: malloc failed\n");
        exit(1);
    }

    int n = SSL_read(ssl, temp, (int)maxBytes);

    if (n <= 0) {
        int ssl_err = SSL_get_error(ssl, n);
        free(temp);

        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;

        if (ssl_err == SSL_ERROR_ZERO_RETURN || ssl_err == SSL_ERROR_WANT_READ) {
            return arr;
        } else {
            fprintf(stderr, "DtlsConnection.receive: SSL_read failed (error %d)\n", ssl_err);
            exit(1);
        }
    }

    /* Create SnArray with received data */
    SnArray *arr = sn_array_new(sizeof(unsigned char), (long long)n);
    arr->elem_tag = SN_TAG_BYTE;
    for (int i = 0; i < n; i++) {
        sn_array_push(arr, &temp[i]);
    }
    free(temp);

    return arr;
}

/* ============================================================================
 * DtlsConnection Getters
 * ============================================================================ */

char *sn_dtls_connection_get_remote_address(__sn__DtlsConnection *conn) {
    if (conn == NULL || conn->remote_addr == NULL) {
        return strdup("");
    }
    return strdup((char *)conn->remote_addr);
}

/* ============================================================================
 * DtlsConnection Lifecycle
 * ============================================================================ */

void sn_dtls_connection_close(__sn__DtlsConnection *conn) {
    if (conn == NULL) return;

    DtlsSslWrapper *w = (DtlsSslWrapper *)conn->ssl_ptr;
    if (w != NULL) {
        if (w->ssl != NULL) {
            SSL_shutdown(w->ssl);
            SSL_free(w->ssl);
        }
        if (w->ctx != NULL) {
            SSL_CTX_free(w->ctx);
        }
        if (w->owns_socket && (socket_t)conn->socket_fd != INVALID_SOCKET_VAL) {
            CLOSE_SOCKET((socket_t)conn->socket_fd);
        }
        free(w);
    }

    conn->ssl_ptr = NULL;
    conn->socket_fd = (long long)INVALID_SOCKET_VAL;
}

/* ============================================================================
 * Threading Primitives (same pattern as QUIC)
 * ============================================================================ */

#ifdef _WIN32
    #include <process.h>
    typedef HANDLE dtls_thread_t;
    typedef CRITICAL_SECTION dtls_mutex_t;
    typedef CONDITION_VARIABLE dtls_cond_t;

    #define DTLS_MUTEX_INIT(m) InitializeCriticalSection(m)
    #define DTLS_MUTEX_LOCK(m) EnterCriticalSection(m)
    #define DTLS_MUTEX_UNLOCK(m) LeaveCriticalSection(m)
    #define DTLS_MUTEX_DESTROY(m) DeleteCriticalSection(m)
    #define DTLS_COND_INIT(c) InitializeConditionVariable(c)
    #define DTLS_COND_WAIT(c, m) SleepConditionVariableCS(c, m, INFINITE)
    #define DTLS_COND_SIGNAL(c) WakeConditionVariable(c)
    #define DTLS_COND_BROADCAST(c) WakeAllConditionVariable(c)
    #define DTLS_COND_DESTROY(c) /* no-op on Windows */
#else
    #include <pthread.h>
    typedef pthread_t dtls_thread_t;
    typedef pthread_mutex_t dtls_mutex_t;
    typedef pthread_cond_t dtls_cond_t;

    #define DTLS_MUTEX_INIT(m) pthread_mutex_init(m, NULL)
    #define DTLS_MUTEX_LOCK(m) pthread_mutex_lock(m)
    #define DTLS_MUTEX_UNLOCK(m) pthread_mutex_unlock(m)
    #define DTLS_MUTEX_DESTROY(m) pthread_mutex_destroy(m)
    #define DTLS_COND_INIT(c) pthread_cond_init(c, NULL)
    #define DTLS_COND_WAIT(c, m) pthread_cond_wait(c, m)
    #define DTLS_COND_SIGNAL(c) pthread_cond_signal(c)
    #define DTLS_COND_BROADCAST(c) pthread_cond_broadcast(c)
    #define DTLS_COND_DESTROY(c) pthread_cond_destroy(c)
#endif

/* ============================================================================
 * DtlsListener Internal Data
 * ============================================================================ */

#define DTLS_MAX_ACCEPT_QUEUE 16

typedef struct DtlsListenerData {
    socket_t socket_fd;
    long long bound_port;
    SSL_CTX *ssl_ctx;
    bool running;

    /* Accept queue (thread-safe) */
    __sn__DtlsConnection *accept_queue[DTLS_MAX_ACCEPT_QUEUE];
    int accept_head;
    int accept_tail;
    int accept_count;
    dtls_mutex_t accept_mutex;
    dtls_cond_t accept_cond;

    /* Listener thread */
    dtls_thread_t listen_thread;
} DtlsListenerData;

/* File-scope mapping from listener -> internal data */
static DtlsListenerData *g_dtls_ld[16] = {0};
static __sn__DtlsListener *g_dtls_ls[16] = {0};
static int g_dtls_ld_count = 0;

static void dtls_register_listener(__sn__DtlsListener *listener, DtlsListenerData *ld) {
    if (g_dtls_ld_count < 16) {
        g_dtls_ls[g_dtls_ld_count] = listener;
        g_dtls_ld[g_dtls_ld_count] = ld;
        g_dtls_ld_count++;
    }
}

static DtlsListenerData *dtls_find_listener_data(__sn__DtlsListener *listener) {
    for (int i = 0; i < g_dtls_ld_count; i++) {
        if (g_dtls_ls[i] == listener) return g_dtls_ld[i];
    }
    return NULL;
}

/* ============================================================================
 * DtlsListener Thread Function
 * ============================================================================ */

static void dtls_listener_thread_func(DtlsListenerData *ld) {
    while (ld->running) {
        struct sockaddr_storage client_ss;
        socklen_t client_len = sizeof(client_ss);
        unsigned char peek_buf[65535];

#ifdef _WIN32
        int nread = recvfrom(ld->socket_fd, (char *)peek_buf, sizeof(peek_buf), MSG_PEEK,
                            (struct sockaddr *)&client_ss, &client_len);
#else
        ssize_t nread = recvfrom(ld->socket_fd, peek_buf, sizeof(peek_buf), MSG_PEEK,
                                 (struct sockaddr *)&client_ss, &client_len);
#endif
        if (nread < 0) {
            if (!ld->running) break;
            continue;
        }
        if (!ld->running) break;

        if (connect(ld->socket_fd, (struct sockaddr *)&client_ss, client_len) != 0) {
            unsigned char discard[1];
            recv(ld->socket_fd, (char *)discard, sizeof(discard), 0);
            continue;
        }

        SSL *ssl = SSL_new(ld->ssl_ctx);
        if (ssl == NULL) {
            if (ld->running) {
                fprintf(stderr, "DtlsListener: SSL_new failed\n");
            }
            break;
        }

        BIO *bio = BIO_new_dgram((int)ld->socket_fd, BIO_NOCLOSE);
        if (bio == NULL) {
            SSL_free(ssl);
            break;
        }

        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_ss);

        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);

        SSL_set_bio(ssl, bio, bio);

        int accept_ret = SSL_accept(ssl);
        if (accept_ret != 1) {
            SSL_free(ssl);
            if (!ld->running) break;
            struct sockaddr_in unspec;
            memset(&unspec, 0, sizeof(unspec));
            unspec.sin_family = AF_UNSPEC;
            connect(ld->socket_fd, (struct sockaddr *)&unspec, sizeof(unspec));
            continue;
        }

        /* Build remote address string */
        char addr_str[256];
        if (client_ss.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&client_ss;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            snprintf(addr_str, sizeof(addr_str), "%s:%d", ip, ntohs(sin->sin_port));
        } else {
            snprintf(addr_str, sizeof(addr_str), "unknown:0");
        }

        /* Create DtlsConnection */
        __sn__DtlsConnection *conn = (__sn__DtlsConnection *)calloc(1, sizeof(__sn__DtlsConnection));
        if (conn == NULL) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            continue;
        }

        conn->socket_fd = (long long)INVALID_SOCKET_VAL; /* Don't own the socket */
        conn->ssl_ptr = dtls_ssl_wrapper_new(ssl, NULL, false); /* Server conn doesn't own ctx */
        conn->remote_addr = strdup(addr_str);

        /* Push to accept queue */
        DTLS_MUTEX_LOCK(&ld->accept_mutex);
        if (ld->accept_count < DTLS_MAX_ACCEPT_QUEUE) {
            ld->accept_queue[ld->accept_tail] = conn;
            ld->accept_tail = (ld->accept_tail + 1) % DTLS_MAX_ACCEPT_QUEUE;
            ld->accept_count++;
            DTLS_COND_SIGNAL(&ld->accept_cond);
        } else {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            DtlsSslWrapper *w = (DtlsSslWrapper *)conn->ssl_ptr;
            free(w);
            conn->ssl_ptr = NULL;
        }
        DTLS_MUTEX_UNLOCK(&ld->accept_mutex);

        break;
    }
}

#ifdef _WIN32
static unsigned __stdcall dtls_listener_thread_entry(void *arg) {
    DtlsListenerData *ld = (DtlsListenerData *)arg;
    dtls_listener_thread_func(ld);
    return 0;
}
#else
static void *dtls_listener_thread_entry(void *arg) {
    DtlsListenerData *ld = (DtlsListenerData *)arg;
    dtls_listener_thread_func(ld);
    return NULL;
}
#endif

/* ============================================================================
 * DtlsListener Bind
 * ============================================================================ */

__sn__DtlsListener *sn_dtls_listener_bind(char *address, char *cert_file, char *key_file) {
    ensure_winsock_initialized();
    ensure_openssl_initialized();

    if (address == NULL || cert_file == NULL || key_file == NULL) {
        fprintf(stderr, "DtlsListener.bind: NULL argument\n");
        exit(1);
    }

    char host[256];
    int port;

    if (!dtls_parse_address(address, host, sizeof(host), &port)) {
        fprintf(stderr, "DtlsListener.bind: invalid address format '%s'\n", address);
        exit(1);
    }

    /* Create server SSL context */
    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "DtlsListener.bind: SSL_CTX_new failed\n");
        exit(1);
    }

    /* Load certificate */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        SSL_CTX_free(ctx);
        fprintf(stderr, "DtlsListener.bind: failed to load certificate '%s': %s\n",
                cert_file, err_buf);
        exit(1);
    }

    /* Load private key */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        SSL_CTX_free(ctx);
        fprintf(stderr, "DtlsListener.bind: failed to load private key '%s': %s\n",
                key_file, err_buf);
        exit(1);
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        fprintf(stderr, "DtlsListener.bind: private key does not match certificate\n");
        exit(1);
    }

    /* Create and bind UDP socket */
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int status = getaddrinfo(host[0] ? host : NULL, port_str, &hints, &result);
    if (status != 0) {
        SSL_CTX_free(ctx);
        fprintf(stderr, "DtlsListener.bind: getaddrinfo failed: %s\n", gai_strerror(status));
        exit(1);
    }

    socket_t sock = socket(result->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET_VAL) {
        freeaddrinfo(result);
        SSL_CTX_free(ctx);
        fprintf(stderr, "DtlsListener.bind: socket creation failed\n");
        exit(1);
    }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval, sizeof(optval));

    if (bind(sock, result->ai_addr, (int)result->ai_addrlen) != 0) {
        freeaddrinfo(result);
        CLOSE_SOCKET(sock);
        SSL_CTX_free(ctx);
        fprintf(stderr, "DtlsListener.bind: bind failed on '%s'\n", address);
        exit(1);
    }

    freeaddrinfo(result);

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

    /* Create listener internal data */
    DtlsListenerData *ld = (DtlsListenerData *)calloc(1, sizeof(DtlsListenerData));
    if (ld == NULL) {
        CLOSE_SOCKET(sock);
        SSL_CTX_free(ctx);
        fprintf(stderr, "DtlsListener.bind: allocation failed\n");
        exit(1);
    }

    ld->socket_fd = sock;
    ld->bound_port = bound_port;
    ld->ssl_ctx = ctx;
    ld->running = true;

    /* Set receive timeout on listener socket so thread can check running flag */
#ifdef _WIN32
    DWORD tv_ms = 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_ms, sizeof(tv_ms));
#else
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    DTLS_MUTEX_INIT(&ld->accept_mutex);
    DTLS_COND_INIT(&ld->accept_cond);

    /* Start listener thread */
#ifdef _WIN32
    ld->listen_thread = (HANDLE)_beginthreadex(NULL, 0,
        dtls_listener_thread_entry, ld, 0, NULL);
#else
    pthread_create(&ld->listen_thread, NULL, dtls_listener_thread_entry, ld);
#endif

    /* Create the Sindarin-visible listener struct */
    __sn__DtlsListener *listener = (__sn__DtlsListener *)calloc(1, sizeof(__sn__DtlsListener));
    if (listener == NULL) {
        fprintf(stderr, "DtlsListener.bind: allocation failed\n");
        exit(1);
    }

    listener->socket_fd = (long long)sock;
    listener->bound_port = (long long)bound_port;

    /* Store internal data pointer — we'll use a global side-table or just
     * stash it somewhere accessible. Use SSL_CTX ex_data or a simple approach:
     * store the DtlsListenerData pointer in the __sn__DtlsListener via a cast trick.
     * Actually, we need a way to get from listener -> ld. We'll store ld as a
     * void* in a global array keyed by listener pointer. For simplicity,
     * let's use a thread-local or static approach. Since there are few listeners,
     * a simple linked list works. */

    /* Simplest: store ld pointer as the socket_fd is already stored in ld,
     * so we can use a static lookup. But that's fragile. Better: store ld
     * pointer directly. We can use a global table or just embed it.
     *
     * For the minimal runtime, the cleanest pattern is to use a simple
     * global mapping. Let's use a small static array. */

    dtls_register_listener(listener, ld);

    return listener;
}

/* ============================================================================
 * DtlsListener Accept (blocks until a connection is available)
 * ============================================================================ */

__sn__DtlsConnection *sn_dtls_listener_accept(__sn__DtlsListener *listener) {
    if (listener == NULL) {
        fprintf(stderr, "DtlsListener.accept: listener is NULL or closed\n");
        exit(1);
    }
    DtlsListenerData *ld = dtls_find_listener_data(listener);
    if (ld == NULL || !ld->running) {
        fprintf(stderr, "DtlsListener.accept: listener is NULL or closed\n");
        exit(1);
    }

    DTLS_MUTEX_LOCK(&ld->accept_mutex);

    while (ld->accept_count == 0 && ld->running) {
        DTLS_COND_WAIT(&ld->accept_cond, &ld->accept_mutex);
    }

    if (!ld->running || ld->accept_count == 0) {
        DTLS_MUTEX_UNLOCK(&ld->accept_mutex);
        return NULL;
    }

    __sn__DtlsConnection *conn = ld->accept_queue[ld->accept_head];
    ld->accept_head = (ld->accept_head + 1) % DTLS_MAX_ACCEPT_QUEUE;
    ld->accept_count--;

    DTLS_MUTEX_UNLOCK(&ld->accept_mutex);
    return conn;
}

/* ============================================================================
 * DtlsListener Getters
 * ============================================================================ */

long long sn_dtls_listener_get_port(__sn__DtlsListener *listener) {
    if (listener == NULL) return 0;
    return listener->bound_port;
}

/* ============================================================================
 * DtlsListener Lifecycle
 * ============================================================================ */

void sn_dtls_listener_close(__sn__DtlsListener *listener) {
    if (listener == NULL) return;
    DtlsListenerData *ld = dtls_find_listener_data(listener);
    if (ld == NULL || !ld->running) return;

    ld->running = false;

    /* Signal any waiters on accept */
    DTLS_MUTEX_LOCK(&ld->accept_mutex);
    DTLS_COND_BROADCAST(&ld->accept_cond);
    DTLS_MUTEX_UNLOCK(&ld->accept_mutex);

    /* Close socket first to unblock recvfrom in the thread */
    if (ld->socket_fd != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(ld->socket_fd);
        ld->socket_fd = INVALID_SOCKET_VAL;
    }

    /* Wait for listener thread */
#ifdef _WIN32
    WaitForSingleObject(ld->listen_thread, 5000);
    CloseHandle(ld->listen_thread);
#else
    pthread_join(ld->listen_thread, NULL);
#endif

    if (ld->ssl_ctx != NULL) {
        SSL_CTX_free(ld->ssl_ctx);
    }

    DTLS_MUTEX_DESTROY(&ld->accept_mutex);
    DTLS_COND_DESTROY(&ld->accept_cond);

    free(ld);
}
