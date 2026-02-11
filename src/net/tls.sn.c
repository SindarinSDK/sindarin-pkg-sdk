/* ==============================================================================
 * sdk/net/tls.sn.c - Self-contained TLS Stream Implementation
 * ==============================================================================
 * This file provides the C implementation for TlsStream using OpenSSL.
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

/* Include runtime for proper memory management */
#include "runtime/array/runtime_array_v2.h"
#include "runtime/string/runtime_string_v2.h"

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
    #include <signal.h>
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
    #include <signal.h>

    typedef int socket_t;
    #define INVALID_SOCKET_VAL (-1)
    #define SOCKET_ERROR_VAL (-1)
    #define CLOSE_SOCKET(s) close(s)
    #define GET_SOCKET_ERROR() errno
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

#define SN_TLS_DEFAULT_BUFFER_SIZE 8192

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

typedef struct RtTlsStream {
    socket_t socket_fd;         /* Underlying socket file descriptor */
    void *ssl_ptr;              /* SSL* - opaque to Sindarin */
    char *remote_addr;          /* Remote address string (host:port) */

    /* SSL context - owned per connection */
    SSL_CTX *ctx;

    /* Read buffer - arena allocated */
    unsigned char *read_buf;    /* Buffer storage */
    size_t read_buf_capacity;   /* Total buffer size */
    size_t read_buf_pos;        /* Current read position */
    size_t read_buf_end;        /* End of valid data */

    bool eof_reached;           /* True if SSL connection closed */
} RtTlsStream;

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
#ifndef _WIN32
        /* Ignore SIGPIPE to prevent crashes when writing to closed connections */
        signal(SIGPIPE, SIG_IGN);
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
            fprintf(stderr, "TlsStream: WSAStartup failed: %d\n", result);
            exit(1);
        }
        winsock_initialized = 1;
    }
}
#else
#define ensure_winsock_initialized() ((void)0)
#endif

/* ============================================================================
 * Internal Buffer Management
 * ============================================================================ */

static inline size_t tls_stream_buffered(RtTlsStream *stream) {
    return stream->read_buf_end - stream->read_buf_pos;
}

static inline size_t tls_stream_space(RtTlsStream *stream) {
    return stream->read_buf_capacity - stream->read_buf_end;
}

static void tls_stream_compact(RtTlsStream *stream) {
    size_t buffered = tls_stream_buffered(stream);
    if (buffered > 0 && stream->read_buf_pos > 0) {
        memmove(stream->read_buf,
                stream->read_buf + stream->read_buf_pos,
                buffered);
    }
    stream->read_buf_pos = 0;
    stream->read_buf_end = buffered;
}

/* Fill buffer from SSL connection.
 * Returns: >0 bytes read, 0 on EOF, -1 on error */
static int tls_stream_fill(RtTlsStream *stream) {
    if (stream->eof_reached) {
        return 0;
    }

    /* Compact if we've consumed more than half the buffer */
    if (stream->read_buf_pos > stream->read_buf_capacity / 2) {
        tls_stream_compact(stream);
    }

    /* If buffer is full, compact to make room */
    size_t space = tls_stream_space(stream);
    if (space == 0) {
        tls_stream_compact(stream);
        space = tls_stream_space(stream);
        if (space == 0) {
            return -1;
        }
    }

    SSL *ssl = (SSL *)stream->ssl_ptr;
    int n = SSL_read(ssl, stream->read_buf + stream->read_buf_end, (int)space);

    if (n > 0) {
        stream->read_buf_end += n;
    } else {
        int ssl_err = SSL_get_error(ssl, n);
        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            stream->eof_reached = true;
            return 0;
        } else if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            return 0; /* Retry needed */
        } else if (ssl_err == SSL_ERROR_SYSCALL && ERR_peek_error() == 0) {
            /* Peer disconnected without close_notify - treat as EOF */
            stream->eof_reached = true;
            return 0;
        } else {
            return -1; /* Error */
        }
    }

    return n;
}

static inline void tls_stream_consume(RtTlsStream *stream, size_t n) {
    stream->read_buf_pos += n;
    if (stream->read_buf_pos >= stream->read_buf_end) {
        stream->read_buf_pos = 0;
        stream->read_buf_end = 0;
    }
}

/* ============================================================================
 * Certificate Loading
 * ============================================================================ */

#ifdef _WIN32
/* Load certificates from Windows Certificate Store into SSL_CTX */
static int load_windows_certs(SSL_CTX *ctx) {
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
/* Load certificates from macOS System Keychain into SSL_CTX */
static int load_macos_certs(SSL_CTX *ctx) {
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

/* Load certificates into SSL_CTX using priority:
 * 1. SN_CERTS env var
 * 2. Platform-native cert store */
static void load_certificates(SSL_CTX *ctx) {
    /* Priority 1: SN_CERTS environment variable */
    const char *sn_certs = getenv("SN_CERTS");
    if (sn_certs != NULL && sn_certs[0] != '\0') {
        /* Try as file first, then as directory */
        if (SSL_CTX_load_verify_locations(ctx, sn_certs, NULL) == 1) {
            return;
        }
        if (SSL_CTX_load_verify_locations(ctx, NULL, sn_certs) == 1) {
            return;
        }
        fprintf(stderr, "TlsStream: warning: SN_CERTS='%s' could not be loaded, "
                "falling back to system certs\n", sn_certs);
    }

    /* Priority 2: Platform-native certificate store */
#ifdef _WIN32
    int count = load_windows_certs(ctx);
    if (count == 0) {
        fprintf(stderr, "TlsStream: warning: no certificates loaded from Windows store\n");
    }
#elif defined(__APPLE__)
    int count = load_macos_certs(ctx);
    if (count == 0) {
        /* Fall back to OpenSSL default paths */
        SSL_CTX_set_default_verify_paths(ctx);
    }
#else
    /* Linux: use OpenSSL's built-in default path probing */
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        fprintf(stderr, "TlsStream: warning: failed to load default certificate paths\n");
    }
#endif
}

/* ============================================================================
 * Address Parsing (same format as TCP)
 * ============================================================================ */

static int tls_parse_address(const char *address, char *host, size_t host_len, int *port) {
    if (address == NULL) return 0;

    const char *last_colon = NULL;

    /* Handle IPv6 addresses like [::1]:8080 */
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
            /* Default to 443 for TLS */
            *port = 443;
        }
        return 1;
    }

    /* Find the last colon (for host:port format) */
    for (const char *p = address; *p; p++) {
        if (*p == ':') last_colon = p;
    }

    if (last_colon == NULL) {
        /* No port specified - use hostname as-is with default port 443 */
        size_t len = strlen(address);
        if (len >= host_len) return 0;
        strcpy(host, address);
        *port = 443;
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
 * TlsStream Creation
 * ============================================================================ */

static RtTlsStream *sn_tls_stream_create(RtArenaV2 *arena, socket_t sock,
                                           SSL_CTX *ctx, SSL *ssl,
                                           const char *remote_addr) {
    RtHandleV2 *_stream_h = rt_arena_v2_alloc(arena, sizeof(RtTlsStream));
    rt_handle_v2_pin(_stream_h);
    RtTlsStream *stream = (RtTlsStream *)_stream_h->ptr;
    if (stream == NULL) {
        fprintf(stderr, "TlsStream: allocation failed\n");
        exit(1);
    }

    stream->socket_fd = sock;
    stream->ssl_ptr = ssl;
    stream->ctx = ctx;

    /* Initialize read buffer */
    stream->read_buf_capacity = SN_TLS_DEFAULT_BUFFER_SIZE;
    RtHandleV2 *_buf_h = rt_arena_v2_alloc(arena, stream->read_buf_capacity);
    rt_handle_v2_pin(_buf_h);
    stream->read_buf = (unsigned char *)_buf_h->ptr;
    if (stream->read_buf == NULL) {
        fprintf(stderr, "TlsStream: buffer allocation failed\n");
        exit(1);
    }
    stream->read_buf_pos = 0;
    stream->read_buf_end = 0;
    stream->eof_reached = false;

    /* Copy remote address string */
    if (remote_addr) {
        size_t len = strlen(remote_addr) + 1;
        RtHandleV2 *_addr_h = rt_arena_v2_alloc(arena, len);
        rt_handle_v2_pin(_addr_h);
        stream->remote_addr = (char *)_addr_h->ptr;
        if (stream->remote_addr) {
            memcpy(stream->remote_addr, remote_addr, len);
        }
    } else {
        stream->remote_addr = NULL;
    }

    return stream;
}

/* ============================================================================
 * TlsStream Connect
 * ============================================================================ */

RtTlsStream *sn_tls_stream_connect(RtArenaV2 *arena, const char *address) {
    ensure_winsock_initialized();
    ensure_openssl_initialized();

    if (address == NULL) {
        fprintf(stderr, "TlsStream.connect: NULL address\n");
        exit(1);
    }

    char host[256];
    int port;

    if (!tls_parse_address(address, host, sizeof(host), &port)) {
        fprintf(stderr, "TlsStream.connect: invalid address format '%s'\n", address);
        exit(1);
    }

    /* --- TCP Connection --- */

    struct addrinfo hints, *result, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int status = getaddrinfo(host, port_str, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "TlsStream.connect: DNS resolution failed for '%s': %s\n",
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
        fprintf(stderr, "TlsStream.connect: TCP connection failed to '%s'\n", address);
        exit(1);
    }

    /* --- TLS Handshake --- */

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        CLOSE_SOCKET(sock);
        fprintf(stderr, "TlsStream.connect: SSL_CTX_new failed\n");
        exit(1);
    }

    /* Load certificates */
    load_certificates(ctx);

    /* Enable certificate verification */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        SSL_CTX_free(ctx);
        CLOSE_SOCKET(sock);
        fprintf(stderr, "TlsStream.connect: SSL_new failed\n");
        exit(1);
    }

    /* Set SNI hostname */
    SSL_set_tlsext_host_name(ssl, host);

    /* Enable hostname verification */
    SSL_set1_host(ssl, host);

    /* Attach socket to SSL */
    if (SSL_set_fd(ssl, (int)sock) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        CLOSE_SOCKET(sock);
        fprintf(stderr, "TlsStream.connect: SSL_set_fd failed\n");
        exit(1);
    }

    /* Perform TLS handshake */
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
            fprintf(stderr, "TlsStream.connect: TLS handshake failed for '%s': %s\n",
                    address, err_buf);
        } else {
            fprintf(stderr, "TlsStream.connect: TLS handshake failed for '%s' (error %d)\n",
                    address, ssl_err);
        }
        exit(1);
    }

    /* Verify certificate was validated */
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        const char *verify_str = X509_verify_cert_error_string(verify_result);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        CLOSE_SOCKET(sock);
        fprintf(stderr, "TlsStream.connect: certificate verification failed for '%s': %s\n",
                address, verify_str);
        exit(1);
    }

    return sn_tls_stream_create(arena, sock, ctx, ssl, address);
}

/* ============================================================================
 * TlsStream Read Operations
 * ============================================================================ */

/* Read up to maxBytes (may return fewer) */
RtHandleV2 *sn_tls_stream_read(RtArenaV2 *arena, RtTlsStream *stream, long maxBytes) {
    if (stream == NULL || maxBytes <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    /* If buffer is empty, fill it */
    if (tls_stream_buffered(stream) == 0 && !stream->eof_reached) {
        int n = tls_stream_fill(stream);
        if (n < 0) {
            fprintf(stderr, "TlsStream.read: SSL_read failed\n");
            exit(1);
        }
    }

    /* Return what we have (up to maxBytes) */
    size_t available = tls_stream_buffered(stream);
    size_t to_read = ((size_t)maxBytes < available) ? (size_t)maxBytes : available;

    RtHandleV2 *result = rt_array_create_generic_v2(arena, to_read, sizeof(unsigned char),
                                              stream->read_buf + stream->read_buf_pos);
    tls_stream_consume(stream, to_read);

    return result;
}

/* Read until connection closes */
RtHandleV2 *sn_tls_stream_read_all(RtArenaV2 *arena, RtTlsStream *stream) {
    if (stream == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    size_t capacity = 4096;
    size_t total_read = 0;
    unsigned char *temp_buffer = (unsigned char *)malloc(capacity);

    if (temp_buffer == NULL) {
        fprintf(stderr, "TlsStream.readAll: malloc failed\n");
        exit(1);
    }

    while (!stream->eof_reached) {
        if (tls_stream_buffered(stream) == 0) {
            int n = tls_stream_fill(stream);
            if (n < 0) {
                free(temp_buffer);
                fprintf(stderr, "TlsStream.readAll: SSL_read failed\n");
                exit(1);
            }
            if (n == 0 && tls_stream_buffered(stream) == 0) {
                break;
            }
        }

        size_t available = tls_stream_buffered(stream);
        if (available > 0) {
            /* Grow temp buffer if needed */
            while (total_read + available > capacity) {
                capacity *= 2;
                unsigned char *new_buffer = (unsigned char *)realloc(temp_buffer, capacity);
                if (new_buffer == NULL) {
                    free(temp_buffer);
                    fprintf(stderr, "TlsStream.readAll: realloc failed\n");
                    exit(1);
                }
                temp_buffer = new_buffer;
            }

            memcpy(temp_buffer + total_read,
                   stream->read_buf + stream->read_buf_pos,
                   available);
            total_read += available;
            tls_stream_consume(stream, available);
        }
    }

    RtHandleV2 *result = rt_array_create_generic_v2(arena, total_read, sizeof(unsigned char), temp_buffer);
    free(temp_buffer);

    return result;
}

/* Read until newline */
RtHandleV2 *sn_tls_stream_read_line(RtArenaV2 *arena, RtTlsStream *stream) {
    if (stream == NULL) {
        return rt_arena_v2_strdup(arena, "");
    }

    size_t accum_capacity = 0;
    size_t accum_len = 0;
    char *accum_buffer = NULL;

    while (1) {
        /* Scan buffer for newline */
        for (size_t i = stream->read_buf_pos; i < stream->read_buf_end; i++) {
            unsigned char ch = stream->read_buf[i];

            if (ch == '\n') {
                size_t chunk_len = i - stream->read_buf_pos;
                size_t total_len = accum_len + chunk_len;

                /* Strip trailing \r */
                if (chunk_len > 0 && stream->read_buf[i - 1] == '\r') {
                    chunk_len--;
                    total_len--;
                } else if (chunk_len == 0 && accum_len > 0 && accum_buffer[accum_len - 1] == '\r') {
                    accum_len--;
                    total_len--;
                }

                RtHandleV2 *_temp_h1 = rt_arena_v2_alloc(arena, total_len + 1);
                rt_handle_v2_pin(_temp_h1);
                char *temp = (char *)_temp_h1->ptr;
                if (temp == NULL) {
                    if (accum_buffer) free(accum_buffer);
                    fprintf(stderr, "TlsStream.readLine: arena alloc failed\n");
                    exit(1);
                }

                if (accum_len > 0) {
                    memcpy(temp, accum_buffer, accum_len);
                }
                if (chunk_len > 0) {
                    memcpy(temp + accum_len,
                           stream->read_buf + stream->read_buf_pos,
                           chunk_len);
                }
                temp[total_len] = '\0';

                stream->read_buf_pos = i + 1;
                if (stream->read_buf_pos >= stream->read_buf_end) {
                    stream->read_buf_pos = 0;
                    stream->read_buf_end = 0;
                }

                if (accum_buffer) free(accum_buffer);
                return rt_arena_v2_strdup(arena, temp);
            }
        }

        /* No newline found - accumulate current buffer content */
        size_t chunk_len = stream->read_buf_end - stream->read_buf_pos;

        if (chunk_len > 0) {
            if (accum_buffer == NULL) {
                accum_capacity = (chunk_len < 256) ? 256 : chunk_len * 2;
                accum_buffer = (char *)malloc(accum_capacity);
                if (accum_buffer == NULL) {
                    fprintf(stderr, "TlsStream.readLine: malloc failed\n");
                    exit(1);
                }
            } else if (accum_len + chunk_len > accum_capacity) {
                accum_capacity = (accum_len + chunk_len) * 2;
                char *new_buf = (char *)realloc(accum_buffer, accum_capacity);
                if (new_buf == NULL) {
                    free(accum_buffer);
                    fprintf(stderr, "TlsStream.readLine: realloc failed\n");
                    exit(1);
                }
                accum_buffer = new_buf;
            }

            memcpy(accum_buffer + accum_len,
                   stream->read_buf + stream->read_buf_pos,
                   chunk_len);
            accum_len += chunk_len;
            stream->read_buf_pos = 0;
            stream->read_buf_end = 0;
        }

        /* Try to fill buffer */
        if (stream->eof_reached) {
            break;
        }

        int n = tls_stream_fill(stream);
        if (n < 0) {
            if (accum_buffer) free(accum_buffer);
            fprintf(stderr, "TlsStream.readLine: SSL_read failed\n");
            exit(1);
        }
        if (n == 0 && tls_stream_buffered(stream) == 0) {
            break; /* EOF */
        }
    }

    /* EOF reached - return accumulated data (or empty string) */
    size_t total_len = accum_len;
    /* Strip trailing \r */
    if (total_len > 0 && accum_buffer[total_len - 1] == '\r') {
        total_len--;
    }

    RtHandleV2 *_temp_h2 = rt_arena_v2_alloc(arena, total_len + 1);
    rt_handle_v2_pin(_temp_h2);
    char *temp = (char *)_temp_h2->ptr;
    if (temp == NULL) {
        if (accum_buffer) free(accum_buffer);
        fprintf(stderr, "TlsStream.readLine: arena alloc failed\n");
        exit(1);
    }

    if (total_len > 0 && accum_buffer) {
        memcpy(temp, accum_buffer, total_len);
    }
    temp[total_len] = '\0';

    if (accum_buffer) free(accum_buffer);
    return rt_arena_v2_strdup(arena, temp);
}

/* ============================================================================
 * TlsStream Write Operations
 * ============================================================================ */

long sn_tls_stream_write(RtTlsStream *stream, unsigned char *data) {
    if (stream == NULL || data == NULL) return 0;

    size_t length = rt_v2_data_array_length(data);
    if (length == 0) return 0;

    SSL *ssl = (SSL *)stream->ssl_ptr;
    int bytes_sent = SSL_write(ssl, data, (int)length);

    if (bytes_sent <= 0) {
        int ssl_err = SSL_get_error(ssl, bytes_sent);
        fprintf(stderr, "TlsStream.write: SSL_write failed (error %d)\n", ssl_err);
        exit(1);
    }

    return bytes_sent;
}

void sn_tls_stream_write_line(RtTlsStream *stream, const char *text) {
    if (stream == NULL) return;

    SSL *ssl = (SSL *)stream->ssl_ptr;

    if (text != NULL) {
        size_t len = strlen(text);
        if (len > 0) {
            int result = SSL_write(ssl, text, (int)len);
            if (result <= 0) {
                fprintf(stderr, "TlsStream.writeLine: SSL_write failed\n");
                exit(1);
            }
        }
    }

    /* Send CRLF newline */
    int result = SSL_write(ssl, "\r\n", 2);
    if (result <= 0) {
        fprintf(stderr, "TlsStream.writeLine: SSL_write newline failed\n");
        exit(1);
    }
}

/* ============================================================================
 * TlsStream Getters
 * ============================================================================ */

RtHandleV2 *sn_tls_stream_get_remote_address(RtArenaV2 *arena, RtTlsStream *stream) {
    if (stream == NULL || stream->remote_addr == NULL) {
        return rt_arena_v2_strdup(arena, "");
    }
    return rt_arena_v2_strdup(arena, stream->remote_addr);
}

/* ============================================================================
 * TlsStream Lifecycle
 * ============================================================================ */

void sn_tls_stream_close(RtTlsStream *stream) {
    if (stream == NULL) return;

    if (stream->ssl_ptr != NULL) {
        SSL *ssl = (SSL *)stream->ssl_ptr;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        stream->ssl_ptr = NULL;
    }

    if (stream->ctx != NULL) {
        SSL_CTX_free(stream->ctx);
        stream->ctx = NULL;
    }

    if (stream->socket_fd != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(stream->socket_fd);
        stream->socket_fd = INVALID_SOCKET_VAL;
    }
}

/* ============================================================================
 * TlsListener Type Definition
 * ============================================================================ */

typedef struct RtTlsListener {
    socket_t socket_fd;         /* Listening TCP socket */
    int bound_port;             /* Bound port number */
    SSL_CTX *ssl_ctx;           /* Server SSL context (shared across accepts) */
} RtTlsListener;

/* ============================================================================
 * TlsListener Bind
 * ============================================================================ */

RtTlsListener *sn_tls_listener_bind(RtArenaV2 *arena, const char *address,
                                      const char *cert_file, const char *key_file) {
    ensure_winsock_initialized();
    ensure_openssl_initialized();

    if (address == NULL || cert_file == NULL || key_file == NULL) {
        fprintf(stderr, "TlsListener.bind: NULL argument\n");
        exit(1);
    }

    char host[256];
    int port;

    if (!tls_parse_address(address, host, sizeof(host), &port)) {
        fprintf(stderr, "TlsListener.bind: invalid address format '%s'\n", address);
        exit(1);
    }

    /* Create server SSL context */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "TlsListener.bind: SSL_CTX_new failed\n");
        exit(1);
    }

    /* Load certificate */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        SSL_CTX_free(ctx);
        fprintf(stderr, "TlsListener.bind: failed to load certificate '%s': %s\n",
                cert_file, err_buf);
        exit(1);
    }

    /* Load private key */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        SSL_CTX_free(ctx);
        fprintf(stderr, "TlsListener.bind: failed to load private key '%s': %s\n",
                key_file, err_buf);
        exit(1);
    }

    /* Verify key matches certificate */
    if (SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        fprintf(stderr, "TlsListener.bind: private key does not match certificate\n");
        exit(1);
    }

    /* Create and bind TCP socket */
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int status = getaddrinfo(host[0] ? host : NULL, port_str, &hints, &result);
    if (status != 0) {
        SSL_CTX_free(ctx);
        fprintf(stderr, "TlsListener.bind: getaddrinfo failed: %s\n", gai_strerror(status));
        exit(1);
    }

    socket_t sock = socket(result->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET_VAL) {
        freeaddrinfo(result);
        SSL_CTX_free(ctx);
        fprintf(stderr, "TlsListener.bind: socket creation failed\n");
        exit(1);
    }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval, sizeof(optval));

    if (bind(sock, result->ai_addr, (int)result->ai_addrlen) != 0) {
        freeaddrinfo(result);
        CLOSE_SOCKET(sock);
        SSL_CTX_free(ctx);
        fprintf(stderr, "TlsListener.bind: bind failed on '%s'\n", address);
        exit(1);
    }

    freeaddrinfo(result);

    /* Listen for connections */
    if (listen(sock, SOMAXCONN) != 0) {
        CLOSE_SOCKET(sock);
        SSL_CTX_free(ctx);
        fprintf(stderr, "TlsListener.bind: listen failed\n");
        exit(1);
    }

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

    /* Create listener struct */
    RtHandleV2 *_listener_h = rt_arena_v2_alloc(arena, sizeof(RtTlsListener));
    rt_handle_v2_pin(_listener_h);
    RtTlsListener *listener = (RtTlsListener *)_listener_h->ptr;
    if (listener == NULL) {
        CLOSE_SOCKET(sock);
        SSL_CTX_free(ctx);
        fprintf(stderr, "TlsListener.bind: allocation failed\n");
        exit(1);
    }

    listener->socket_fd = sock;
    listener->bound_port = bound_port;
    listener->ssl_ctx = ctx;

    return listener;
}

/* ============================================================================
 * TlsListener Accept (blocks until a connection is available)
 * ============================================================================ */

RtTlsStream *sn_tls_listener_accept(RtArenaV2 *arena, RtTlsListener *listener) {
    if (listener == NULL) {
        fprintf(stderr, "TlsListener.accept: listener is NULL\n");
        exit(1);
    }

    /* Accept TCP connection */
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);

    socket_t client_sock = accept(listener->socket_fd,
                                   (struct sockaddr *)&client_addr, &client_len);
    if (client_sock == INVALID_SOCKET_VAL) {
        fprintf(stderr, "TlsListener.accept: accept failed (errno %d)\n", GET_SOCKET_ERROR());
        exit(1);
    }

    /* Create SSL object from the listener's shared context */
    SSL *ssl = SSL_new(listener->ssl_ctx);
    if (ssl == NULL) {
        CLOSE_SOCKET(client_sock);
        fprintf(stderr, "TlsListener.accept: SSL_new failed\n");
        exit(1);
    }

    /* Attach the client socket to SSL */
    if (SSL_set_fd(ssl, (int)client_sock) != 1) {
        SSL_free(ssl);
        CLOSE_SOCKET(client_sock);
        fprintf(stderr, "TlsListener.accept: SSL_set_fd failed\n");
        exit(1);
    }

    /* Perform server-side TLS handshake */
    int accept_ret = SSL_accept(ssl);
    if (accept_ret != 1) {
        int ssl_err = SSL_get_error(ssl, accept_ret);
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));

        SSL_free(ssl);
        CLOSE_SOCKET(client_sock);

        if (ssl_err == SSL_ERROR_SSL) {
            fprintf(stderr, "TlsListener.accept: TLS handshake failed: %s\n", err_buf);
        } else {
            fprintf(stderr, "TlsListener.accept: TLS handshake failed (error %d)\n", ssl_err);
        }
        exit(1);
    }

    /* Build remote address string */
    char addr_str[256];
    if (client_addr.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&client_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        snprintf(addr_str, sizeof(addr_str), "%s:%d", ip, ntohs(sin->sin_port));
    } else if (client_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&client_addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        snprintf(addr_str, sizeof(addr_str), "[%s]:%d", ip, ntohs(sin6->sin6_port));
    } else {
        snprintf(addr_str, sizeof(addr_str), "unknown:0");
    }

    /* Create TlsStream - pass NULL for ctx since the listener owns the context */
    return sn_tls_stream_create(arena, client_sock, NULL, ssl, addr_str);
}

/* ============================================================================
 * TlsListener Getters
 * ============================================================================ */

int sn_tls_listener_get_port(RtTlsListener *listener) {
    return listener ? listener->bound_port : 0;
}

/* ============================================================================
 * TlsListener Lifecycle
 * ============================================================================ */

void sn_tls_listener_close(RtTlsListener *listener) {
    if (listener == NULL) return;

    if (listener->socket_fd != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(listener->socket_fd);
        listener->socket_fd = INVALID_SOCKET_VAL;
    }

    if (listener->ssl_ctx != NULL) {
        SSL_CTX_free(listener->ssl_ctx);
        listener->ssl_ctx = NULL;
    }
}
