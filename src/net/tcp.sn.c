/* ==============================================================================
 * sdk/net/tcp.sn.c - Self-contained TCP Implementation (TcpStream + TcpListener)
 * ==============================================================================
 * Minimal runtime version - no arena, uses calloc/malloc/strdup for allocations.
 * Uses SnArray for byte array returns.
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Platform-specific socket includes */
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")

    typedef SOCKET socket_t;
    #define INVALID_SOCKET_VAL INVALID_SOCKET
    #define SOCKET_ERROR_VAL SOCKET_ERROR
    #define CLOSE_SOCKET(s) closesocket(s)
    #define GET_SOCKET_ERROR() WSAGetLastError()
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
 * Constants
 * ============================================================================ */

#define SN_TCP_DEFAULT_BUFFER_SIZE 8192
#define SN_TCP_MIN_BUFFER_SIZE 256

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

typedef __sn__TcpStream RtTcpStream;
typedef __sn__TcpListener RtTcpListener;

/* Cast macros for socket fd stored as long long */
#define SOCK_FD(s) ((socket_t)(s)->socket_fd)
#define SET_SOCK_FD(s, v) ((s)->socket_fd = (long long)(v))

/* Internal stream state (not exposed to Sindarin) */
typedef struct TcpStreamInternal {
    unsigned char *read_buf;
    size_t read_buf_capacity;
    size_t read_buf_pos;
    size_t read_buf_end;
    int read_timeout_ms;
    bool eof_reached;
} TcpStreamInternal;

/* Global table to associate stream pointers with internal state */
#define MAX_TCP_STREAMS 1024
static struct {
    __sn__TcpStream *stream;
    TcpStreamInternal *internal;
} tcp_stream_table[MAX_TCP_STREAMS];
static int tcp_stream_count = 0;

static TcpStreamInternal *get_internal(__sn__TcpStream *stream) {
    for (int i = 0; i < tcp_stream_count; i++) {
        if (tcp_stream_table[i].stream == stream) {
            return tcp_stream_table[i].internal;
        }
    }
    return NULL;
}

static void register_internal(__sn__TcpStream *stream, TcpStreamInternal *internal) {
    /* Check if slot already exists */
    for (int i = 0; i < tcp_stream_count; i++) {
        if (tcp_stream_table[i].stream == stream) {
            tcp_stream_table[i].internal = internal;
            return;
        }
    }
    if (tcp_stream_count < MAX_TCP_STREAMS) {
        tcp_stream_table[tcp_stream_count].stream = stream;
        tcp_stream_table[tcp_stream_count].internal = internal;
        tcp_stream_count++;
    } else {
        fprintf(stderr, "sn_tcp: too many open streams\n");
        exit(1);
    }
}

static void unregister_internal(__sn__TcpStream *stream) {
    for (int i = 0; i < tcp_stream_count; i++) {
        if (tcp_stream_table[i].stream == stream) {
            /* Swap with last */
            tcp_stream_table[i] = tcp_stream_table[tcp_stream_count - 1];
            tcp_stream_count--;
            return;
        }
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
            fprintf(stderr, "WSAStartup failed: %d\n", result);
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

/* Returns number of bytes available in read buffer without syscall */
static inline size_t stream_buffered(TcpStreamInternal *internal) {
    return internal->read_buf_end - internal->read_buf_pos;
}

/* Returns available space at end of buffer */
static inline size_t stream_space(TcpStreamInternal *internal) {
    return internal->read_buf_capacity - internal->read_buf_end;
}

/* Compact buffer - move unread data to start to make room for more */
static void stream_compact(TcpStreamInternal *internal) {
    size_t buffered = stream_buffered(internal);
    if (buffered > 0 && internal->read_buf_pos > 0) {
        memmove(internal->read_buf,
                internal->read_buf + internal->read_buf_pos,
                buffered);
    }
    internal->read_buf_pos = 0;
    internal->read_buf_end = buffered;
}

/* Wait for socket to be readable with timeout.
 * Returns: 1 = readable, 0 = timeout, -1 = error */
static int stream_wait_readable(socket_t socket_fd, TcpStreamInternal *internal) {
    if (internal->read_timeout_ms < 0) {
        return 1;  /* Blocking mode - assume readable */
    }

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(socket_fd, &readfds);

    struct timeval tv;
    struct timeval *tvp = NULL;

    if (internal->read_timeout_ms > 0) {
        tv.tv_sec = internal->read_timeout_ms / 1000;
        tv.tv_usec = (internal->read_timeout_ms % 1000) * 1000;
        tvp = &tv;
    } else {
        /* Non-blocking: zero timeout */
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        tvp = &tv;
    }

    int result = select((int)(socket_fd + 1), &readfds, NULL, NULL, tvp);
    return result;
}

/* Fill buffer from socket.
 * Returns: >0 bytes read, 0 on EOF, -1 on error, -2 on timeout */
static int stream_fill(socket_t socket_fd, TcpStreamInternal *internal) {
    if (internal->eof_reached) {
        return 0;
    }

    /* Compact if we've consumed more than half the buffer */
    if (internal->read_buf_pos > internal->read_buf_capacity / 2) {
        stream_compact(internal);
    }

    /* If buffer is full, compact to make room */
    size_t space = stream_space(internal);
    if (space == 0) {
        stream_compact(internal);
        space = stream_space(internal);
        if (space == 0) {
            /* Buffer truly full with unread data */
            return -1;
        }
    }

    /* Wait for data if timeout is configured */
    if (internal->read_timeout_ms >= 0) {
        int wait_result = stream_wait_readable(socket_fd, internal);
        if (wait_result == 0) {
            return -2;  /* Timeout */
        }
        if (wait_result < 0) {
            return -1;  /* Error */
        }
    }

    /* Read from socket into buffer */
    int n = recv(socket_fd,
                 (char *)(internal->read_buf + internal->read_buf_end),
                 (int)space, 0);

    if (n > 0) {
        internal->read_buf_end += n;
    } else if (n == 0) {
        internal->eof_reached = true;
    }

    return n;
}

/* Consume n bytes from the buffer (advance read position) */
static inline void stream_consume(TcpStreamInternal *internal, size_t n) {
    internal->read_buf_pos += n;
    if (internal->read_buf_pos >= internal->read_buf_end) {
        /* Buffer empty - reset positions */
        internal->read_buf_pos = 0;
        internal->read_buf_end = 0;
    }
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static __sn__TcpStream *sn_tcp_stream_create(socket_t sock, char *remote_addr) {
    __sn__TcpStream *stream = (__sn__TcpStream *)calloc(1, sizeof(__sn__TcpStream));
    if (stream == NULL) {
        fprintf(stderr, "sn_tcp_stream_create: allocation failed\n");
        exit(1);
    }
    SET_SOCK_FD(stream, sock);
    stream->remote_addr = remote_addr ? strdup(remote_addr) : NULL;

    /* Create internal state */
    TcpStreamInternal *internal = (TcpStreamInternal *)calloc(1, sizeof(TcpStreamInternal));
    if (internal == NULL) {
        fprintf(stderr, "sn_tcp_stream_create: internal allocation failed\n");
        exit(1);
    }
    internal->read_buf_capacity = SN_TCP_DEFAULT_BUFFER_SIZE;
    internal->read_buf = (unsigned char *)malloc(internal->read_buf_capacity);
    if (internal->read_buf == NULL) {
        fprintf(stderr, "sn_tcp_stream_create: buffer allocation failed\n");
        exit(1);
    }
    internal->read_buf_pos = 0;
    internal->read_buf_end = 0;
    internal->read_timeout_ms = -1;
    internal->eof_reached = false;

    register_internal(stream, internal);

    return stream;
}

/* Parse address string "host:port" into host and port components */
static int parse_address(char *address, char *host, size_t host_len, int *port) {
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
            return 0; /* No port specified */
        }
        return 1;
    }

    /* Find the last colon (for host:port format) */
    for (const char *p = address; *p; p++) {
        if (*p == ':') last_colon = p;
    }

    if (last_colon == NULL) return 0;

    size_t len = last_colon - address;
    if (len >= host_len) return 0;

    if (len == 0) {
        /* Empty host means all interfaces (0.0.0.0) */
        strcpy(host, "0.0.0.0");
    } else {
        memcpy(host, address, len);
        host[len] = '\0';
    }

    *port = atoi(last_colon + 1);
    return 1;
}

/* ============================================================================
 * TcpStream Creation
 * ============================================================================ */

__sn__TcpStream *sn_tcp_stream_connect(char *address) {
    ensure_winsock_initialized();

    if (address == NULL) {
        fprintf(stderr, "sn_tcp_stream_connect: NULL address\n");
        exit(1);
    }

    char host[256];
    int port;

    if (!parse_address(address, host, sizeof(host), &port)) {
        fprintf(stderr, "sn_tcp_stream_connect: invalid address format '%s'\n", address);
        exit(1);
    }

    /* Resolve hostname */
    struct addrinfo hints, *result, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;  /* TCP */

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int status = getaddrinfo(host, port_str, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "sn_tcp_stream_connect: DNS resolution failed for '%s': %s\n",
                host, gai_strerror(status));
        exit(1);
    }

    socket_t sock = INVALID_SOCKET_VAL;

    /* Try each address until we successfully connect */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == INVALID_SOCKET_VAL) continue;

        if (connect(sock, rp->ai_addr, (int)rp->ai_addrlen) != SOCKET_ERROR_VAL) {
            break; /* Success */
        }

        CLOSE_SOCKET(sock);
        sock = INVALID_SOCKET_VAL;
    }

    freeaddrinfo(result);

    if (sock == INVALID_SOCKET_VAL) {
        fprintf(stderr, "sn_tcp_stream_connect: connection failed to '%s'\n", address);
        exit(1);
    }

    return sn_tcp_stream_create(sock, address);
}

/* ============================================================================
 * TcpStream Read Operations
 * ============================================================================ */

/* Read up to maxBytes (may return fewer) - uses internal buffer */
SnArray *sn_tcp_stream_read(__sn__TcpStream *stream, long long maxBytes) {
    if (stream == NULL || maxBytes <= 0) {
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
    }
    TcpStreamInternal *internal = get_internal(stream);
    if (internal == NULL) {
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
    }

    socket_t sock = SOCK_FD(stream);

    /* If buffer is empty, fill it */
    if (stream_buffered(internal) == 0 && !internal->eof_reached) {
        int n = stream_fill(sock, internal);
        if (n < 0 && n != -2) {  /* Error (not timeout) - return empty array */
            SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
            arr->elem_tag = SN_TAG_BYTE;
            return arr;
        }
    }

    /* Return what we have (up to maxBytes) */
    size_t available = stream_buffered(internal);
    size_t to_read = ((size_t)maxBytes < available) ? (size_t)maxBytes : available;

    SnArray *arr = sn_array_new(sizeof(unsigned char), (long long)to_read);
    arr->elem_tag = SN_TAG_BYTE;
    if (to_read > 0) {
        memcpy(arr->data, internal->read_buf + internal->read_buf_pos, to_read);
        arr->len = (long long)to_read;
    }
    stream_consume(internal, to_read);

    return arr;
}

/* Read until connection closes - uses internal buffer */
SnArray *sn_tcp_stream_read_all(__sn__TcpStream *stream) {
    if (stream == NULL) {
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
    }
    TcpStreamInternal *internal = get_internal(stream);
    if (internal == NULL) {
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
    }

    socket_t sock = SOCK_FD(stream);

    /* We still need a growing buffer for accumulating all data,
     * but we read through our internal buffer for efficiency */
    size_t capacity = 4096;
    size_t total_read = 0;
    unsigned char *temp_buffer = (unsigned char *)malloc(capacity);

    if (temp_buffer == NULL) {
        fprintf(stderr, "sn_tcp_stream_read_all: malloc failed\n");
        exit(1);
    }

    while (!internal->eof_reached) {
        /* Fill internal buffer if empty */
        if (stream_buffered(internal) == 0) {
            int n = stream_fill(sock, internal);
            if (n < 0 && n != -2) {
                free(temp_buffer);
                fprintf(stderr, "sn_tcp_stream_read_all: recv failed (%d)\n", GET_SOCKET_ERROR());
                exit(1);
            }
            if (n == 0 || n == -2) {
                break;  /* EOF or timeout */
            }
        }

        /* Copy from internal buffer to accumulator */
        size_t available = stream_buffered(internal);
        if (available > 0) {
            /* Grow accumulator if needed */
            if (total_read + available > capacity) {
                while (total_read + available > capacity) {
                    capacity *= 2;
                }
                unsigned char *new_buffer = (unsigned char *)realloc(temp_buffer, capacity);
                if (new_buffer == NULL) {
                    free(temp_buffer);
                    fprintf(stderr, "sn_tcp_stream_read_all: realloc failed\n");
                    exit(1);
                }
                temp_buffer = new_buffer;
            }

            memcpy(temp_buffer + total_read,
                   internal->read_buf + internal->read_buf_pos,
                   available);
            total_read += available;
            stream_consume(internal, available);
        }
    }

    /* Create SnArray with received data */
    SnArray *arr = sn_array_new(sizeof(unsigned char), (long long)total_read);
    arr->elem_tag = SN_TAG_BYTE;
    if (total_read > 0) {
        memcpy(arr->data, temp_buffer, total_read);
        arr->len = (long long)total_read;
    }
    free(temp_buffer);

    return arr;
}

/* Read until newline - efficient buffered implementation */
char *sn_tcp_stream_read_line(__sn__TcpStream *stream) {
    if (stream == NULL) {
        return strdup("");
    }
    TcpStreamInternal *internal = get_internal(stream);
    if (internal == NULL) {
        return strdup("");
    }

    socket_t sock = SOCK_FD(stream);

    /* For lines that fit in buffer, we can avoid extra malloc.
     * For longer lines, we accumulate in a temp buffer. */
    size_t accum_capacity = 0;
    size_t accum_len = 0;
    char *accum_buffer = NULL;

    while (1) {
        /* Scan buffer for newline */
        for (size_t i = internal->read_buf_pos; i < internal->read_buf_end; i++) {
            unsigned char ch = internal->read_buf[i];

            if (ch == '\n') {
                /* Found newline - calculate line length */
                size_t chunk_len = i - internal->read_buf_pos;

                /* Total line length (accumulated + this chunk, minus trailing \r) */
                size_t total_len = accum_len + chunk_len;

                /* Check for \r at end of chunk */
                if (chunk_len > 0 && internal->read_buf[i - 1] == '\r') {
                    chunk_len--;
                    total_len--;
                } else if (chunk_len == 0 && accum_len > 0 && accum_buffer[accum_len - 1] == '\r') {
                    /* \r was at end of accumulated buffer */
                    accum_len--;
                    total_len--;
                }

                /* Allocate result string */
                char *result = (char *)malloc(total_len + 1);
                if (result == NULL) {
                    if (accum_buffer) free(accum_buffer);
                    fprintf(stderr, "sn_tcp_stream_read_line: malloc failed\n");
                    exit(1);
                }

                /* Copy accumulated data first */
                if (accum_len > 0) {
                    memcpy(result, accum_buffer, accum_len);
                }

                /* Copy this chunk (excluding \r if present) */
                if (chunk_len > 0) {
                    memcpy(result + accum_len,
                           internal->read_buf + internal->read_buf_pos,
                           chunk_len);
                }

                result[total_len] = '\0';

                /* Consume up to and including the newline */
                internal->read_buf_pos = i + 1;
                if (internal->read_buf_pos >= internal->read_buf_end) {
                    internal->read_buf_pos = 0;
                    internal->read_buf_end = 0;
                }

                if (accum_buffer) free(accum_buffer);
                return result;
            }
        }

        /* No newline found in current buffer content.
         * Save what we have and try to get more data. */
        size_t chunk_len = internal->read_buf_end - internal->read_buf_pos;

        if (chunk_len > 0) {
            /* Need to accumulate this chunk */
            if (accum_buffer == NULL) {
                accum_capacity = (chunk_len < 256) ? 256 : chunk_len * 2;
                accum_buffer = (char *)malloc(accum_capacity);
                if (accum_buffer == NULL) {
                    fprintf(stderr, "sn_tcp_stream_read_line: malloc failed\n");
                    exit(1);
                }
            } else if (accum_len + chunk_len > accum_capacity) {
                while (accum_len + chunk_len > accum_capacity) {
                    accum_capacity *= 2;
                }
                char *new_buffer = (char *)realloc(accum_buffer, accum_capacity);
                if (new_buffer == NULL) {
                    free(accum_buffer);
                    fprintf(stderr, "sn_tcp_stream_read_line: realloc failed\n");
                    exit(1);
                }
                accum_buffer = new_buffer;
            }

            memcpy(accum_buffer + accum_len,
                   internal->read_buf + internal->read_buf_pos,
                   chunk_len);
            accum_len += chunk_len;
            internal->read_buf_pos = internal->read_buf_end;
        }

        /* Reset buffer and fill with more data */
        internal->read_buf_pos = 0;
        internal->read_buf_end = 0;

        if (internal->eof_reached) {
            break;
        }

        int n = stream_fill(sock, internal);
        if (n <= 0) {
            break;  /* EOF or error */
        }
    }

    /* EOF reached without newline - return accumulated data */
    /* Strip trailing \r if present */
    if (accum_len > 0 && accum_buffer && accum_buffer[accum_len - 1] == '\r') {
        accum_len--;
    }

    /* Allocate result string */
    char *result = (char *)malloc(accum_len + 1);
    if (result == NULL) {
        if (accum_buffer) free(accum_buffer);
        fprintf(stderr, "sn_tcp_stream_read_line: malloc failed\n");
        exit(1);
    }

    if (accum_len > 0 && accum_buffer) {
        memcpy(result, accum_buffer, accum_len);
    }
    result[accum_len] = '\0';

    if (accum_buffer) free(accum_buffer);
    return result;
}

/* ============================================================================
 * TcpStream Configuration
 * ============================================================================ */

/* Set read timeout in milliseconds (-1 = blocking, 0 = non-blocking) */
void sn_tcp_stream_set_timeout(__sn__TcpStream *stream, long long timeout_ms) {
    if (stream == NULL) return;
    TcpStreamInternal *internal = get_internal(stream);
    if (internal == NULL) return;
    internal->read_timeout_ms = (int)timeout_ms;
}

/* ============================================================================
 * TcpStream Write Operations
 * ============================================================================ */

/* Write bytes, return count written */
long long sn_tcp_stream_write(__sn__TcpStream *stream, SnArray *data) {
    if (stream == NULL || data == NULL) return 0;

    long long length = sn_array_length(data);
    if (length == 0) return 0;

    socket_t sock = SOCK_FD(stream);
    int bytes_sent = send(sock, (const char *)data->data, (int)length, 0);

    if (bytes_sent < 0) {
        fprintf(stderr, "sn_tcp_stream_write: send failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }

    return (long long)bytes_sent;
}

/* Write string + newline */
void sn_tcp_stream_write_line(__sn__TcpStream *stream, char *text) {
    if (stream == NULL) return;

    socket_t sock = SOCK_FD(stream);

    if (text != NULL) {
        size_t len = strlen(text);
        if (len > 0) {
            int result = send(sock, text, (int)len, 0);
            if (result < 0) {
                fprintf(stderr, "sn_tcp_stream_write_line: send failed (%d)\n", GET_SOCKET_ERROR());
                exit(1);
            }
        }
    }

    /* Send newline */
    int result = send(sock, "\r\n", 2, 0);
    if (result < 0) {
        fprintf(stderr, "sn_tcp_stream_write_line: send newline failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }
}

/* ============================================================================
 * TcpStream Getters
 * ============================================================================ */

char *sn_tcp_stream_get_remote_address(__sn__TcpStream *stream) {
    if (stream == NULL) {
        return strdup("");
    }
    if (stream->remote_addr == NULL) {
        return strdup("");
    }
    return strdup((char *)stream->remote_addr);
}

/* ============================================================================
 * TcpStream Lifecycle
 * ============================================================================ */

void sn_tcp_stream_dispose(__sn__TcpStream *stream) {
    if (stream == NULL) return;

    socket_t fd = SOCK_FD(stream);

    /* Close socket */
    if (fd != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(fd);
        SET_SOCK_FD(stream, INVALID_SOCKET_VAL);
    }

    /* Free internal state */
    TcpStreamInternal *internal = get_internal(stream);
    if (internal != NULL) {
        if (internal->read_buf != NULL) {
            free(internal->read_buf);
            internal->read_buf = NULL;
        }
        unregister_internal(stream);
        free(internal);
    }

    /* Free the stream struct and its owned strings */
    if (stream->remote_addr) {
        free(stream->remote_addr);
        stream->remote_addr = NULL;
    }
    free(stream);
}

/* ============================================================================
 * TcpListener Creation
 * ============================================================================ */

__sn__TcpListener *sn_tcp_listener_bind(char *address) {
    ensure_winsock_initialized();

    if (address == NULL) {
        fprintf(stderr, "sn_tcp_listener_bind: NULL address\n");
        exit(1);
    }

    char host[256];
    int port;

    if (!parse_address(address, host, sizeof(host), &port)) {
        fprintf(stderr, "sn_tcp_listener_bind: invalid address format '%s'\n", address);
        exit(1);
    }

    /* Create socket */
    socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET_VAL) {
        fprintf(stderr, "sn_tcp_listener_bind: socket creation failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }

    /* Allow address reuse */
    int opt = 1;
#ifdef _WIN32
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#else
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    /* Bind to address */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (strcmp(host, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
            /* Try to resolve hostname */
            struct addrinfo hints, *result;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            if (getaddrinfo(host, NULL, &hints, &result) != 0) {
                CLOSE_SOCKET(sock);
                fprintf(stderr, "sn_tcp_listener_bind: invalid host '%s'\n", host);
                exit(1);
            }

            struct sockaddr_in *resolved = (struct sockaddr_in *)result->ai_addr;
            addr.sin_addr = resolved->sin_addr;
            freeaddrinfo(result);
        }
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR_VAL) {
        CLOSE_SOCKET(sock);
        fprintf(stderr, "sn_tcp_listener_bind: bind failed on '%s' (%d)\n", address, GET_SOCKET_ERROR());
        exit(1);
    }

    /* Get the actual port (in case port was 0) */
    struct sockaddr_in bound_addr;
    socklen_t addr_len = sizeof(bound_addr);
    if (getsockname(sock, (struct sockaddr *)&bound_addr, &addr_len) == SOCKET_ERROR_VAL) {
        CLOSE_SOCKET(sock);
        fprintf(stderr, "sn_tcp_listener_bind: getsockname failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }
    int actual_port = ntohs(bound_addr.sin_port);

    /* Listen for connections */
    if (listen(sock, SOMAXCONN) == SOCKET_ERROR_VAL) {
        CLOSE_SOCKET(sock);
        fprintf(stderr, "sn_tcp_listener_bind: listen failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }

    __sn__TcpListener *listener = (__sn__TcpListener *)calloc(1, sizeof(__sn__TcpListener));
    if (listener == NULL) {
        CLOSE_SOCKET(sock);
        fprintf(stderr, "sn_tcp_listener_bind: allocation failed\n");
        exit(1);
    }
    SET_SOCK_FD(listener, sock);
    listener->bound_port = (long long)actual_port;

    return listener;
}

/* ============================================================================
 * TcpListener Accept
 * ============================================================================ */

__sn__TcpStream *sn_tcp_listener_accept(__sn__TcpListener *listener) {
    if (listener == NULL) {
        fprintf(stderr, "sn_tcp_listener_accept: NULL listener\n");
        exit(1);
    }

    socket_t listener_fd = SOCK_FD(listener);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    socket_t client_sock = accept(listener_fd, (struct sockaddr *)&client_addr, &client_len);

    if (client_sock == INVALID_SOCKET_VAL) {
        fprintf(stderr, "sn_tcp_listener_accept: accept failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }

    /* Format remote address as "ip:port" */
    char remote_addr[64];
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
    snprintf(remote_addr, sizeof(remote_addr), "%s:%d", ip_str, ntohs(client_addr.sin_port));

    return sn_tcp_stream_create(client_sock, remote_addr);
}

/* ============================================================================
 * TcpListener Getters
 * ============================================================================ */

long long sn_tcp_listener_get_port(__sn__TcpListener *listener) {
    if (listener == NULL) return 0;
    return listener->bound_port;
}

/* ============================================================================
 * TcpListener Lifecycle
 * ============================================================================ */

void sn_tcp_listener_dispose(__sn__TcpListener *listener) {
    if (listener == NULL) return;

    socket_t fd = SOCK_FD(listener);

    if (fd != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(fd);
        SET_SOCK_FD(listener, INVALID_SOCKET_VAL);
    }
}
