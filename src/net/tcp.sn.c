/* ==============================================================================
 * sdk/net/tcp.sn.c - Self-contained TCP Implementation (TcpStream + TcpListener)
 * ==============================================================================
 * This file provides the C implementation for SnTcpStream and SnTcpListener.
 * It is compiled via #pragma source and linked with Sindarin code.
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Include runtime for proper memory management */
#include "runtime/array/runtime_array_v2.h"

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

typedef struct RtTcpStream {
    socket_t socket_fd;
    char *remote_addr;
    unsigned char *read_buf;
    size_t read_buf_capacity;
    size_t read_buf_pos;
    size_t read_buf_end;
    int read_timeout_ms;
    bool eof_reached;
    RtArenaV2 *arena;             /* Private arena — owns all internal allocations */
} RtTcpStream;

typedef struct RtTcpListener {
    socket_t socket_fd;
    int bound_port;
    RtArenaV2 *arena;       /* Private arena — owns all internal allocations */
} RtTcpListener;

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
static inline size_t stream_buffered(RtTcpStream *stream) {
    return stream->read_buf_end - stream->read_buf_pos;
}

/* Returns available space at end of buffer */
static inline size_t stream_space(RtTcpStream *stream) {
    return stream->read_buf_capacity - stream->read_buf_end;
}

/* Compact buffer - move unread data to start to make room for more */
static void stream_compact(RtTcpStream *stream) {
    size_t buffered = stream_buffered(stream);
    if (buffered > 0 && stream->read_buf_pos > 0) {
        memmove(stream->read_buf,
                stream->read_buf + stream->read_buf_pos,
                buffered);
    }
    stream->read_buf_pos = 0;
    stream->read_buf_end = buffered;
}

/* Wait for socket to be readable with timeout.
 * Returns: 1 = readable, 0 = timeout, -1 = error */
static int stream_wait_readable(RtTcpStream *stream) {
    if (stream->read_timeout_ms < 0) {
        return 1;  /* Blocking mode - assume readable */
    }

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(stream->socket_fd, &readfds);

    struct timeval tv;
    struct timeval *tvp = NULL;

    if (stream->read_timeout_ms > 0) {
        tv.tv_sec = stream->read_timeout_ms / 1000;
        tv.tv_usec = (stream->read_timeout_ms % 1000) * 1000;
        tvp = &tv;
    } else {
        /* Non-blocking: zero timeout */
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        tvp = &tv;
    }

    int result = select((int)(stream->socket_fd + 1), &readfds, NULL, NULL, tvp);
    return result;
}

/* Fill buffer from socket.
 * Returns: >0 bytes read, 0 on EOF, -1 on error, -2 on timeout */
static int stream_fill(RtTcpStream *stream) {
    if (stream->eof_reached) {
        return 0;
    }

    /* Compact if we've consumed more than half the buffer */
    if (stream->read_buf_pos > stream->read_buf_capacity / 2) {
        stream_compact(stream);
    }

    /* If buffer is full, compact to make room */
    size_t space = stream_space(stream);
    if (space == 0) {
        stream_compact(stream);
        space = stream_space(stream);
        if (space == 0) {
            /* Buffer truly full with unread data */
            return -1;
        }
    }

    /* Wait for data if timeout is configured */
    if (stream->read_timeout_ms >= 0) {
        int wait_result = stream_wait_readable(stream);
        if (wait_result == 0) {
            return -2;  /* Timeout */
        }
        if (wait_result < 0) {
            return -1;  /* Error */
        }
    }

    /* Read from socket into buffer */
    int n = recv(stream->socket_fd,
                 (char *)(stream->read_buf + stream->read_buf_end),
                 (int)space, 0);

    if (n > 0) {
        stream->read_buf_end += n;
    } else if (n == 0) {
        stream->eof_reached = true;
    }

    return n;
}

/* Ensure at least 'need' bytes in buffer.
 * Returns: true if enough data available, false on EOF/error/timeout */
static bool stream_ensure(RtTcpStream *stream, size_t need) {
    while (stream_buffered(stream) < need) {
        if (stream->eof_reached) {
            return false;
        }
        int n = stream_fill(stream);
        if (n <= 0) {
            return false;
        }
    }
    return true;
}

/* Consume n bytes from the buffer (advance read position) */
static inline void stream_consume(RtTcpStream *stream, size_t n) {
    stream->read_buf_pos += n;
    if (stream->read_buf_pos >= stream->read_buf_end) {
        /* Buffer empty - reset positions */
        stream->read_buf_pos = 0;
        stream->read_buf_end = 0;
    }
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static RtTcpStream *sn_tcp_stream_create(RtArenaV2 *arena, socket_t sock, const char *remote_addr) {
    (void)arena;  /* caller arena not used for internal allocations */
    RtArenaV2 *priv = rt_arena_v2_create(NULL, RT_ARENA_MODE_DEFAULT, "tcp_stream");
    RtHandleV2 *_stream_h = rt_arena_v2_alloc(priv, sizeof(RtTcpStream));
    RtTcpStream *stream = (RtTcpStream *)_stream_h->ptr;
    if (stream == NULL) {
        fprintf(stderr, "sn_tcp_stream_create: allocation failed\n");
        exit(1);
    }
    stream->socket_fd = sock;

    /* Initialize read buffer */
    stream->read_buf_capacity = SN_TCP_DEFAULT_BUFFER_SIZE;
    RtHandleV2 *_buf_h = rt_arena_v2_alloc(priv, stream->read_buf_capacity);
    stream->read_buf = (unsigned char *)_buf_h->ptr;
    if (stream->read_buf == NULL) {
        fprintf(stderr, "sn_tcp_stream_create: buffer allocation failed\n");
        exit(1);
    }
    stream->read_buf_pos = 0;
    stream->read_buf_end = 0;

    /* Configuration defaults */
    stream->read_timeout_ms = -1;
    stream->eof_reached = false;

    /* Store private arena */
    stream->arena = priv;

    /* Copy remote address string */
    if (remote_addr) {
        size_t len = strlen(remote_addr) + 1;
        RtHandleV2 *_addr_h = rt_arena_v2_alloc(priv, len);
        stream->remote_addr = (char *)_addr_h->ptr;
        if (stream->remote_addr) {
            memcpy(stream->remote_addr, remote_addr, len);
        }
    } else {
        stream->remote_addr = NULL;
    }

    return stream;
}

/* Parse address string "host:port" into host and port components */
static int parse_address(const char *address, char *host, size_t host_len, int *port) {
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

RtTcpStream *sn_tcp_stream_connect(RtArenaV2 *arena, const char *address) {
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

    return sn_tcp_stream_create(arena, sock, address);
}

/* ============================================================================
 * TcpStream Read Operations
 * ============================================================================ */

/* Read up to maxBytes (may return fewer) - uses internal buffer */
RtHandleV2 *sn_tcp_stream_read(RtArenaV2 *arena, RtTcpStream *stream, long maxBytes) {
    if (stream == NULL || maxBytes <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    /* If buffer is empty, fill it */
    if (stream_buffered(stream) == 0 && !stream->eof_reached) {
        int n = stream_fill(stream);
        if (n < 0 && n != -2) {  /* Error (not timeout) */
            fprintf(stderr, "sn_tcp_stream_read: recv failed (%d)\n", GET_SOCKET_ERROR());
            exit(1);
        }
    }

    /* Return what we have (up to maxBytes) */
    size_t available = stream_buffered(stream);
    size_t to_read = ((size_t)maxBytes < available) ? (size_t)maxBytes : available;

    RtHandleV2 *result = rt_array_create_generic_v2(arena, to_read, sizeof(unsigned char),
                                              stream->read_buf + stream->read_buf_pos);
    stream_consume(stream, to_read);

    return result;
}

/* Read until connection closes - uses internal buffer */
RtHandleV2 *sn_tcp_stream_read_all(RtArenaV2 *arena, RtTcpStream *stream) {
    if (stream == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    /* We still need a growing buffer for accumulating all data,
     * but we read through our internal buffer for efficiency */
    size_t capacity = 4096;
    size_t total_read = 0;
    unsigned char *temp_buffer = (unsigned char *)malloc(capacity);

    if (temp_buffer == NULL) {
        fprintf(stderr, "sn_tcp_stream_read_all: malloc failed\n");
        exit(1);
    }

    while (!stream->eof_reached) {
        /* Fill internal buffer if empty */
        if (stream_buffered(stream) == 0) {
            int n = stream_fill(stream);
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
        size_t available = stream_buffered(stream);
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
                   stream->read_buf + stream->read_buf_pos,
                   available);
            total_read += available;
            stream_consume(stream, available);
        }
    }

    /* Create runtime array with received data */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, total_read, sizeof(unsigned char), temp_buffer);
    free(temp_buffer);

    return result;
}

/* Read until newline - efficient buffered implementation */
RtHandleV2 *sn_tcp_stream_read_line(RtArenaV2 *arena, RtTcpStream *stream) {
    if (stream == NULL) {
        return rt_arena_v2_strdup(arena, "");
    }

    /* For lines that fit in buffer, we can avoid malloc entirely.
     * For longer lines, we accumulate in a temp buffer. */
    size_t accum_capacity = 0;
    size_t accum_len = 0;
    char *accum_buffer = NULL;

    while (1) {
        /* Scan buffer for newline */
        for (size_t i = stream->read_buf_pos; i < stream->read_buf_end; i++) {
            unsigned char ch = stream->read_buf[i];

            if (ch == '\n') {
                /* Found newline - calculate line length */
                size_t chunk_len = i - stream->read_buf_pos;

                /* Total line length (accumulated + this chunk, minus trailing \r) */
                size_t total_len = accum_len + chunk_len;

                /* Check for \r at end of chunk */
                if (chunk_len > 0 && stream->read_buf[i - 1] == '\r') {
                    chunk_len--;
                    total_len--;
                } else if (chunk_len == 0 && accum_len > 0 && accum_buffer[accum_len - 1] == '\r') {
                    /* \r was at end of accumulated buffer */
                    accum_len--;
                    total_len--;
                }

                /* Allocate temp buffer and build final string */
                char *temp = (char *)malloc(total_len + 1);
                if (temp == NULL) {
                    if (accum_buffer) free(accum_buffer);
                    fprintf(stderr, "sn_tcp_stream_read_line: malloc failed\n");
                    exit(1);
                }

                /* Copy accumulated data first */
                if (accum_len > 0) {
                    memcpy(temp, accum_buffer, accum_len);
                }

                /* Copy this chunk (excluding \r if present) */
                if (chunk_len > 0) {
                    memcpy(temp + accum_len,
                           stream->read_buf + stream->read_buf_pos,
                           chunk_len);
                }

                temp[total_len] = '\0';

                /* Consume up to and including the newline */
                stream->read_buf_pos = i + 1;
                if (stream->read_buf_pos >= stream->read_buf_end) {
                    stream->read_buf_pos = 0;
                    stream->read_buf_end = 0;
                }

                if (accum_buffer) free(accum_buffer);
                RtHandleV2 *result = rt_arena_v2_strdup(arena, temp);
                free(temp);
                return result;
            }
        }

        /* No newline found in current buffer content.
         * Save what we have and try to get more data. */
        size_t chunk_len = stream->read_buf_end - stream->read_buf_pos;

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
                   stream->read_buf + stream->read_buf_pos,
                   chunk_len);
            accum_len += chunk_len;
            stream->read_buf_pos = stream->read_buf_end;
        }

        /* Reset buffer and fill with more data */
        stream->read_buf_pos = 0;
        stream->read_buf_end = 0;

        if (stream->eof_reached) {
            break;
        }

        int n = stream_fill(stream);
        if (n <= 0) {
            break;  /* EOF or error */
        }
    }

    /* EOF reached without newline - return accumulated data */
    /* Strip trailing \r if present */
    if (accum_len > 0 && accum_buffer && accum_buffer[accum_len - 1] == '\r') {
        accum_len--;
    }

    /* Allocate temp buffer for final string */
    char *temp = (char *)malloc(accum_len + 1);
    if (temp == NULL) {
        if (accum_buffer) free(accum_buffer);
        fprintf(stderr, "sn_tcp_stream_read_line: malloc failed\n");
        exit(1);
    }

    if (accum_len > 0 && accum_buffer) {
        memcpy(temp, accum_buffer, accum_len);
    }
    temp[accum_len] = '\0';

    if (accum_buffer) free(accum_buffer);
    RtHandleV2 *result = rt_arena_v2_strdup(arena, temp);
    free(temp);
    return result;
}

/* ============================================================================
 * TcpStream Advanced Read Operations
 * ============================================================================ */

/* Peek at next n bytes without consuming them */
RtHandleV2 *sn_tcp_stream_peek(RtArenaV2 *arena, RtTcpStream *stream, long n) {
    if (stream == NULL || n <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    /* Ensure we have enough data */
    if (!stream_ensure(stream, (size_t)n)) {
        /* Return what we have */
        size_t available = stream_buffered(stream);
        return rt_array_create_generic_v2(arena, available, sizeof(unsigned char),
                                       stream->read_buf + stream->read_buf_pos);
    }

    /* Return n bytes without consuming */
    return rt_array_create_generic_v2(arena, (size_t)n, sizeof(unsigned char),
                                   stream->read_buf + stream->read_buf_pos);
}

/* Read exactly n bytes, blocking until all received or EOF/error */
RtHandleV2 *sn_tcp_stream_read_exact(RtArenaV2 *arena, RtTcpStream *stream, long n) {
    if (stream == NULL || n <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    size_t needed = (size_t)n;

    /* Fast path: if all data is already in buffer */
    if (stream_buffered(stream) >= needed) {
        RtHandleV2 *result = rt_array_create_generic_v2(arena, needed, sizeof(unsigned char),
                                                  stream->read_buf + stream->read_buf_pos);
        stream_consume(stream, needed);
        return result;
    }

    /* Slow path: need to accumulate from multiple fills */
    unsigned char *temp = (unsigned char *)malloc(needed);
    if (temp == NULL) {
        fprintf(stderr, "sn_tcp_stream_read_exact: malloc failed\n");
        exit(1);
    }

    size_t total_read = 0;

    while (total_read < needed && !stream->eof_reached) {
        /* Copy from buffer */
        size_t available = stream_buffered(stream);
        if (available > 0) {
            size_t to_copy = (needed - total_read < available) ?
                             (needed - total_read) : available;
            memcpy(temp + total_read,
                   stream->read_buf + stream->read_buf_pos,
                   to_copy);
            stream_consume(stream, to_copy);
            total_read += to_copy;
        }

        /* Fill buffer if we need more */
        if (total_read < needed && !stream->eof_reached) {
            int fill_result = stream_fill(stream);
            if (fill_result <= 0) {
                break;  /* EOF or error */
            }
        }
    }

    RtHandleV2 *result = rt_array_create_generic_v2(arena, total_read, sizeof(unsigned char), temp);
    free(temp);
    return result;
}

/* Read until delimiter byte is found (delimiter included in result) */
RtHandleV2 *sn_tcp_stream_read_until(RtArenaV2 *arena, RtTcpStream *stream, int delimiter) {
    if (stream == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    unsigned char delim_byte = (unsigned char)delimiter;
    size_t accum_capacity = 0;
    size_t accum_len = 0;
    unsigned char *accum_buffer = NULL;

    while (1) {
        /* Scan buffer for delimiter */
        for (size_t i = stream->read_buf_pos; i < stream->read_buf_end; i++) {
            if (stream->read_buf[i] == delim_byte) {
                /* Found delimiter */
                size_t chunk_len = i - stream->read_buf_pos + 1;  /* Include delimiter */
                size_t total_len = accum_len + chunk_len;

                /* First accumulate all data into temp buffer */
                unsigned char *temp = (unsigned char *)malloc(total_len);
                if (temp == NULL) {
                    if (accum_buffer) free(accum_buffer);
                    fprintf(stderr, "sn_tcp_stream_read_until: alloc failed\n");
                    exit(1);
                }

                if (accum_len > 0 && accum_buffer) {
                    memcpy(temp, accum_buffer, accum_len);
                }
                memcpy(temp + accum_len,
                       stream->read_buf + stream->read_buf_pos,
                       chunk_len);

                stream_consume(stream, chunk_len);

                if (accum_buffer) free(accum_buffer);
                RtHandleV2 *result = rt_array_create_generic_v2(arena, total_len, sizeof(unsigned char), temp);
                free(temp);
                return result;
            }
        }

        /* No delimiter found - accumulate and get more data */
        size_t chunk_len = stream_buffered(stream);

        if (chunk_len > 0) {
            if (accum_buffer == NULL) {
                accum_capacity = (chunk_len < 256) ? 256 : chunk_len * 2;
                accum_buffer = (unsigned char *)malloc(accum_capacity);
                if (accum_buffer == NULL) {
                    fprintf(stderr, "sn_tcp_stream_read_until: malloc failed\n");
                    exit(1);
                }
            } else if (accum_len + chunk_len > accum_capacity) {
                while (accum_len + chunk_len > accum_capacity) {
                    accum_capacity *= 2;
                }
                unsigned char *new_buffer = (unsigned char *)realloc(accum_buffer, accum_capacity);
                if (new_buffer == NULL) {
                    free(accum_buffer);
                    fprintf(stderr, "sn_tcp_stream_read_until: realloc failed\n");
                    exit(1);
                }
                accum_buffer = new_buffer;
            }

            memcpy(accum_buffer + accum_len,
                   stream->read_buf + stream->read_buf_pos,
                   chunk_len);
            accum_len += chunk_len;
            stream_consume(stream, chunk_len);
        }

        if (stream->eof_reached) {
            break;
        }

        int n = stream_fill(stream);
        if (n <= 0) {
            break;
        }
    }

    /* EOF without finding delimiter - return what we have */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, accum_len, sizeof(unsigned char),
                                              accum_len > 0 ? accum_buffer : NULL);
    if (accum_buffer) free(accum_buffer);
    return result;
}

/* Check how many bytes are available without blocking */
long sn_tcp_stream_available(RtTcpStream *stream) {
    if (stream == NULL) return 0;
    return (long)stream_buffered(stream);
}

/* Check if EOF has been reached */
bool sn_tcp_stream_eof(RtTcpStream *stream) {
    if (stream == NULL) return true;
    return stream->eof_reached && stream_buffered(stream) == 0;
}

/* ============================================================================
 * TcpStream Configuration
 * ============================================================================ */

/* Set read timeout in milliseconds (-1 = blocking, 0 = non-blocking) */
void sn_tcp_stream_set_timeout(RtTcpStream *stream, long timeout_ms) {
    if (stream == NULL) return;
    stream->read_timeout_ms = (int)timeout_ms;
}

/* Get current read timeout */
long sn_tcp_stream_get_timeout(RtTcpStream *stream) {
    if (stream == NULL) return -1;
    return stream->read_timeout_ms;
}

/* ============================================================================
 * TcpStream Write Operations
 * ============================================================================ */

/* Write bytes, return count written */
long sn_tcp_stream_write(RtTcpStream *stream, unsigned char *data) {
    if (stream == NULL || data == NULL) return 0;

    size_t length = rt_v2_data_array_length(data);
    if (length == 0) return 0;

    int bytes_sent = send(stream->socket_fd, (const char *)data, (int)length, 0);

    if (bytes_sent < 0) {
        fprintf(stderr, "sn_tcp_stream_write: send failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }

    return bytes_sent;
}

/* Write string + newline */
void sn_tcp_stream_write_line(RtTcpStream *stream, const char *text) {
    if (stream == NULL) return;

    if (text != NULL) {
        size_t len = strlen(text);
        if (len > 0) {
            int result = send(stream->socket_fd, text, (int)len, 0);
            if (result < 0) {
                fprintf(stderr, "sn_tcp_stream_write_line: send failed (%d)\n", GET_SOCKET_ERROR());
                exit(1);
            }
        }
    }

    /* Send newline */
    int result = send(stream->socket_fd, "\r\n", 2, 0);
    if (result < 0) {
        fprintf(stderr, "sn_tcp_stream_write_line: send newline failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }
}

/* ============================================================================
 * TcpStream Getters
 * ============================================================================ */

RtHandleV2 *sn_tcp_stream_get_remote_address(RtArenaV2 *arena, RtTcpStream *stream) {
    if (stream == NULL || stream->remote_addr == NULL) {
        return rt_arena_v2_strdup(arena, "");
    }
    return rt_arena_v2_strdup(arena, stream->remote_addr);
}

/* ============================================================================
 * TcpStream Lifecycle
 * ============================================================================ */

void sn_tcp_stream_close(RtTcpStream *stream) {
    if (stream == NULL) return;

    socket_t fd = stream->socket_fd;
    RtArenaV2 *priv = stream->arena;

    /* Close socket before destroying arena */
    if (fd != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(fd);
    }

    /* Destroy private arena — frees struct, buffer, addr string */
    if (priv != NULL) {
        rt_arena_v2_destroy(priv, false);
    }
}

/* ============================================================================
 * TcpListener Creation
 * ============================================================================ */

static RtTcpListener *sn_tcp_listener_create(RtArenaV2 *arena, socket_t sock, int port) {
    (void)arena;
    RtArenaV2 *priv = rt_arena_v2_create(NULL, RT_ARENA_MODE_DEFAULT, "tcp_listener");
    RtHandleV2 *_listener_h = rt_arena_v2_alloc(priv, sizeof(RtTcpListener));
    RtTcpListener *listener = (RtTcpListener *)_listener_h->ptr;
    if (listener == NULL) {
        fprintf(stderr, "sn_tcp_listener_create: allocation failed\n");
        exit(1);
    }
    listener->socket_fd = sock;
    listener->bound_port = port;
    listener->arena = priv;
    return listener;
}

RtTcpListener *sn_tcp_listener_bind(RtArenaV2 *arena, const char *address) {
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

    return sn_tcp_listener_create(arena, sock, actual_port);
}

/* ============================================================================
 * TcpListener Accept
 * ============================================================================ */

RtTcpStream *sn_tcp_listener_accept(RtArenaV2 *arena, RtTcpListener *listener) {
    if (listener == NULL) {
        fprintf(stderr, "sn_tcp_listener_accept: NULL listener\n");
        exit(1);
    }

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    socket_t client_sock = accept(listener->socket_fd, (struct sockaddr *)&client_addr, &client_len);

    if (client_sock == INVALID_SOCKET_VAL) {
        fprintf(stderr, "sn_tcp_listener_accept: accept failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }

    /* Format remote address as "ip:port" */
    char remote_addr[64];
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
    snprintf(remote_addr, sizeof(remote_addr), "%s:%d", ip_str, ntohs(client_addr.sin_port));

    return sn_tcp_stream_create(arena, client_sock, remote_addr);
}

/* ============================================================================
 * TcpListener Getters
 * ============================================================================ */

long sn_tcp_listener_get_port(RtTcpListener *listener) {
    if (listener == NULL) return 0;
    return listener->bound_port;
}

/* ============================================================================
 * TcpListener Lifecycle
 * ============================================================================ */

void sn_tcp_listener_close(RtTcpListener *listener) {
    if (listener == NULL) return;

    socket_t fd = listener->socket_fd;
    RtArenaV2 *priv = listener->arena;

    if (fd != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(fd);
    }

    /* Destroy private arena — frees everything */
    if (priv != NULL) {
        rt_arena_v2_destroy(priv, false);
    }
}