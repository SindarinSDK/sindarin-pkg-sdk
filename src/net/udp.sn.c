/* ==============================================================================
 * sdk/net/udp_socket.sn.c - Self-contained UdpSocket Implementation
 * ==============================================================================
 * This file provides the C implementation for the SnUdpSocket type.
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
 * UdpSocket Type Definition
 * ============================================================================ */

typedef struct RtUdpSocket {
    socket_t socket_fd;     /* Socket file descriptor */
    int bound_port;         /* Port number we're bound to */
    int recv_timeout_ms;    /* Receive timeout: -1=blocking, 0=non-blocking, >0=timeout ms */
} RtUdpSocket;

/* Result struct for receiveFrom */
typedef struct RtUdpReceiveResult {
    RtHandleV2 *data;          /* byte[] runtime array handle */
    char *sender;           /* Sender address string "ip:port" */
} RtUdpReceiveResult;

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
 * Helper Functions
 * ============================================================================ */

/* Wait for socket to be readable with timeout.
 * Returns: 1 = readable, 0 = timeout, -1 = error */
static int udp_wait_readable(RtUdpSocket *socket_obj) {
    if (socket_obj->recv_timeout_ms < 0) {
        return 1;  /* Blocking mode - assume readable */
    }

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(socket_obj->socket_fd, &readfds);

    struct timeval tv;
    struct timeval *tvp = NULL;

    if (socket_obj->recv_timeout_ms > 0) {
        tv.tv_sec = socket_obj->recv_timeout_ms / 1000;
        tv.tv_usec = (socket_obj->recv_timeout_ms % 1000) * 1000;
        tvp = &tv;
    } else {
        /* Non-blocking: zero timeout */
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        tvp = &tv;
    }

    int result = select((int)(socket_obj->socket_fd + 1), &readfds, NULL, NULL, tvp);
    return result;
}

static RtUdpSocket *sn_udp_socket_create(RtArenaV2 *arena, socket_t sock, int port) {
    RtHandleV2 *_socket_h = rt_arena_v2_alloc(arena, sizeof(RtUdpSocket));
    rt_handle_v2_pin(_socket_h);
    RtUdpSocket *socket_obj = (RtUdpSocket *)_socket_h->ptr;
    if (socket_obj == NULL) {
        fprintf(stderr, "sn_udp_socket_create: allocation failed\n");
        exit(1);
    }
    socket_obj->socket_fd = sock;
    socket_obj->bound_port = port;
    socket_obj->recv_timeout_ms = -1;  /* Blocking by default */
    return socket_obj;
}

/* Parse address string "host:port" or ":port" into host and port components */
static int parse_bind_address(const char *address, char *host, size_t host_len, int *port) {
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

/* Parse destination address for sendTo */
static int parse_dest_address(const char *address, struct sockaddr_in *dest_addr) {
    if (address == NULL) return 0;

    char host[256];
    int port;

    const char *last_colon = NULL;

    /* Handle IPv6 addresses like [::1]:8080 */
    if (address[0] == '[') {
        /* IPv6 not fully supported for sendTo yet */
        return 0;
    }

    /* Find the last colon */
    for (const char *p = address; *p; p++) {
        if (*p == ':') last_colon = p;
    }

    if (last_colon == NULL) return 0;

    size_t len = last_colon - address;
    if (len >= sizeof(host)) return 0;

    memcpy(host, address, len);
    host[len] = '\0';
    port = atoi(last_colon + 1);

    memset(dest_addr, 0, sizeof(*dest_addr));
    dest_addr->sin_family = AF_INET;
    dest_addr->sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &dest_addr->sin_addr) != 1) {
        /* Try to resolve hostname */
        struct addrinfo hints, *result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(host, NULL, &hints, &result) != 0) {
            return 0;
        }

        struct sockaddr_in *resolved = (struct sockaddr_in *)result->ai_addr;
        dest_addr->sin_addr = resolved->sin_addr;
        freeaddrinfo(result);
    }

    return 1;
}

/* ============================================================================
 * UdpSocket Creation
 * ============================================================================ */

RtUdpSocket *sn_udp_socket_bind(RtArenaV2 *arena, const char *address) {
    ensure_winsock_initialized();

    if (address == NULL) {
        fprintf(stderr, "sn_udp_socket_bind: NULL address\n");
        exit(1);
    }

    char host[256];
    int port;

    if (!parse_bind_address(address, host, sizeof(host), &port)) {
        fprintf(stderr, "sn_udp_socket_bind: invalid address format '%s'\n", address);
        exit(1);
    }

    /* Create UDP socket */
    socket_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET_VAL) {
        fprintf(stderr, "sn_udp_socket_bind: socket creation failed (%d)\n", GET_SOCKET_ERROR());
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
            hints.ai_socktype = SOCK_DGRAM;

            if (getaddrinfo(host, NULL, &hints, &result) != 0) {
                CLOSE_SOCKET(sock);
                fprintf(stderr, "sn_udp_socket_bind: invalid host '%s'\n", host);
                exit(1);
            }

            struct sockaddr_in *resolved = (struct sockaddr_in *)result->ai_addr;
            addr.sin_addr = resolved->sin_addr;
            freeaddrinfo(result);
        }
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR_VAL) {
        CLOSE_SOCKET(sock);
        fprintf(stderr, "sn_udp_socket_bind: bind failed on '%s' (%d)\n", address, GET_SOCKET_ERROR());
        exit(1);
    }

    /* Get the actual port (in case port was 0) */
    struct sockaddr_in bound_addr;
    socklen_t addr_len = sizeof(bound_addr);
    if (getsockname(sock, (struct sockaddr *)&bound_addr, &addr_len) == SOCKET_ERROR_VAL) {
        CLOSE_SOCKET(sock);
        fprintf(stderr, "sn_udp_socket_bind: getsockname failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }
    int actual_port = ntohs(bound_addr.sin_port);

    return sn_udp_socket_create(arena, sock, actual_port);
}

/* ============================================================================
 * UdpSocket Send/Receive
 * ============================================================================ */

/* Send datagram to address, return bytes sent */
long sn_udp_socket_send_to(RtUdpSocket *socket_obj, unsigned char *data, const char *address) {
    if (socket_obj == NULL || data == NULL || address == NULL) return 0;

    struct sockaddr_in dest_addr;
    if (!parse_dest_address(address, &dest_addr)) {
        fprintf(stderr, "sn_udp_socket_send_to: invalid address '%s'\n", address);
        exit(1);
    }

    size_t length = rt_v2_data_array_length(data);
    if (length == 0) return 0;

    int bytes_sent = sendto(socket_obj->socket_fd, (const char *)data, (int)length, 0,
                            (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (bytes_sent < 0) {
        fprintf(stderr, "sn_udp_socket_send_to: sendto failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }

    return bytes_sent;
}

/* Receive datagram and sender address */
RtUdpReceiveResult *sn_udp_socket_receive_from(RtArenaV2 *arena, RtUdpSocket *socket_obj, long maxBytes) {
    RtHandleV2 *_result_h = rt_arena_v2_alloc(arena, sizeof(RtUdpReceiveResult));
    rt_handle_v2_pin(_result_h);
    RtUdpReceiveResult *result = (RtUdpReceiveResult *)_result_h->ptr;
    if (result == NULL) {
        fprintf(stderr, "sn_udp_socket_receive_from: allocation failed\n");
        exit(1);
    }

    if (socket_obj == NULL || maxBytes <= 0) {
        /* Return empty result */
        result->data = rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
        { RtHandleV2 *_h = rt_arena_v2_strdup(arena, ""); rt_handle_v2_pin(_h); result->sender = (char *)_h->ptr; }
        return result;
    }

    /* Wait for data with timeout if configured */
    if (socket_obj->recv_timeout_ms >= 0) {
        int wait_result = udp_wait_readable(socket_obj);
        if (wait_result == 0) {
            /* Timeout - return empty result */
            result->data = rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
            { RtHandleV2 *_h = rt_arena_v2_strdup(arena, ""); rt_handle_v2_pin(_h); result->sender = (char *)_h->ptr; }
            return result;
        }
        if (wait_result < 0) {
            fprintf(stderr, "sn_udp_socket_receive_from: select failed (%d)\n", GET_SOCKET_ERROR());
            exit(1);
        }
    }

    /* Allocate temporary buffer for receiving */
    unsigned char *temp = (unsigned char *)malloc((size_t)maxBytes);
    if (temp == NULL) {
        fprintf(stderr, "sn_udp_socket_receive_from: malloc failed\n");
        exit(1);
    }

    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);

    int bytes_received = recvfrom(socket_obj->socket_fd, (char *)temp,
                                   (int)maxBytes, 0, (struct sockaddr *)&sender_addr, &sender_len);

    if (bytes_received < 0) {
        free(temp);
        fprintf(stderr, "sn_udp_socket_receive_from: recvfrom failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }

    /* Create runtime array with received data */
    result->data = rt_array_create_generic_v2(arena, (size_t)bytes_received, sizeof(unsigned char), temp);
    free(temp);

    /* Format sender address as "ip:port" */
    char sender_str[64];
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sender_addr.sin_addr, ip_str, sizeof(ip_str));
    snprintf(sender_str, sizeof(sender_str), "%s:%d", ip_str, ntohs(sender_addr.sin_port));

    { RtHandleV2 *_h = rt_arena_v2_strdup(arena, sender_str); rt_handle_v2_pin(_h); result->sender = (char *)_h->ptr; }
    if (result->sender == NULL) {
        fprintf(stderr, "sn_udp_socket_receive_from: sender allocation failed\n");
        exit(1);
    }

    return result;
}

/* ============================================================================
 * UdpSocket Getters
 * ============================================================================ */

long sn_udp_socket_get_port(RtUdpSocket *socket_obj) {
    if (socket_obj == NULL) return 0;
    return socket_obj->bound_port;
}

/* ============================================================================
 * UdpSocket Configuration
 * ============================================================================ */

/* Set receive timeout in milliseconds (-1 = blocking, 0 = non-blocking) */
void sn_udp_socket_set_timeout(RtUdpSocket *socket_obj, long timeout_ms) {
    if (socket_obj == NULL) return;
    socket_obj->recv_timeout_ms = (int)timeout_ms;
}

/* Get current receive timeout */
long sn_udp_socket_get_timeout(RtUdpSocket *socket_obj) {
    if (socket_obj == NULL) return -1;
    return socket_obj->recv_timeout_ms;
}

/* ============================================================================
 * UdpSocket Lifecycle
 * ============================================================================ */

void sn_udp_socket_close(RtUdpSocket *socket_obj) {
    if (socket_obj == NULL) return;

    if (socket_obj->socket_fd != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(socket_obj->socket_fd);
        socket_obj->socket_fd = INVALID_SOCKET_VAL;
    }
}

/* ============================================================================
 * UdpReceiveResult Getters
 * ============================================================================ */

RtHandleV2 *sn_udp_result_get_data(RtArenaV2 *arena, RtUdpReceiveResult *result) {
    if (result == NULL || result->data == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }
    return result->data;
}

RtHandleV2 *sn_udp_result_get_sender(RtArenaV2 *arena, RtUdpReceiveResult *result) {
    if (result == NULL || result->sender == NULL) {
        return rt_arena_v2_strdup(arena, "");
    }
    return rt_arena_v2_strdup(arena, result->sender);
}