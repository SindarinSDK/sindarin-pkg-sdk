/* ==============================================================================
 * sdk/net/udp.sn.c - Self-contained UdpSocket Implementation
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
 * Type Definitions
 * ============================================================================ */

typedef __sn__UdpSocket RtUdpSocket;
typedef __sn__UdpReceiveResult RtUdpReceiveResult;

/* Internal UDP socket state */
typedef struct UdpSocketInternal {
    int recv_timeout_ms;
} UdpSocketInternal;

/* Global table for internal state */
#define MAX_UDP_SOCKETS 1024
static struct {
    __sn__UdpSocket *socket;
    UdpSocketInternal *internal;
} udp_socket_table[MAX_UDP_SOCKETS];
static int udp_socket_count = 0;

static UdpSocketInternal *udp_get_internal(__sn__UdpSocket *socket) {
    for (int i = 0; i < udp_socket_count; i++) {
        if (udp_socket_table[i].socket == socket) {
            return udp_socket_table[i].internal;
        }
    }
    return NULL;
}

static void udp_register_internal(__sn__UdpSocket *socket, UdpSocketInternal *internal) {
    for (int i = 0; i < udp_socket_count; i++) {
        if (udp_socket_table[i].socket == socket) {
            udp_socket_table[i].internal = internal;
            return;
        }
    }
    if (udp_socket_count < MAX_UDP_SOCKETS) {
        udp_socket_table[udp_socket_count].socket = socket;
        udp_socket_table[udp_socket_count].internal = internal;
        udp_socket_count++;
    } else {
        fprintf(stderr, "sn_udp: too many open sockets\n");
        exit(1);
    }
}

static void udp_unregister_internal(__sn__UdpSocket *socket) {
    for (int i = 0; i < udp_socket_count; i++) {
        if (udp_socket_table[i].socket == socket) {
            udp_socket_table[i] = udp_socket_table[udp_socket_count - 1];
            udp_socket_count--;
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
 * Helper Functions
 * ============================================================================ */

/* Wait for socket to be readable with timeout.
 * Returns: 1 = readable, 0 = timeout, -1 = error */
static int udp_wait_readable(__sn__UdpSocket *socket_obj, UdpSocketInternal *internal) {
    if (internal->recv_timeout_ms < 0) {
        return 1;  /* Blocking mode - assume readable */
    }

    socket_t fd = (socket_t)socket_obj->socket_fd;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    struct timeval tv;
    struct timeval *tvp = NULL;

    if (internal->recv_timeout_ms > 0) {
        tv.tv_sec = internal->recv_timeout_ms / 1000;
        tv.tv_usec = (internal->recv_timeout_ms % 1000) * 1000;
        tvp = &tv;
    } else {
        /* Non-blocking: zero timeout */
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        tvp = &tv;
    }

    int result = select((int)(fd + 1), &readfds, NULL, NULL, tvp);
    return result;
}

/* Parse address string "host:port" or ":port" into host and port components */
static int parse_bind_address(char *address, char *host, size_t host_len, int *port) {
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
static int parse_dest_address(char *address, struct sockaddr_in *dest_addr) {
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

__sn__UdpSocket *sn_udp_socket_bind(char *address) {
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

    __sn__UdpSocket *socket_obj = (__sn__UdpSocket *)calloc(1, sizeof(__sn__UdpSocket));
    if (socket_obj == NULL) {
        CLOSE_SOCKET(sock);
        fprintf(stderr, "sn_udp_socket_bind: allocation failed\n");
        exit(1);
    }
    socket_obj->socket_fd = (long long)sock;
    socket_obj->bound_port = (long long)actual_port;

    /* Create internal state */
    UdpSocketInternal *internal = (UdpSocketInternal *)calloc(1, sizeof(UdpSocketInternal));
    if (internal == NULL) {
        CLOSE_SOCKET(sock);
        free(socket_obj);
        fprintf(stderr, "sn_udp_socket_bind: internal allocation failed\n");
        exit(1);
    }
    internal->recv_timeout_ms = -1;
    udp_register_internal(socket_obj, internal);

    return socket_obj;
}

/* ============================================================================
 * UdpSocket Send/Receive
 * ============================================================================ */

/* Send datagram to address, return bytes sent */
long long sn_udp_socket_send_to(__sn__UdpSocket *socket_obj, SnArray *data, char *address) {
    if (socket_obj == NULL || data == NULL || address == NULL) return 0;

    struct sockaddr_in dest_addr;
    if (!parse_dest_address(address, &dest_addr)) {
        fprintf(stderr, "sn_udp_socket_send_to: invalid address '%s'\n", address);
        exit(1);
    }

    long long length = sn_array_length(data);
    if (length == 0) return 0;

    socket_t fd = (socket_t)socket_obj->socket_fd;
    int bytes_sent = sendto(fd, (const char *)data->data, (int)length, 0,
                            (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (bytes_sent < 0) {
        fprintf(stderr, "sn_udp_socket_send_to: sendto failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }

    return (long long)bytes_sent;
}

/* Receive datagram and sender address */
__sn__UdpReceiveResult *sn_udp_socket_receive_from(__sn__UdpSocket *socket_obj, long long maxBytes) {
    __sn__UdpReceiveResult *result = (__sn__UdpReceiveResult *)calloc(1, sizeof(__sn__UdpReceiveResult));
    if (result == NULL) {
        fprintf(stderr, "sn_udp_socket_receive_from: allocation failed\n");
        exit(1);
    }

    if (socket_obj == NULL || maxBytes <= 0) {
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        result->data = arr;
        result->sender = strdup("");
        return result;
    }

    UdpSocketInternal *internal = udp_get_internal(socket_obj);

    /* Wait for data with timeout if configured */
    if (internal != NULL && internal->recv_timeout_ms >= 0) {
        int wait_result = udp_wait_readable(socket_obj, internal);
        if (wait_result == 0) {
            SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
            arr->elem_tag = SN_TAG_BYTE;
            result->data = arr;
            result->sender = strdup("");
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

    socket_t fd = (socket_t)socket_obj->socket_fd;
    int bytes_received = recvfrom(fd, (char *)temp,
                                   (int)maxBytes, 0, (struct sockaddr *)&sender_addr, &sender_len);

    if (bytes_received < 0) {
        free(temp);
        fprintf(stderr, "sn_udp_socket_receive_from: recvfrom failed (%d)\n", GET_SOCKET_ERROR());
        exit(1);
    }

    SnArray *arr = sn_array_new(sizeof(unsigned char), (long long)bytes_received);
    arr->elem_tag = SN_TAG_BYTE;
    if (bytes_received > 0) {
        memcpy(arr->data, temp, (size_t)bytes_received);
        arr->len = (long long)bytes_received;
    }
    free(temp);

    result->data = arr;

    char sender_str[64];
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sender_addr.sin_addr, ip_str, sizeof(ip_str));
    snprintf(sender_str, sizeof(sender_str), "%s:%d", ip_str, ntohs(sender_addr.sin_port));

    result->sender = strdup(sender_str);
    if (result->sender == NULL) {
        fprintf(stderr, "sn_udp_socket_receive_from: sender allocation failed\n");
        exit(1);
    }

    return result;
}

/* ============================================================================
 * UdpSocket Getters
 * ============================================================================ */

long long sn_udp_socket_get_port(__sn__UdpSocket *socket_obj) {
    if (socket_obj == NULL) return 0;
    return socket_obj->bound_port;
}

/* ============================================================================
 * UdpSocket Lifecycle
 * ============================================================================ */

void sn_udp_socket_dispose(__sn__UdpSocket *socket_obj) {
    if (socket_obj == NULL) return;

    socket_t fd = (socket_t)socket_obj->socket_fd;

    if (fd != INVALID_SOCKET_VAL) {
        CLOSE_SOCKET(fd);
        socket_obj->socket_fd = (long long)INVALID_SOCKET_VAL;
    }

    /* Free internal state */
    UdpSocketInternal *internal = udp_get_internal(socket_obj);
    if (internal != NULL) {
        udp_unregister_internal(socket_obj);
        free(internal);
    }
}

/* ============================================================================
 * UdpReceiveResult Getters
 * ============================================================================ */

SnArray *sn_udp_result_get_data(__sn__UdpReceiveResult *result) {
    if (result == NULL) {
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
    }
    if (result->data == NULL) {
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
    }
    /* Return a copy — the caller gets its own sn_auto_arr cleanup,
     * and UdpReceiveResult_release will clean up the original. */
    return sn_array_copy((SnArray *)result->data);
}

char *sn_udp_result_get_sender(__sn__UdpReceiveResult *result) {
    if (result == NULL) {
        return strdup("");
    }
    if (result->sender == NULL) {
        return strdup("");
    }
    return strdup(result->sender);
}
