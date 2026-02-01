/* ==============================================================================
 * sdk/net/ssh.sn.c - SSH Client and Server Implementation
 * ==============================================================================
 * This file provides the C implementation for SSH client (SshConnection) and
 * server (SshListener, SshSession, SshChannel) using libssh with OpenSSL backend.
 * It is compiled via @source and linked with Sindarin code.
 *
 * Known hosts verification priority:
 *   1. SN_SSH_KNOWN_HOSTS environment variable (path to known_hosts file)
 *   2. Platform default (~/.ssh/known_hosts or %USERPROFILE%\.ssh\known_hosts)
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Include runtime for proper memory management */
#include "runtime/runtime_arena.h"
#include "runtime/array/runtime_array.h"
#include "runtime/arena/managed_arena.h"
#include "runtime/string/runtime_string_h.h"

/* libssh includes */
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

/* Platform-specific includes */
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>

    #ifndef PATH_MAX
        #define PATH_MAX 260
    #endif
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <errno.h>
    #include <limits.h>
#endif

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

typedef struct RtSshExecResult {
    char *stdout_str;
    char *stderr_str;
    long exit_code;
} RtSshExecResult;

typedef struct RtSshConnection {
    void *session_ptr;          /* ssh_session handle */
    char *remote_addr;          /* Remote address string (host:port) */
} RtSshConnection;

/* Server types */

typedef struct {
    char *username;
    char *password;
} SshUserCredential;

typedef struct RtSshServerConfig {
    char *host_key_path;
    SshUserCredential *users;
    long user_count;
    char *authorized_keys_dir;
} RtSshServerConfig;

typedef struct RtSshListener {
    void *bind_ptr;             /* ssh_bind handle */
    long bound_port;
    RtSshServerConfig *config_ptr;
} RtSshListener;

typedef struct RtSshSession {
    void *session_ptr;          /* ssh_session handle */
    char *username;
    char *remote_addr;
} RtSshSession;

typedef struct RtSshChannel {
    void *channel_ptr;          /* ssh_channel handle */
    char *command_str;
    long is_shell;
} RtSshChannel;

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

void sn_ssh_close(RtSshConnection *conn);

/* ============================================================================
 * libssh Initialization (one-time)
 * ============================================================================ */

static int libssh_initialized = 0;

static void ensure_libssh_initialized(void) {
    if (!libssh_initialized) {
        int rc = ssh_init();
        if (rc != SSH_OK) {
            fprintf(stderr, "SshConnection: ssh_init failed\n");
            exit(1);
        }
        libssh_initialized = 1;
    }
}

/* ============================================================================
 * Known Hosts Verification
 * ============================================================================ */

static void ssh_verify_known_host(ssh_session session) {
    /* Determine known_hosts file path */
    char known_hosts_path[PATH_MAX];
    const char *env_path = getenv("SN_SSH_KNOWN_HOSTS");
    if (env_path && env_path[0] != '\0') {
        /* If set to /dev/null or empty-like path, skip verification */
        if (strcmp(env_path, "/dev/null") == 0) {
            return;
        }
        strncpy(known_hosts_path, env_path, sizeof(known_hosts_path) - 1);
        known_hosts_path[sizeof(known_hosts_path) - 1] = '\0';
        ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_path);
    } else {
#ifdef _WIN32
        const char *home = getenv("USERPROFILE");
#else
        const char *home = getenv("HOME");
#endif
        if (home) {
            snprintf(known_hosts_path, sizeof(known_hosts_path),
                     "%s/.ssh/known_hosts", home);
            ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_path);
        } else {
            return; /* Can't find known_hosts, skip */
        }
    }

    enum ssh_known_hosts_e state = ssh_session_is_known_server(session);

    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* Host key matches */
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf(stderr, "SshConnection: HOST KEY CHANGED - "
                    "possible man-in-the-middle attack!\n");
            exit(1);
        case SSH_KNOWN_HOSTS_NOT_FOUND:
        case SSH_KNOWN_HOSTS_UNKNOWN:
            /* Trust on first use */
            break;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr, "SshConnection: host key type mismatch\n");
            exit(1);
        case SSH_KNOWN_HOSTS_ERROR:
            /* Error checking, proceed anyway (TOFU behavior) */
            break;
    }
}

/* ============================================================================
 * Address Parsing (host:port with default port 22)
 * ============================================================================ */

static int ssh_parse_address(const char *address, char *host, size_t host_len, int *port) {
    if (address == NULL) return 0;

    const char *last_colon = NULL;

    /* Handle IPv6 addresses like [::1]:22 */
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
            *port = 22; /* Default SSH port */
        }
        return 1;
    }

    /* Find the last colon (for host:port format) */
    for (const char *p = address; *p; p++) {
        if (*p == ':') last_colon = p;
    }

    if (last_colon == NULL) {
        /* No port specified - use hostname as-is with default port 22 */
        size_t len = strlen(address);
        if (len >= host_len) return 0;
        strcpy(host, address);
        *port = 22;
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
 * Internal: SSH Session Connect + Handshake
 * ============================================================================ */

static RtSshConnection *ssh_connect_and_handshake(RtArena *arena, const char *address) {
    ensure_libssh_initialized();

    if (address == NULL) {
        fprintf(stderr, "SshConnection: NULL address\n");
        exit(1);
    }

    char host[256];
    int port;

    if (!ssh_parse_address(address, host, sizeof(host), &port)) {
        fprintf(stderr, "SshConnection: invalid address format '%s'\n", address);
        exit(1);
    }

    /* Create SSH session */
    ssh_session session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "SshConnection: ssh_new() failed\n");
        exit(1);
    }

    /* Set connection options */
    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);

    /* Connect */
    int rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "SshConnection: connection failed to '%s': %s\n",
                address, ssh_get_error(session));
        ssh_free(session);
        exit(1);
    }

    /* Verify known hosts */
    ssh_verify_known_host(session);

    /* Allocate Connection Struct */
    RtSshConnection *conn = (RtSshConnection *)rt_arena_alloc(arena, sizeof(RtSshConnection));
    if (!conn) {
        fprintf(stderr, "SshConnection: allocation failed\n");
        ssh_disconnect(session);
        ssh_free(session);
        exit(1);
    }

    conn->session_ptr = session;

    /* Copy address string into arena */
    size_t addr_len = strlen(address) + 1;
    conn->remote_addr = (char *)rt_arena_alloc(arena, addr_len);
    if (conn->remote_addr) {
        memcpy(conn->remote_addr, address, addr_len);
    }

    return conn;
}

/* ============================================================================
 * Authentication: Password
 * ============================================================================ */

RtSshConnection *sn_ssh_connect_password(RtArena *arena, const char *address,
                                           const char *username, const char *password) {
    RtSshConnection *conn = ssh_connect_and_handshake(arena, address);
    ssh_session session = (ssh_session)conn->session_ptr;

    int rc = ssh_userauth_password(session, username, password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "SshConnection.connectPassword: auth failed for '%s@%s': %s\n",
                username, address, ssh_get_error(session));
        sn_ssh_close(conn);
        exit(1);
    }

    return conn;
}

/* ============================================================================
 * Authentication: Public Key
 * ============================================================================ */

RtSshConnection *sn_ssh_connect_key(RtArena *arena, const char *address,
                                      const char *username, const char *privateKeyPath,
                                      const char *passphrase) {
    RtSshConnection *conn = ssh_connect_and_handshake(arena, address);
    ssh_session session = (ssh_session)conn->session_ptr;

    /* If passphrase is empty string, pass NULL */
    const char *pp = (passphrase && passphrase[0] != '\0') ? passphrase : NULL;

    /* Import private key */
    ssh_key privkey = NULL;
    int rc = ssh_pki_import_privkey_file(privateKeyPath, pp, NULL, NULL, &privkey);
    if (rc != SSH_OK) {
        fprintf(stderr, "SshConnection.connectKey: failed to load key '%s': %s\n",
                privateKeyPath, ssh_get_error(session));
        sn_ssh_close(conn);
        exit(1);
    }

    /* Authenticate with key */
    rc = ssh_userauth_publickey(session, username, privkey);
    ssh_key_free(privkey);

    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "SshConnection.connectKey: auth failed for '%s@%s' with key '%s': %s\n",
                username, address, privateKeyPath, ssh_get_error(session));
        sn_ssh_close(conn);
        exit(1);
    }

    return conn;
}

/* ============================================================================
 * Authentication: SSH Agent
 * ============================================================================ */

RtSshConnection *sn_ssh_connect_agent(RtArena *arena, const char *address,
                                        const char *username) {
    RtSshConnection *conn = ssh_connect_and_handshake(arena, address);
    ssh_session session = (ssh_session)conn->session_ptr;

    int rc = ssh_userauth_agent(session, username);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "SshConnection.connectAgent: auth failed for '%s@%s': %s\n",
                username, address, ssh_get_error(session));
        sn_ssh_close(conn);
        exit(1);
    }

    return conn;
}

/* ============================================================================
 * Authentication: Keyboard-Interactive
 * ============================================================================ */

RtSshConnection *sn_ssh_connect_interactive(RtArena *arena, const char *address,
                                              const char *username, const char *password) {
    RtSshConnection *conn = ssh_connect_and_handshake(arena, address);
    ssh_session session = (ssh_session)conn->session_ptr;

    int rc = ssh_userauth_kbdint(session, username, NULL);

    while (rc == SSH_AUTH_INFO) {
        int nprompts = ssh_userauth_kbdint_getnprompts(session);
        for (int i = 0; i < nprompts; i++) {
            ssh_userauth_kbdint_setanswer(session, i, password);
        }
        rc = ssh_userauth_kbdint(session, username, NULL);
    }

    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "SshConnection.connectInteractive: auth failed for '%s@%s': %s\n",
                username, address, ssh_get_error(session));
        sn_ssh_close(conn);
        exit(1);
    }

    return conn;
}

/* ============================================================================
 * Command Execution (Internal)
 * ============================================================================ */

static RtSshExecResult *ssh_exec_internal(RtArena *arena, RtSshConnection *conn,
                                            const char *command) {
    if (!conn || !conn->session_ptr) {
        fprintf(stderr, "SshConnection.exec: connection is closed\n");
        exit(1);
    }

    ssh_session session = (ssh_session)conn->session_ptr;

    /* Open a channel */
    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) {
        fprintf(stderr, "SshConnection.exec: channel creation failed: %s\n",
                ssh_get_error(session));
        exit(1);
    }

    int rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "SshConnection.exec: channel open failed: %s\n",
                ssh_get_error(session));
        ssh_channel_free(channel);
        exit(1);
    }

    /* Execute the command */
    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        fprintf(stderr, "SshConnection.exec: exec failed for command '%s': %s\n",
                command, ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        exit(1);
    }

    /* Read stdout */
    size_t out_cap = 4096, out_len = 0;
    char *out_buf = (char *)malloc(out_cap);
    if (!out_buf) {
        fprintf(stderr, "SshConnection.exec: allocation failed\n");
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        exit(1);
    }

    /* Read stderr */
    size_t err_cap = 4096, err_len = 0;
    char *err_buf = (char *)malloc(err_cap);
    if (!err_buf) {
        fprintf(stderr, "SshConnection.exec: allocation failed\n");
        free(out_buf);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        exit(1);
    }

    /* Read both stdout and stderr until EOF */
    while (!ssh_channel_is_eof(channel)) {
        int n;

        /* Read stdout (is_stderr=0) */
        n = ssh_channel_read(channel, out_buf + out_len, (uint32_t)(out_cap - out_len - 1), 0);
        if (n > 0) {
            out_len += n;
            if (out_len >= out_cap - 1) {
                out_cap *= 2;
                char *new_buf = (char *)realloc(out_buf, out_cap);
                if (!new_buf) {
                    fprintf(stderr, "SshConnection.exec: realloc failed\n");
                    free(out_buf);
                    free(err_buf);
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    exit(1);
                }
                out_buf = new_buf;
            }
        }

        /* Read stderr (is_stderr=1) */
        n = ssh_channel_read(channel, err_buf + err_len, (uint32_t)(err_cap - err_len - 1), 1);
        if (n > 0) {
            err_len += n;
            if (err_len >= err_cap - 1) {
                err_cap *= 2;
                char *new_buf = (char *)realloc(err_buf, err_cap);
                if (!new_buf) {
                    fprintf(stderr, "SshConnection.exec: realloc failed\n");
                    free(out_buf);
                    free(err_buf);
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    exit(1);
                }
                err_buf = new_buf;
            }
        }
    }

    out_buf[out_len] = '\0';
    err_buf[err_len] = '\0';

    /* Send our EOF, then wait for channel close from remote.
     * This ensures we receive the exit-status message before querying it. */
    ssh_channel_send_eof(channel);

    /* Poll until channel is closed by remote or exit status is available.
     * The exit status arrives as a separate SSH message after EOF. */
    int exit_code = -1;
    int wait_attempts = 0;
    while (!ssh_channel_is_closed(channel) && wait_attempts < 50) {
        exit_code = ssh_channel_get_exit_status(channel);
        if (exit_code != -1) break;
        /* Read with short timeout to process incoming messages */
        char tmp[1];
        ssh_channel_read_timeout(channel, tmp, 1, 0, 100);
        wait_attempts++;
    }
    if (exit_code == -1) {
        exit_code = ssh_channel_get_exit_status(channel);
    }

    ssh_channel_close(channel);
    ssh_channel_free(channel);

    /* Allocate result in arena */
    RtSshExecResult *result = (RtSshExecResult *)rt_arena_alloc(arena, sizeof(RtSshExecResult));
    if (!result) {
        fprintf(stderr, "SshConnection.exec: result allocation failed\n");
        free(out_buf);
        free(err_buf);
        exit(1);
    }

    /* Copy stdout to arena */
    result->stdout_str = (char *)rt_arena_alloc(arena, out_len + 1);
    if (result->stdout_str) {
        memcpy(result->stdout_str, out_buf, out_len + 1);
    }

    /* Copy stderr to arena */
    result->stderr_str = (char *)rt_arena_alloc(arena, err_len + 1);
    if (result->stderr_str) {
        memcpy(result->stderr_str, err_buf, err_len + 1);
    }

    result->exit_code = exit_code;

    free(out_buf);
    free(err_buf);

    return result;
}

/* ============================================================================
 * Public API: Command Execution
 * ============================================================================ */

/* Execute command, return stdout only */
RtHandle sn_ssh_run(RtManagedArena *arena, RtSshConnection *conn, const char *command) {
    RtSshExecResult *result = ssh_exec_internal((RtArena *)arena, conn, command);
    return rt_managed_strdup(arena, RT_HANDLE_NULL, result->stdout_str ? result->stdout_str : "");
}

/* Execute command, return full result struct */
RtSshExecResult *sn_ssh_exec(RtArena *arena, RtSshConnection *conn, const char *command) {
    return ssh_exec_internal(arena, conn, command);
}

/* ============================================================================
 * Getters
 * ============================================================================ */

RtHandle sn_ssh_get_remote_address(RtManagedArena *arena, RtSshConnection *conn) {
    if (conn == NULL || conn->remote_addr == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }
    return rt_managed_strdup(arena, RT_HANDLE_NULL, conn->remote_addr);
}

RtHandle sn_ssh_exec_result_get_stdout(RtManagedArena *arena, RtSshExecResult *result) {
    if (result == NULL || result->stdout_str == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }
    return rt_managed_strdup(arena, RT_HANDLE_NULL, result->stdout_str);
}

RtHandle sn_ssh_exec_result_get_stderr(RtManagedArena *arena, RtSshExecResult *result) {
    if (result == NULL || result->stderr_str == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }
    return rt_managed_strdup(arena, RT_HANDLE_NULL, result->stderr_str);
}

long sn_ssh_exec_result_get_exit_code(RtSshExecResult *result) {
    if (result == NULL) return -1;
    return result->exit_code;
}

/* ============================================================================
 * Lifecycle: Close (Client)
 * ============================================================================ */

void sn_ssh_close(RtSshConnection *conn) {
    if (conn == NULL) return;

    if (conn->session_ptr != NULL) {
        ssh_session session = (ssh_session)conn->session_ptr;
        ssh_disconnect(session);
        ssh_free(session);
        conn->session_ptr = NULL;
    }
}

/* ============================================================================
 * Server: SshServerConfig
 * ============================================================================ */

#define SSH_MAX_USERS 64

RtSshServerConfig *sn_ssh_server_config_defaults(RtArena *arena) {
    RtSshServerConfig *config = (RtSshServerConfig *)rt_arena_alloc(arena, sizeof(RtSshServerConfig));
    if (!config) {
        fprintf(stderr, "SshServerConfig.defaults: allocation failed\n");
        exit(1);
    }
    config->host_key_path = NULL;
    config->users = (SshUserCredential *)rt_arena_alloc(arena, sizeof(SshUserCredential) * SSH_MAX_USERS);
    config->user_count = 0;
    config->authorized_keys_dir = NULL;
    return config;
}

RtSshServerConfig *sn_ssh_server_config_set_host_key(RtArena *arena, RtSshServerConfig *config, const char *path) {
    (void)arena;
    if (!config || !path) return config;
    size_t len = strlen(path) + 1;
    config->host_key_path = (char *)rt_arena_alloc(arena, len);
    if (config->host_key_path) {
        memcpy(config->host_key_path, path, len);
    }
    return config;
}

RtSshServerConfig *sn_ssh_server_config_add_user(RtArena *arena, RtSshServerConfig *config,
                                                   const char *username, const char *password) {
    if (!config || !username || !password) return config;
    if (config->user_count >= SSH_MAX_USERS) {
        fprintf(stderr, "SshServerConfig.addUser: max users (%d) exceeded\n", SSH_MAX_USERS);
        exit(1);
    }

    int idx = (int)config->user_count;

    size_t ulen = strlen(username) + 1;
    config->users[idx].username = (char *)rt_arena_alloc(arena, ulen);
    if (config->users[idx].username) {
        memcpy(config->users[idx].username, username, ulen);
    }

    size_t plen = strlen(password) + 1;
    config->users[idx].password = (char *)rt_arena_alloc(arena, plen);
    if (config->users[idx].password) {
        memcpy(config->users[idx].password, password, plen);
    }

    config->user_count++;
    return config;
}

RtSshServerConfig *sn_ssh_server_config_set_authorized_keys_dir(RtArena *arena,
                                                                   RtSshServerConfig *config,
                                                                   const char *path) {
    if (!config || !path) return config;
    size_t len = strlen(path) + 1;
    config->authorized_keys_dir = (char *)rt_arena_alloc(arena, len);
    if (config->authorized_keys_dir) {
        memcpy(config->authorized_keys_dir, path, len);
    }
    return config;
}

/* ============================================================================
 * Server: SshListener
 * ============================================================================ */

static RtSshListener *ssh_listener_bind_internal(RtArena *arena, const char *address,
                                                   RtSshServerConfig *config) {
    ensure_libssh_initialized();

    if (!address) {
        fprintf(stderr, "SshListener.bind: NULL address\n");
        exit(1);
    }
    if (!config || !config->host_key_path) {
        fprintf(stderr, "SshListener.bind: host key path is required\n");
        exit(1);
    }

    char host[256];
    int port;
    if (!ssh_parse_address(address, host, sizeof(host), &port)) {
        fprintf(stderr, "SshListener.bind: invalid address format '%s'\n", address);
        exit(1);
    }

    ssh_bind sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "SshListener.bind: ssh_bind_new() failed\n");
        exit(1);
    }

    /* Set bind options */
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, host);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, config->host_key_path);

    /* Listen */
    int rc = ssh_bind_listen(sshbind);
    if (rc != SSH_OK) {
        fprintf(stderr, "SshListener.bind: listen failed on '%s': %s\n",
                address, ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        exit(1);
    }

    /* Determine actual bound port */
    int actual_port = port;
    if (port == 0) {
        /* Get the actual port from the bind socket */
        socket_t sock_handle = ssh_bind_get_fd(sshbind);
        if (sock_handle >= 0) {
            struct sockaddr_storage addr_storage;
            socklen_t addr_len = sizeof(addr_storage);
            if (getsockname(sock_handle, (struct sockaddr *)&addr_storage, &addr_len) == 0) {
                if (addr_storage.ss_family == AF_INET) {
                    actual_port = ntohs(((struct sockaddr_in *)&addr_storage)->sin_port);
                } else if (addr_storage.ss_family == AF_INET6) {
                    actual_port = ntohs(((struct sockaddr_in6 *)&addr_storage)->sin6_port);
                }
            }
        }
    }

    /* Allocate listener */
    RtSshListener *listener = (RtSshListener *)rt_arena_alloc(arena, sizeof(RtSshListener));
    if (!listener) {
        fprintf(stderr, "SshListener.bind: allocation failed\n");
        ssh_bind_free(sshbind);
        exit(1);
    }

    listener->bind_ptr = sshbind;
    listener->bound_port = actual_port;
    listener->config_ptr = config;

    return listener;
}

RtSshListener *sn_ssh_listener_bind(RtArena *arena, const char *address, const char *hostKeyPath) {
    /* Create a simple config with just the host key */
    RtSshServerConfig *config = sn_ssh_server_config_defaults(arena);
    sn_ssh_server_config_set_host_key(arena, config, hostKeyPath);
    return ssh_listener_bind_internal(arena, address, config);
}

RtSshListener *sn_ssh_listener_bind_with(RtArena *arena, const char *address,
                                            RtSshServerConfig *config) {
    return ssh_listener_bind_internal(arena, address, config);
}

long sn_ssh_listener_port(RtSshListener *listener) {
    if (!listener) return 0;
    return listener->bound_port;
}

void sn_ssh_listener_close(RtSshListener *listener) {
    if (!listener) return;
    if (listener->bind_ptr) {
        ssh_bind_free((ssh_bind)listener->bind_ptr);
        listener->bind_ptr = NULL;
    }
}

/* ============================================================================
 * Server: Accept Session (Authentication)
 * ============================================================================ */

RtSshSession *sn_ssh_listener_accept(RtArena *arena, RtSshListener *listener) {
    if (!listener || !listener->bind_ptr) {
        fprintf(stderr, "SshListener.accept: listener is closed\n");
        exit(1);
    }

    ssh_bind sshbind = (ssh_bind)listener->bind_ptr;
    RtSshServerConfig *config = listener->config_ptr;

    /* Create a new session for the incoming connection */
    ssh_session session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "SshListener.accept: ssh_new() failed\n");
        exit(1);
    }

    /* Accept the incoming connection */
    int rc = ssh_bind_accept(sshbind, session);
    if (rc != SSH_OK) {
        fprintf(stderr, "SshListener.accept: accept failed: %s\n",
                ssh_get_error(sshbind));
        ssh_free(session);
        exit(1);
    }

    /* Perform key exchange */
    rc = ssh_handle_key_exchange(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "SshListener.accept: key exchange failed: %s\n",
                ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        exit(1);
    }

    /* Authentication message loop */
    char *auth_username = NULL;
    int authenticated = 0;
    int max_attempts = 20;

    for (int attempt = 0; attempt < max_attempts && !authenticated; attempt++) {
        ssh_message msg = ssh_message_get(session);
        if (msg == NULL) {
            break;
        }

        int msg_type = ssh_message_type(msg);
        int msg_subtype = ssh_message_subtype(msg);

        if (msg_type == SSH_REQUEST_AUTH) {
            if (msg_subtype == SSH_AUTH_METHOD_PASSWORD) {
                const char *user = ssh_message_auth_user(msg);
                const char *pass = ssh_message_auth_password(msg);

                /* Check against configured credentials */
                if (config && config->users) {
                    for (int i = 0; i < config->user_count; i++) {
                        if (strcmp(user, config->users[i].username) == 0 &&
                            strcmp(pass, config->users[i].password) == 0) {
                            authenticated = 1;
                            /* Copy username */
                            size_t ulen = strlen(user) + 1;
                            auth_username = (char *)rt_arena_alloc(arena, ulen);
                            if (auth_username) memcpy(auth_username, user, ulen);
                            break;
                        }
                    }
                }

                if (authenticated) {
                    ssh_message_auth_reply_success(msg, 0);
                } else {
                    ssh_message_reply_default(msg);
                }
            } else if (msg_subtype == SSH_AUTH_METHOD_NONE) {
                /* Client is querying supported auth methods */
                ssh_message_auth_set_methods(msg, SSH_AUTH_METHOD_PASSWORD);
                ssh_message_reply_default(msg);
            } else {
                /* Unsupported auth method */
                ssh_message_auth_set_methods(msg, SSH_AUTH_METHOD_PASSWORD);
                ssh_message_reply_default(msg);
            }
        } else {
            ssh_message_reply_default(msg);
        }

        ssh_message_free(msg);
    }

    if (!authenticated) {
        fprintf(stderr, "SshListener.accept: authentication failed\n");
        ssh_disconnect(session);
        ssh_free(session);
        exit(1);
    }

    /* Get remote address info */
    char remote_addr_buf[256] = "";
    struct sockaddr_storage addr_storage;
    socklen_t addr_len = sizeof(addr_storage);
    socket_t client_fd = ssh_get_fd(session);
    if (client_fd >= 0) {
        if (getpeername(client_fd, (struct sockaddr *)&addr_storage, &addr_len) == 0) {
            char ip[INET6_ADDRSTRLEN];
            int peer_port = 0;
            if (addr_storage.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&addr_storage;
                inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
                peer_port = ntohs(s->sin_port);
            } else {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr_storage;
                inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof(ip));
                peer_port = ntohs(s->sin6_port);
            }
            snprintf(remote_addr_buf, sizeof(remote_addr_buf), "%s:%d", ip, peer_port);
        }
    }

    /* Allocate session struct */
    RtSshSession *sess = (RtSshSession *)rt_arena_alloc(arena, sizeof(RtSshSession));
    if (!sess) {
        fprintf(stderr, "SshListener.accept: session allocation failed\n");
        ssh_disconnect(session);
        ssh_free(session);
        exit(1);
    }

    sess->session_ptr = session;
    sess->username = auth_username;

    size_t rlen = strlen(remote_addr_buf) + 1;
    sess->remote_addr = (char *)rt_arena_alloc(arena, rlen);
    if (sess->remote_addr) {
        memcpy(sess->remote_addr, remote_addr_buf, rlen);
    }

    return sess;
}

/* ============================================================================
 * Server: SshSession
 * ============================================================================ */

RtHandle sn_ssh_session_get_username(RtManagedArena *arena, RtSshSession *session) {
    if (!session || !session->username) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }
    return rt_managed_strdup(arena, RT_HANDLE_NULL, session->username);
}

RtHandle sn_ssh_session_get_remote_address(RtManagedArena *arena, RtSshSession *session) {
    if (!session || !session->remote_addr) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }
    return rt_managed_strdup(arena, RT_HANDLE_NULL, session->remote_addr);
}

void sn_ssh_session_close(RtSshSession *session) {
    if (!session) return;
    if (session->session_ptr) {
        ssh_disconnect((ssh_session)session->session_ptr);
        ssh_free((ssh_session)session->session_ptr);
        session->session_ptr = NULL;
    }
}

/* ============================================================================
 * Server: Accept Channel
 * ============================================================================ */

RtSshChannel *sn_ssh_session_accept_channel(RtArena *arena, RtSshSession *session) {
    if (!session || !session->session_ptr) {
        fprintf(stderr, "SshSession.acceptChannel: session is closed\n");
        exit(1);
    }

    ssh_session ssh_sess = (ssh_session)session->session_ptr;
    ssh_channel channel = NULL;
    char *command = NULL;
    int is_shell = 0;
    int got_channel = 0;
    int got_request = 0;

    /* Message loop: wait for channel open, then exec/shell request */
    int max_messages = 100;
    for (int i = 0; i < max_messages && !got_request; i++) {
        ssh_message msg = ssh_message_get(ssh_sess);
        if (msg == NULL) {
            break;
        }

        int msg_type = ssh_message_type(msg);
        int msg_subtype = ssh_message_subtype(msg);

        if (!got_channel && msg_type == SSH_REQUEST_CHANNEL_OPEN) {
            if (msg_subtype == SSH_CHANNEL_SESSION) {
                channel = ssh_message_channel_request_open_reply_accept(msg);
                if (channel) {
                    got_channel = 1;
                }
            } else {
                ssh_message_reply_default(msg);
            }
        } else if (got_channel && msg_type == SSH_REQUEST_CHANNEL) {
            if (msg_subtype == SSH_CHANNEL_REQUEST_EXEC) {
                const char *cmd = ssh_message_channel_request_command(msg);
                if (cmd) {
                    size_t clen = strlen(cmd) + 1;
                    command = (char *)rt_arena_alloc(arena, clen);
                    if (command) memcpy(command, cmd, clen);
                }
                is_shell = 0;
                ssh_message_channel_request_reply_success(msg);
                got_request = 1;
            } else if (msg_subtype == SSH_CHANNEL_REQUEST_SHELL) {
                is_shell = 1;
                ssh_message_channel_request_reply_success(msg);
                got_request = 1;
            } else if (msg_subtype == SSH_CHANNEL_REQUEST_PTY) {
                /* Accept PTY request, continue waiting for shell/exec */
                ssh_message_channel_request_reply_success(msg);
            } else {
                ssh_message_reply_default(msg);
            }
        } else {
            ssh_message_reply_default(msg);
        }

        ssh_message_free(msg);
    }

    if (!got_channel || !got_request) {
        fprintf(stderr, "SshSession.acceptChannel: no channel/request received\n");
        exit(1);
    }

    /* Allocate channel struct */
    RtSshChannel *ch = (RtSshChannel *)rt_arena_alloc(arena, sizeof(RtSshChannel));
    if (!ch) {
        fprintf(stderr, "SshSession.acceptChannel: allocation failed\n");
        exit(1);
    }

    ch->channel_ptr = channel;
    ch->command_str = command;
    ch->is_shell = is_shell;

    return ch;
}

/* ============================================================================
 * Server: SshChannel Operations
 * ============================================================================ */

RtHandle sn_ssh_channel_get_command(RtManagedArena *arena, RtSshChannel *channel) {
    if (!channel || !channel->command_str) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }
    return rt_managed_strdup(arena, RT_HANDLE_NULL, channel->command_str);
}

long sn_ssh_channel_is_shell(RtSshChannel *channel) {
    if (!channel) return 0;
    return channel->is_shell;
}

unsigned char *sn_ssh_channel_read(RtArena *arena, RtSshChannel *channel, long maxBytes) {
    if (!channel || !channel->channel_ptr || maxBytes <= 0) {
        return rt_array_create_byte(arena, 0, NULL);
    }

    ssh_channel ch = (ssh_channel)channel->channel_ptr;

    /* Allocate temp buffer */
    size_t buf_size = (size_t)maxBytes;
    unsigned char *temp = (unsigned char *)malloc(buf_size);
    if (!temp) {
        return rt_array_create_byte(arena, 0, NULL);
    }

    int n = ssh_channel_read(ch, temp, (uint32_t)buf_size, 0);
    if (n <= 0) {
        free(temp);
        return rt_array_create_byte(arena, 0, NULL);
    }

    unsigned char *result = rt_array_create_byte(arena, (size_t)n, temp);
    free(temp);
    return result;
}

RtHandle sn_ssh_channel_read_line(RtManagedArena *arena, RtSshChannel *channel) {
    if (!channel || !channel->channel_ptr) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    ssh_channel ch = (ssh_channel)channel->channel_ptr;

    /* Read character by character until newline */
    size_t cap = 256, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    while (1) {
        char c;
        int n = ssh_channel_read(ch, &c, 1, 0);
        if (n <= 0) break; /* EOF or error */
        if (c == '\n') break;
        if (c == '\r') continue; /* Skip CR */

        if (len >= cap - 1) {
            cap *= 2;
            char *new_buf = (char *)realloc(buf, cap);
            if (!new_buf) break;
            buf = new_buf;
        }
        buf[len++] = c;
    }
    buf[len] = '\0';

    /* Copy to managed arena */
    RtHandle result = rt_managed_strdup(arena, RT_HANDLE_NULL, buf);
    free(buf);
    return result;
}

long sn_ssh_channel_write(RtSshChannel *channel, unsigned char *data) {
    if (!channel || !channel->channel_ptr || !data) return 0;

    size_t length = rt_array_length(data);
    if (length == 0) return 0;

    ssh_channel ch = (ssh_channel)channel->channel_ptr;
    int written = ssh_channel_write(ch, data, (uint32_t)length);
    if (written < 0) {
        fprintf(stderr, "SshChannel.write: write failed\n");
        exit(1);
    }
    return written;
}

void sn_ssh_channel_write_line(RtSshChannel *channel, const char *text) {
    if (!channel || !channel->channel_ptr) return;

    ssh_channel ch = (ssh_channel)channel->channel_ptr;

    if (text) {
        size_t len = strlen(text);
        if (len > 0) {
            int rc = ssh_channel_write(ch, text, (uint32_t)len);
            if (rc < 0) {
                fprintf(stderr, "SshChannel.writeLine: write failed\n");
                exit(1);
            }
        }
    }

    /* Send newline */
    int rc = ssh_channel_write(ch, "\n", 1);
    if (rc < 0) {
        fprintf(stderr, "SshChannel.writeLine: write newline failed\n");
        exit(1);
    }
}

void sn_ssh_channel_send_exit_status(RtSshChannel *channel, long code) {
    if (!channel || !channel->channel_ptr) return;
    ssh_channel ch = (ssh_channel)channel->channel_ptr;
    ssh_channel_request_send_exit_status(ch, (int)code);
}

void sn_ssh_channel_close(RtSshChannel *channel) {
    if (!channel) return;
    if (channel->channel_ptr) {
        ssh_channel ch = (ssh_channel)channel->channel_ptr;
        ssh_channel_send_eof(ch);
        ssh_channel_close(ch);
        ssh_channel_free(ch);
        channel->channel_ptr = NULL;
    }
}
