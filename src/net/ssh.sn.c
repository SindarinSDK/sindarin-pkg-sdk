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

/* No arena runtime — minimal runtime */

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

typedef __sn__SshExecResult RtSshExecResult;
typedef __sn__SshConnection RtSshConnection;
typedef __sn__SshServerConfig RtSshServerConfig;
typedef __sn__SshListener RtSshListener;
typedef __sn__SshSession RtSshSession;
typedef __sn__SshChannel RtSshChannel;

/* Server types */

typedef struct {
    char *username;
    char *password;
} SshUserCredential;

/* Internal data stored alongside SshServerConfig */
typedef struct {
    SshUserCredential *users;
    long long user_count;
    char *host_key_path;
    char *authorized_keys_dir;
} SshServerConfigInternal;

/* Internal data stored alongside structs that need extra fields */
static SshServerConfigInternal *g_ssh_config_internals[16] = {0};
static __sn__SshServerConfig *g_ssh_configs[16] = {0};
static int g_ssh_config_count = 0;

static void ssh_register_config(__sn__SshServerConfig *cfg, SshServerConfigInternal *internal) {
    if (g_ssh_config_count < 16) {
        g_ssh_configs[g_ssh_config_count] = cfg;
        g_ssh_config_internals[g_ssh_config_count] = internal;
        g_ssh_config_count++;
    }
}

static SshServerConfigInternal *ssh_find_config_internal(__sn__SshServerConfig *cfg) {
    for (int i = 0; i < g_ssh_config_count; i++) {
        if (g_ssh_configs[i] == cfg) return g_ssh_config_internals[i];
    }
    return NULL;
}

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

void sn_ssh_close(__sn__SshConnection *conn);

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

static __sn__SshConnection *ssh_connect_and_handshake(const char *address) {
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
    __sn__SshConnection *conn = (__sn__SshConnection *)calloc(1, sizeof(__sn__SshConnection));
    if (!conn) {
        fprintf(stderr, "SshConnection: allocation failed\n");
        ssh_disconnect(session);
        ssh_free(session);
        exit(1);
    }

    conn->session_ptr = session;
    conn->remote_addr = strdup(address);

    return conn;
}

/* ============================================================================
 * Authentication: Password
 * ============================================================================ */

__sn__SshConnection *sn_ssh_connect_password(char *address,
                                           char *username, char *password) {
    __sn__SshConnection *_conn = ssh_connect_and_handshake(address);
    ssh_session session = (ssh_session)_conn->session_ptr;

    int rc = ssh_userauth_password(session, username, password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "SshConnection.connectPassword: auth failed for '%s@%s': %s\n",
                username, address, ssh_get_error(session));
        sn_ssh_close(_conn);
        exit(1);
    }

    return _conn;
}

/* ============================================================================
 * Authentication: Public Key
 * ============================================================================ */

__sn__SshConnection *sn_ssh_connect_key(char *address,
                                      char *username, char *privateKeyPath,
                                      char *passphrase) {
    __sn__SshConnection *_conn = ssh_connect_and_handshake(address);
    ssh_session session = (ssh_session)_conn->session_ptr;

    /* If passphrase is empty string, pass NULL */
    const char *pp = (passphrase && passphrase[0] != '\0') ? passphrase : NULL;

    /* Import private key */
    ssh_key privkey = NULL;
    int rc = ssh_pki_import_privkey_file(privateKeyPath, pp, NULL, NULL, &privkey);
    if (rc != SSH_OK) {
        fprintf(stderr, "SshConnection.connectKey: failed to load key '%s': %s\n",
                privateKeyPath, ssh_get_error(session));
        sn_ssh_close(_conn);
        exit(1);
    }

    /* Authenticate with key */
    rc = ssh_userauth_publickey(session, username, privkey);
    ssh_key_free(privkey);

    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "SshConnection.connectKey: auth failed for '%s@%s' with key '%s': %s\n",
                username, address, privateKeyPath, ssh_get_error(session));
        sn_ssh_close(_conn);
        exit(1);
    }

    return _conn;
}

/* ============================================================================
 * Authentication: SSH Agent
 * ============================================================================ */

__sn__SshConnection *sn_ssh_connect_agent(char *address,
                                        char *username) {
    __sn__SshConnection *_conn = ssh_connect_and_handshake(address);
    ssh_session session = (ssh_session)_conn->session_ptr;

    int rc = ssh_userauth_agent(session, username);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "SshConnection.connectAgent: auth failed for '%s@%s': %s\n",
                username, address, ssh_get_error(session));
        sn_ssh_close(_conn);
        exit(1);
    }

    return _conn;
}

/* ============================================================================
 * Authentication: Keyboard-Interactive
 * ============================================================================ */

__sn__SshConnection *sn_ssh_connect_interactive(char *address,
                                              char *username, char *password) {
    __sn__SshConnection *_conn = ssh_connect_and_handshake(address);
    ssh_session session = (ssh_session)_conn->session_ptr;

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
        sn_ssh_close(_conn);
        exit(1);
    }

    return _conn;
}

/* ============================================================================
 * Command Execution (Internal)
 * ============================================================================ */

static __sn__SshExecResult *ssh_exec_internal(RtSshConnection *conn,
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

    /* Allocate result */
    RtSshExecResult *result = (RtSshExecResult *)calloc(1, sizeof(RtSshExecResult));
    if (!result) {
        fprintf(stderr, "SshConnection.exec: result allocation failed\n");
        free(out_buf);
        free(err_buf);
        exit(1);
    }

    result->stdout_str = strdup(out_buf);

    result->stderr_str = strdup(err_buf);

    result->exit_code = exit_code;

    free(out_buf);
    free(err_buf);

    return result;
}

/* ============================================================================
 * Public API: Command Execution
 * ============================================================================ */

/* Execute command, return stdout only */
char *sn_ssh_run(__sn__SshConnection *conn, char *command) {
    if (!conn) {
        fprintf(stderr, "SshConnection.run: NULL connection handle\n");
        exit(1);
    }
    __sn__SshExecResult *result = ssh_exec_internal(conn, command);
    char *out = strdup(result->stdout_str ? result->stdout_str : "");
    return out;
}

/* Execute command, return full result struct */
__sn__SshExecResult *sn_ssh_exec(__sn__SshConnection *conn, char *command) {
    if (!conn) {
        fprintf(stderr, "SshConnection.exec: NULL connection handle\n");
        exit(1);
    }
    return ssh_exec_internal(conn, command);
}

/* ============================================================================
 * Getters
 * ============================================================================ */

char *sn_ssh_get_remote_address(__sn__SshConnection *conn) {
    if (conn == NULL || conn->remote_addr == NULL) {
        return strdup("");
    }
    return strdup((char *)conn->remote_addr);
}

char *sn_ssh_exec_result_get_stdout(__sn__SshExecResult *result) {
    if (result == NULL || result->stdout_str == NULL) {
        return strdup("");
    }
    return strdup(result->stdout_str);
}

char *sn_ssh_exec_result_get_stderr(__sn__SshExecResult *result) {
    if (result == NULL || result->stderr_str == NULL) {
        return strdup("");
    }
    return strdup(result->stderr_str);
}

long long sn_ssh_exec_result_get_exit_code(__sn__SshExecResult *result) {
    if (result == NULL) return -1;
    return result->exit_code;
}

/* ============================================================================
 * Lifecycle: Close (Client)
 * ============================================================================ */

void sn_ssh_close(__sn__SshConnection *conn) {
    if (conn == NULL) return;

    ssh_session session = (ssh_session)conn->session_ptr;

    if (session != NULL) {
        ssh_disconnect(session);
        ssh_free(session);
    }
    conn->session_ptr = NULL;
}

/* ============================================================================
 * Server: SshServerConfig
 * ============================================================================ */

#define SSH_MAX_USERS 64

__sn__SshServerConfig *sn_ssh_server_config_defaults(void) {
    __sn__SshServerConfig *config = (__sn__SshServerConfig *)calloc(1, sizeof(__sn__SshServerConfig));
    if (!config) {
        fprintf(stderr, "SshServerConfig.defaults: allocation failed\n");
        exit(1);
    }
    SshServerConfigInternal *internal = (SshServerConfigInternal *)calloc(1, sizeof(SshServerConfigInternal));
    internal->users = (SshUserCredential *)calloc(SSH_MAX_USERS, sizeof(SshUserCredential));
    internal->user_count = 0;
    ssh_register_config(config, internal);
    return config;
}

__sn__SshServerConfig *sn_ssh_server_config_set_host_key(__sn__SshServerConfig *config, char *path) {
    if (!config || !path) return NULL;
    SshServerConfigInternal *internal = ssh_find_config_internal(config);
    if (internal) {
        if (internal->host_key_path) free(internal->host_key_path);
        internal->host_key_path = strdup(path);
    }
    config->host_key_path = strdup(path);
    return config;
}

__sn__SshServerConfig *sn_ssh_server_config_add_user(__sn__SshServerConfig *config,
                                                   char *username, char *password) {
    if (!config || !username || !password) return NULL;
    SshServerConfigInternal *internal = ssh_find_config_internal(config);
    if (!internal) return config;
    if (internal->user_count >= SSH_MAX_USERS) {
        fprintf(stderr, "SshServerConfig.addUser: max users (%d) exceeded\n", SSH_MAX_USERS);
        exit(1);
    }

    int idx = (int)internal->user_count;
    internal->users[idx].username = strdup(username);
    internal->users[idx].password = strdup(password);
    internal->user_count++;
    config->user_count = internal->user_count;
    return config;
}

__sn__SshServerConfig *sn_ssh_server_config_set_authorized_keys_dir(__sn__SshServerConfig *config,
                                                                   char *path) {
    if (!config || !path) return NULL;
    SshServerConfigInternal *internal = ssh_find_config_internal(config);
    if (internal) {
        if (internal->authorized_keys_dir) free(internal->authorized_keys_dir);
        internal->authorized_keys_dir = strdup(path);
    }
    config->authorized_keys_dir = strdup(path);
    return config;
}

/* ============================================================================
 * Server: SshListener
 * ============================================================================ */

static __sn__SshListener *ssh_listener_bind_internal(const char *address,
                                                   SshServerConfigInternal *config) {
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

    /* Create private arena for this listener */
    /* no arena needed */

    /* Allocate listener */
    RtSshListener *listener = (RtSshListener *)calloc(1, sizeof(RtSshListener));
    if (!listener) {
        fprintf(stderr, "SshListener.bind: allocation failed\n");
        ssh_bind_free(sshbind);
        /* no arena to destroy */
        exit(1);
    }

    listener->bind_ptr = sshbind;
    listener->bound_port = actual_port;
    listener->config_ptr = config;

    return listener;
}

__sn__SshListener *sn_ssh_listener_bind(char *address, char *hostKeyPath) {
    /* Create a simple config with just the host key */
    __sn__SshServerConfig *cfg = sn_ssh_server_config_defaults();
    sn_ssh_server_config_set_host_key(cfg, hostKeyPath);
    SshServerConfigInternal *internal = ssh_find_config_internal(cfg);
    return ssh_listener_bind_internal(address, internal);
}

__sn__SshListener *sn_ssh_listener_bind_with(char *address,
                                            __sn__SshServerConfig *config) {
    if (!config) {
        fprintf(stderr, "SshListener.bindWith: NULL config handle\n");
        exit(1);
    }
    SshServerConfigInternal *internal = ssh_find_config_internal(config);
    return ssh_listener_bind_internal(address, internal);
}

long long sn_ssh_listener_port(__sn__SshListener *listener) {
    if (!listener) return 0;
    return listener->bound_port;
}

void sn_ssh_listener_close(__sn__SshListener *listener) {
    if (!listener) return;

    ssh_bind sshbind = (ssh_bind)listener->bind_ptr;

    if (sshbind != NULL) {
        ssh_bind_free(sshbind);
    }
    listener->bind_ptr = NULL;
}

/* ============================================================================
 * Server: Accept Session (Authentication)
 * ============================================================================ */

__sn__SshSession *sn_ssh_listener_accept(__sn__SshListener *listener) {
    if (!listener) {
        fprintf(stderr, "SshListener.accept: NULL listener handle\n");
        exit(1);
    }
    if (!listener->bind_ptr) {
        fprintf(stderr, "SshListener.accept: listener is closed\n");
        exit(1);
    }

    ssh_bind sshbind = (ssh_bind)listener->bind_ptr;
    SshServerConfigInternal *config = (SshServerConfigInternal *)listener->config_ptr;

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

    /* Create private arena for the session */
    /* no arena needed */

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
                            /* Copy username into private arena */
                            auth_username = strdup(user);
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

    /* Allocate session struct in private arena */
    RtSshSession *sess = (RtSshSession *)calloc(1, sizeof(RtSshSession));
    if (!sess) {
        fprintf(stderr, "SshListener.accept: session allocation failed\n");
        ssh_disconnect(session);
        ssh_free(session);
        exit(1);
    }

    sess->session_ptr = session;
    sess->username = auth_username;

    sess->remote_addr = strdup(remote_addr_buf);

    return sess;
}

/* ============================================================================
 * Server: SshSession
 * ============================================================================ */

char *sn_ssh_session_get_username(__sn__SshSession *session) {
    if (!session || !session->username) {
        return strdup("");
    }
    return strdup((char *)session->username);
}

char *sn_ssh_session_get_remote_address(__sn__SshSession *session) {
    if (!session || !session->remote_addr) {
        return strdup("");
    }
    return strdup((char *)session->remote_addr);
}

void sn_ssh_session_close(__sn__SshSession *session) {
    if (!session) return;

    ssh_session ssh_sess = (ssh_session)session->session_ptr;

    if (ssh_sess != NULL) {
        ssh_disconnect(ssh_sess);
        ssh_free(ssh_sess);
    }
    session->session_ptr = NULL;
}

/* ============================================================================
 * Server: Accept Channel
 * ============================================================================ */

__sn__SshChannel *sn_ssh_session_accept_channel(__sn__SshSession *session) {
    if (!session) {
        fprintf(stderr, "SshSession.acceptChannel: NULL session handle\n");
        exit(1);
    }
    if (!session->session_ptr) {
        fprintf(stderr, "SshSession.acceptChannel: session is closed\n");
        exit(1);
    }

    ssh_session ssh_sess = (ssh_session)session->session_ptr;

    /* Create private arena for this channel */
    /* no arena needed */

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
                    command = strdup(cmd);
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
        /* no arena to destroy */
        exit(1);
    }

    /* Allocate channel struct in private arena */
    RtSshChannel *ch = (RtSshChannel *)calloc(1, sizeof(RtSshChannel));
    if (!ch) {
        fprintf(stderr, "SshSession.acceptChannel: allocation failed\n");
        /* no arena to destroy */
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

char *sn_ssh_channel_get_command(__sn__SshChannel *channel) {
    if (!channel) {
        return strdup("");
    }
    if (!channel->command_str) {
        return strdup("");
    }
    return strdup((char *)channel->command_str);
}

bool sn_ssh_channel_is_shell(__sn__SshChannel *channel) {
    if (!channel) return false;
    return channel->is_shell != 0;
}

SnArray *sn_ssh_channel_read(__sn__SshChannel *channel, long long maxBytes) {
    if (!channel || maxBytes <= 0) {
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
    }
    if (!channel->channel_ptr) {
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
    }

    ssh_channel ch = (ssh_channel)channel->channel_ptr;

    /* Allocate temp buffer */
    size_t buf_size = (size_t)maxBytes;
    unsigned char *temp = (unsigned char *)malloc(buf_size);
    if (!temp) {
        SnArray *empty = sn_array_new(sizeof(unsigned char), 0);
        empty->elem_tag = SN_TAG_BYTE;
        return empty;
    }

    int n = ssh_channel_read(ch, temp, (uint32_t)buf_size, 0);
    if (n <= 0) {
        free(temp);
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
    }

    SnArray *arr = sn_array_new(sizeof(unsigned char), (long long)n);
    arr->elem_tag = SN_TAG_BYTE;
    for (int i = 0; i < n; i++) {
        sn_array_push(arr, &temp[i]);
    }
    free(temp);
    return arr;
}

char *sn_ssh_channel_read_line(__sn__SshChannel *channel) {
    if (!channel) {
        return strdup("");
    }
    if (!channel->channel_ptr) {
        return strdup("");
    }

    ssh_channel ch = (ssh_channel)channel->channel_ptr;

    /* Read character by character until newline */
    size_t cap = 256, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        return strdup("");
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

    char *result = strdup(buf);
    free(buf);
    return result;
}

long long sn_ssh_channel_write(__sn__SshChannel *channel, SnArray *data) {
    if (!channel || !data) return 0;
    if (!channel->channel_ptr) return 0;

    if (data->len == 0) return 0;

    ssh_channel ch = (ssh_channel)channel->channel_ptr;
    int written = ssh_channel_write(ch, data->data, (uint32_t)data->len);
    if (written < 0) {
        fprintf(stderr, "SshChannel.write: write failed\n");
        exit(1);
    }
    return (long long)written;
}

void sn_ssh_channel_write_line(__sn__SshChannel *channel, char *text) {
    if (!channel) return;
    if (!channel->channel_ptr) return;

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

void sn_ssh_channel_send_exit_status(__sn__SshChannel *channel, long long code) {
    if (!channel) return;
    if (!channel->channel_ptr) return;
    ssh_channel ch = (ssh_channel)channel->channel_ptr;
    ssh_channel_request_send_exit_status(ch, (int)code);
}

void sn_ssh_channel_close(__sn__SshChannel *channel) {
    if (!channel) return;

    ssh_channel ch = (ssh_channel)channel->channel_ptr;

    if (ch != NULL) {
        ssh_channel_send_eof(ch);
        ssh_channel_close(ch);
        ssh_channel_free(ch);
    }
    channel->channel_ptr = NULL;
}
