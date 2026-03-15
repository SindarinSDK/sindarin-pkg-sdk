/* ==============================================================================
 * sdk/process.sn.c - Self-contained Process Implementation for Sindarin SDK
 * ==============================================================================
 * Minimal runtime version - no arena, uses malloc/strdup for allocations.
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Windows detection */
#if defined(_WIN32) || defined(__MINGW32__) || defined(__MINGW64__)
    #define SN_WINDOWS 1
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/wait.h>
#endif

/* ============================================================================
 * Process Type Definition
 * ============================================================================ */

typedef __sn__Process RtProcess;

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/* Initial buffer size for reading from file descriptors */
#define READ_BUFFER_INITIAL_SIZE 4096

/* Helper function to create RtProcess with given values */
static RtProcess *sn_process_create(int exit_code,
                                    const char *stdout_str, const char *stderr_str)
{
    RtProcess *proc = (RtProcess *)calloc(1, sizeof(RtProcess));
    if (proc == NULL) {
        fprintf(stderr, "sn_process_create: allocation failed\n");
        exit(1);
    }

    proc->exit_code = exit_code;
    proc->stdout_str = strdup(stdout_str ? stdout_str : "");
    proc->stderr_str = strdup(stderr_str ? stderr_str : "");

    return proc;
}

#ifdef SN_WINDOWS
/* ============================================================================
 * Windows Implementation using CreateProcess
 * ============================================================================ */

/* Read all data from a Windows HANDLE until EOF.
 * Returns a null-terminated malloc'd string.
 * Closes the handle after reading.
 */
static char *read_handle_to_string(HANDLE handle)
{
    if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
        if (handle != NULL && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
        return strdup("");
    }

    size_t capacity = READ_BUFFER_INITIAL_SIZE;
    size_t length = 0;
    char *buffer = (char *)malloc(capacity);
    if (buffer == NULL) {
        CloseHandle(handle);
        return strdup("");
    }

    while (1) {
        if (length + 1 >= capacity) {
            size_t new_capacity = capacity * 2;
            char *new_buffer = (char *)realloc(buffer, new_capacity);
            if (new_buffer == NULL) {
                buffer[length] = '\0';
                CloseHandle(handle);
                return buffer;
            }
            buffer = new_buffer;
            capacity = new_capacity;
        }

        DWORD bytes_read = 0;
        BOOL success = ReadFile(handle, buffer + length,
                                (DWORD)(capacity - length - 1), &bytes_read, NULL);

        if (!success || bytes_read == 0) {
            break;
        }

        length += bytes_read;
    }

    buffer[length] = '\0';
    CloseHandle(handle);
    return buffer;
}

/* Build a command line string from command and args for CreateProcess.
 * Returns malloc'd string (caller must free).
 */
static char *build_command_line(const char *cmd, char **args, size_t args_len)
{
    size_t total_len = strlen(cmd) + 3;

    if (args != NULL) {
        for (size_t i = 0; i < args_len; i++) {
            total_len += strlen(args[i]) + 3;
        }
    }

    char *cmdline = (char *)malloc(total_len);
    if (cmdline == NULL) {
        return NULL;
    }

    char *ptr = cmdline;

    if (strchr(cmd, ' ') != NULL) {
        ptr += sprintf(ptr, "\"%s\"", cmd);
    } else {
        ptr += sprintf(ptr, "%s", cmd);
    }

    if (args != NULL) {
        for (size_t i = 0; i < args_len; i++) {
            if (strchr(args[i], ' ') != NULL || args[i][0] == '\0') {
                ptr += sprintf(ptr, " \"%s\"", args[i]);
            } else {
                ptr += sprintf(ptr, " %s", args[i]);
            }
        }
    }

    return cmdline;
}

/* Windows implementation of process execution with args */
static RtProcess *sn_process_run_internal(const char *cmd, char **args, size_t args_len)
{
    if (cmd == NULL) {
        fprintf(stderr, "sn_process_run_internal: NULL command\n");
        return NULL;
    }

    char *cmdline = build_command_line(cmd, args, args_len);
    if (cmdline == NULL) {
        fprintf(stderr, "sn_process_run_internal: failed to build command line\n");
        return sn_process_create(127, "", "");
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE stdout_read = NULL, stdout_write = NULL;
    HANDLE stderr_read = NULL, stderr_write = NULL;

    if (!CreatePipe(&stdout_read, &stdout_write, &sa, 0)) {
        free(cmdline);
        fprintf(stderr, "sn_process_run_internal: stdout pipe failed\n");
        return sn_process_create(127, "", "");
    }
    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);

    if (!CreatePipe(&stderr_read, &stderr_write, &sa, 0)) {
        CloseHandle(stdout_read);
        CloseHandle(stdout_write);
        free(cmdline);
        fprintf(stderr, "sn_process_run_internal: stderr pipe failed\n");
        return sn_process_create(127, "", "");
    }
    SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = stdout_write;
    si.hStdError = stderr_write;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.dwFlags |= STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    BOOL success = CreateProcessA(
        NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi
    );

    CloseHandle(stdout_write);
    CloseHandle(stderr_write);

    if (!success) {
        DWORD error = GetLastError();
        CloseHandle(stdout_read);
        CloseHandle(stderr_read);
        free(cmdline);

        char error_msg[256];
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            snprintf(error_msg, sizeof(error_msg), "%s: command not found\n", cmd);
            return sn_process_create(127, "", error_msg);
        } else {
            snprintf(error_msg, sizeof(error_msg),
                     "CreateProcess failed with error %lu\n", error);
            return sn_process_create(127, "", error_msg);
        }
    }

    free(cmdline);

    char *stdout_data = read_handle_to_string(stdout_read);
    char *stderr_data = read_handle_to_string(stderr_read);

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    RtProcess *proc = sn_process_create((int)exit_code, stdout_data, stderr_data);
    free(stdout_data);
    free(stderr_data);
    return proc;
}

#else
/* ============================================================================
 * POSIX Implementation using fork/exec
 * ============================================================================ */

/* Read all data from a file descriptor until EOF.
 * Returns a null-terminated malloc'd string.
 * Closes the file descriptor after reading.
 */
static char *read_fd_to_string(int fd)
{
    if (fd < 0) {
        return strdup("");
    }

    size_t capacity = READ_BUFFER_INITIAL_SIZE;
    size_t length = 0;
    char *buffer = (char *)malloc(capacity);
    if (buffer == NULL) {
        close(fd);
        return strdup("");
    }

    while (1) {
        if (length + 1 >= capacity) {
            size_t new_capacity = capacity * 2;
            char *new_buffer = (char *)realloc(buffer, new_capacity);
            if (new_buffer == NULL) {
                buffer[length] = '\0';
                close(fd);
                return buffer;
            }
            buffer = new_buffer;
            capacity = new_capacity;
        }

        ssize_t bytes_read = read(fd, buffer + length, capacity - length - 1);

        if (bytes_read < 0) {
            buffer[length] = '\0';
            close(fd);
            return buffer;
        }

        if (bytes_read == 0) {
            break;
        }

        length += (size_t)bytes_read;
    }

    buffer[length] = '\0';
    close(fd);

    return buffer;
}

/* Build argv array for execvp */
static char **build_argv(const char *cmd, char **args, size_t args_len)
{
    size_t argc = 1;
    if (args != NULL) {
        argc += args_len;
    }

    char **argv = (char **)malloc((argc + 1) * sizeof(char *));
    if (argv == NULL) {
        return NULL;
    }

    argv[0] = (char *)cmd;

    if (args != NULL) {
        for (size_t i = 0; i < args_len; i++) {
            argv[i + 1] = args[i];
        }
    }

    argv[argc] = NULL;

    return argv;
}

/* POSIX implementation of process execution with args */
static RtProcess *sn_process_run_internal(const char *cmd, char **args, size_t args_len)
{
    if (cmd == NULL) {
        fprintf(stderr, "sn_process_run_internal: NULL command\n");
        return NULL;
    }

    char **argv = build_argv(cmd, args, args_len);
    if (argv == NULL) {
        fprintf(stderr, "sn_process_run_internal: failed to build argv\n");
        return sn_process_create(127, "", "");
    }

    int stdout_pipe[2];
    if (pipe(stdout_pipe) < 0) {
        free(argv);
        fprintf(stderr, "sn_process_run_internal: stdout pipe failed\n");
        return sn_process_create(127, "", "");
    }

    int stderr_pipe[2];
    if (pipe(stderr_pipe) < 0) {
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        free(argv);
        fprintf(stderr, "sn_process_run_internal: stderr pipe failed\n");
        return sn_process_create(127, "", "");
    }

    pid_t pid = fork();

    if (pid < 0) {
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        free(argv);
        fprintf(stderr, "sn_process_run_internal: fork failed\n");
        return sn_process_create(127, "", "");
    }

    if (pid == 0) {
        /* Child process */
        if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        if (dup2(stderr_pipe[1], STDERR_FILENO) < 0) {
            _exit(127);
        }

        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);

        execvp(cmd, argv);

        dprintf(STDERR_FILENO, "%s: command not found\n", cmd);
        _exit(127);
    }

    /* Parent process */
    free(argv);

    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    char *stdout_data = read_fd_to_string(stdout_pipe[0]);
    char *stderr_data = read_fd_to_string(stderr_pipe[0]);

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "sn_process_run_internal: waitpid failed\n");
        RtProcess *proc = sn_process_create(127, stdout_data, stderr_data);
        free(stdout_data);
        free(stderr_data);
        return proc;
    }

    int exit_code;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        exit_code = 128 + WTERMSIG(status);
    } else {
        exit_code = 127;
    }

    RtProcess *proc = sn_process_create(exit_code, stdout_data, stderr_data);
    free(stdout_data);
    free(stderr_data);
    return proc;
}

#endif /* SN_WINDOWS / POSIX */

/* ============================================================================
 * Public API Functions
 * ============================================================================ */

/* Run a command string via the system shell.
 * On POSIX: /bin/sh -c "cmd"
 * On Windows: CreateProcessA handles command strings natively */
RtProcess *sn_process_run(char *cmd)
{
#ifdef _WIN32
    return sn_process_run_internal(cmd, NULL, 0);
#else
    char *shell_args[] = { "-c", cmd };
    return sn_process_run_internal("/bin/sh", shell_args, 2);
#endif
}

/* Run a command with arguments (args is a Sindarin SnArray) */
RtProcess *sn_process_run_args(char *cmd, SnArray *args)
{
    long long args_len = args ? args->len : 0;
    char **args_data = args ? (char **)args->data : NULL;
    return sn_process_run_internal(cmd, args_data, (size_t)args_len);
}

/* ============================================================================
 * Process Getter Functions
 * ============================================================================ */

/* Get exit code */
long long sn_process_get_exit_code(RtProcess *proc)
{
    if (proc == NULL) return 127;
    return (long long)proc->exit_code;
}

/* Get captured stdout */
char *sn_process_get_stdout(RtProcess *proc)
{
    if (proc == NULL) return strdup("");
    return strdup(proc->stdout_str ? proc->stdout_str : "");
}

/* Get captured stderr */
char *sn_process_get_stderr(RtProcess *proc)
{
    if (proc == NULL) return strdup("");
    return strdup(proc->stderr_str ? proc->stderr_str : "");
}
