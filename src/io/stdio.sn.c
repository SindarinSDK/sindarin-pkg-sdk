/* ==============================================================================
 * sdk/stdio.sn.c - Standard I/O Implementation for Sindarin SDK
 * ==============================================================================
 * This file provides the C implementation for Stdin, Stdout, and Stderr types.
 * It is compiled via @source and linked with Sindarin code.
 * ============================================================================== */

#include <stdio.h>
#include <string.h>
#include "runtime/arena/arena_v2.h"
#include "runtime/runtime_io.h"

/* ============================================================================
 * Type Definitions (Static-only, never instantiated)
 * ============================================================================ */

typedef struct RtStdin {
    int _unused;  /* Placeholder - this struct is never instantiated */
} RtStdin;

typedef struct RtStdout {
    int _unused;  /* Placeholder - this struct is never instantiated */
} RtStdout;

typedef struct RtStderr {
    int _unused;  /* Placeholder - this struct is never instantiated */
} RtStderr;

/* ============================================================================
 * Stdin Functions
 * ============================================================================ */

/* Read a line from standard input (strips trailing newline) */
RtHandleV2 *sn_stdin_read_line(RtArenaV2 *arena)
{
    /* Read a line from stdin, stripping trailing newline */
    char buffer[4096];
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        /* EOF or error - return empty string */
        return rt_arena_v2_strdup(arena,"");
    }

    /* Strip trailing newline if present */
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
        len--;
    }

    return rt_arena_v2_strdup(arena,buffer);
}

/* Read a single character from standard input (returns -1 on EOF) */
long sn_stdin_read_char(void)
{
    return rt_stdin_read_char();
}

/* Read a whitespace-delimited word from standard input */
RtHandleV2 *sn_stdin_read_word(RtArenaV2 *arena)
{
    char buffer[4096];
    if (scanf("%4095s", buffer) != 1) {
        /* EOF or error - return empty string */
        return rt_arena_v2_strdup(arena,"");
    }

    return rt_arena_v2_strdup(arena,buffer);
}

/* Check if characters are available on stdin */
int sn_stdin_has_chars(void)
{
    return rt_stdin_has_chars();
}

/* Check if lines are available on stdin */
int sn_stdin_has_lines(void)
{
    return rt_stdin_has_lines();
}

/* Check if stdin is at EOF */
int sn_stdin_is_eof(void)
{
    return rt_stdin_is_eof();
}

/* ============================================================================
 * Stdout Functions
 * ============================================================================ */

/* Write text to standard output */
void sn_stdout_write(const char *text)
{
    rt_stdout_write(text);
}

/* Write text with newline to standard output */
void sn_stdout_write_line(const char *text)
{
    rt_stdout_write_line(text);
}

/* Flush standard output */
void sn_stdout_flush(void)
{
    rt_stdout_flush();
}

/* ============================================================================
 * Stderr Functions
 * ============================================================================ */

/* Write text to standard error */
void sn_stderr_write(const char *text)
{
    rt_stderr_write(text);
}

/* Write text with newline to standard error */
void sn_stderr_write_line(const char *text)
{
    rt_stderr_write_line(text);
}

/* Flush standard error */
void sn_stderr_flush(void)
{
    rt_stderr_flush();
}
