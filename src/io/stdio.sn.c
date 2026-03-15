/* ==============================================================================
 * sdk/stdio.sn.c - Standard I/O Implementation for Sindarin SDK
 * ==============================================================================
 * Minimal runtime version - no arena, uses strdup for string returns.
 * ============================================================================== */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================================
 * Stdin Functions
 * ============================================================================ */

/* Read a line from standard input (strips trailing newline) */
char *sn_stdin_read_line(void)
{
    char buffer[4096];
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        return strdup("");
    }

    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }

    return strdup(buffer);
}

/* Read a single character from standard input (returns -1 on EOF) */
long long sn_stdin_read_char(void)
{
    int c = fgetc(stdin);
    if (c == EOF) return -1;
    return (long long)c;
}

/* Read a whitespace-delimited word from standard input */
char *sn_stdin_read_word(void)
{
    char buffer[4096];
    if (scanf("%4095s", buffer) != 1) {
        return strdup("");
    }

    return strdup(buffer);
}

/* Check if characters are available on stdin */
long long sn_stdin_has_chars(void)
{
    int c = fgetc(stdin);
    if (c == EOF) return 0;
    ungetc(c, stdin);
    return 1;
}

/* Check if lines are available on stdin */
long long sn_stdin_has_lines(void)
{
    int c = fgetc(stdin);
    if (c == EOF) return 0;
    ungetc(c, stdin);
    return 1;
}

/* Check if stdin is at EOF */
long long sn_stdin_is_eof(void)
{
    int c = fgetc(stdin);
    if (c == EOF) return 1;
    ungetc(c, stdin);
    return 0;
}

/* ============================================================================
 * Stdout Functions
 * ============================================================================ */

void sn_stdout_write(char *text)
{
    if (text) fputs(text, stdout);
}

void sn_stdout_write_line(char *text)
{
    if (text) fputs(text, stdout);
    fputc('\n', stdout);
}

void sn_stdout_flush(void)
{
    fflush(stdout);
}

/* ============================================================================
 * Stderr Functions
 * ============================================================================ */

void sn_stderr_write(char *text)
{
    if (text) fputs(text, stderr);
}

void sn_stderr_write_line(char *text)
{
    if (text) fputs(text, stderr);
    fputc('\n', stderr);
}

void sn_stderr_flush(void)
{
    fflush(stderr);
}
