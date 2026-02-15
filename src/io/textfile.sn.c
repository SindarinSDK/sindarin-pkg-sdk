/* ==============================================================================
 * sdk/textfile.sn.c - Self-contained TextFile Implementation for Sindarin SDK
 * ==============================================================================
 * This file provides the C implementation for the SnTextFile type.
 * It is compiled via #pragma source and linked with Sindarin code.
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

#ifdef _WIN32
    #if defined(__MINGW32__) || defined(__MINGW64__)
    #include <sys/stat.h>
    #include <unistd.h>
    #else
    #include <sys/stat.h>
    #include <io.h>
    #define unlink _unlink
    #endif
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

/* Include runtime arena for proper memory management */
#include "runtime/array/runtime_array_v2.h"

/* ============================================================================
 * TextFile Type Definition
 * ============================================================================ */

typedef struct RtSnTextFile {
    void *fp;
    char *path;
    int32_t is_open;
    RtArenaV2 *arena;           /* Private arena — owns all internal allocations */
} RtSnTextFile;

/* ============================================================================
 * Static Methods
 * ============================================================================ */

/* Open file for reading and writing */
RtSnTextFile *sn_text_file_open(RtArenaV2 *arena, const char *path)
{
    if (arena == NULL) {
        fprintf(stderr, "SnTextFile.open: arena is NULL\n");
        exit(1);
    }
    if (path == NULL) {
        fprintf(stderr, "SnTextFile.open: path is NULL\n");
        exit(1);
    }
    (void)arena;

    FILE *fp = fopen(path, "r+b");  /* Binary mode for cross-platform consistency */
    if (fp == NULL) {
        /* Try to create if doesn't exist */
        fp = fopen(path, "w+b");
        if (fp == NULL) {
            fprintf(stderr, "SnTextFile.open: failed to open file '%s': %s\n", path, strerror(errno));
            exit(1);
        }
    }

    /* Allocate TextFile struct from private arena */
    RtArenaV2 *priv = rt_arena_v2_create(NULL, RT_ARENA_MODE_DEFAULT, "text_file");
    RtHandleV2 *_h = rt_arena_v2_alloc(priv, sizeof(RtSnTextFile));
    RtSnTextFile *file = (RtSnTextFile *)_h->ptr;
    if (file == NULL) {
        fclose(fp);
        fprintf(stderr, "SnTextFile.open: memory allocation failed\n");
        exit(1);
    }

    file->fp = fp;
    file->arena = priv;
    { RtHandleV2 *_path_h = rt_arena_v2_strdup(priv, path); file->path = (char *)_path_h->ptr; }
    file->is_open = 1;

    return file;
}

/* Check if file exists without opening */
int sn_text_file_exists(const char *path)
{
    if (path == NULL) {
        return 0;
    }
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return 0;
    }
    fclose(fp);
    return 1;
}

/* Read entire file contents as string (static method) */
RtHandleV2 *sn_text_file_read_all_static(RtArenaV2 *arena, const char *path)
{
    if (arena == NULL) {
        fprintf(stderr, "SnTextFile.readAll: arena is NULL\n");
        exit(1);
    }
    if (path == NULL) {
        fprintf(stderr, "SnTextFile.readAll: path is NULL\n");
        exit(1);
    }

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "SnTextFile.readAll: failed to open file '%s': %s\n", path, strerror(errno));
        exit(1);
    }

    /* Get file size */
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        fprintf(stderr, "SnTextFile.readAll: failed to seek in file '%s': %s\n", path, strerror(errno));
        exit(1);
    }

    long size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        fprintf(stderr, "SnTextFile.readAll: failed to get size of file '%s': %s\n", path, strerror(errno));
        exit(1);
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        fprintf(stderr, "SnTextFile.readAll: failed to seek in file '%s': %s\n", path, strerror(errno));
        exit(1);
    }

    /* Allocate temporary buffer */
    char *content = (char *)malloc((size_t)size + 1);
    if (content == NULL) {
        fclose(fp);
        fprintf(stderr, "SnTextFile.readAll: memory allocation failed\n");
        exit(1);
    }

    /* Read file contents */
    size_t bytes_read = fread(content, 1, (size_t)size, fp);
    if (ferror(fp)) {
        free(content);
        fclose(fp);
        fprintf(stderr, "SnTextFile.readAll: failed to read file '%s': %s\n", path, strerror(errno));
        exit(1);
    }

    content[bytes_read] = '\0';
    fclose(fp);

    RtHandleV2 *h = rt_arena_v2_strdup(arena,content);
    free(content);
    return h;
}

/* Write string to file (creates or overwrites) */
void sn_text_file_write_all_static(const char *path, const char *content)
{
    if (path == NULL) {
        fprintf(stderr, "SnTextFile.writeAll: path is NULL\n");
        exit(1);
    }
    if (content == NULL) {
        content = "";
    }

    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "SnTextFile.writeAll: failed to open file '%s' for writing: %s\n", path, strerror(errno));
        exit(1);
    }

    size_t len = strlen(content);
    if (len > 0) {
        size_t written = fwrite(content, 1, len, fp);
        if (written != len) {
            fclose(fp);
            fprintf(stderr, "SnTextFile.writeAll: failed to write to file '%s': %s\n", path, strerror(errno));
            exit(1);
        }
    }

    if (fclose(fp) != 0) {
        fprintf(stderr, "SnTextFile.writeAll: failed to close file '%s': %s\n", path, strerror(errno));
        exit(1);
    }
}

/* Delete file */
void sn_text_file_delete(const char *path)
{
    if (path == NULL) {
        fprintf(stderr, "SnTextFile.delete: path is NULL\n");
        exit(1);
    }

    if (remove(path) != 0) {
        fprintf(stderr, "SnTextFile.delete: failed to delete file '%s': %s\n", path, strerror(errno));
        exit(1);
    }
}

/* Copy file to new location */
void sn_text_file_copy(const char *src, const char *dst)
{
    if (src == NULL) {
        fprintf(stderr, "SnTextFile.copy: source path is NULL\n");
        exit(1);
    }
    if (dst == NULL) {
        fprintf(stderr, "SnTextFile.copy: destination path is NULL\n");
        exit(1);
    }

    FILE *src_fp = fopen(src, "rb");
    if (src_fp == NULL) {
        fprintf(stderr, "SnTextFile.copy: failed to open source file '%s': %s\n", src, strerror(errno));
        exit(1);
    }

    FILE *dst_fp = fopen(dst, "wb");
    if (dst_fp == NULL) {
        fclose(src_fp);
        fprintf(stderr, "SnTextFile.copy: failed to open destination file '%s': %s\n", dst, strerror(errno));
        exit(1);
    }

    char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src_fp)) > 0) {
        if (fwrite(buffer, 1, bytes, dst_fp) != bytes) {
            fclose(src_fp);
            fclose(dst_fp);
            fprintf(stderr, "SnTextFile.copy: failed to write to destination file '%s': %s\n", dst, strerror(errno));
            exit(1);
        }
    }

    if (ferror(src_fp)) {
        fclose(src_fp);
        fclose(dst_fp);
        fprintf(stderr, "SnTextFile.copy: failed to read from source file '%s': %s\n", src, strerror(errno));
        exit(1);
    }

    fclose(src_fp);
    if (fclose(dst_fp) != 0) {
        fprintf(stderr, "SnTextFile.copy: failed to close destination file '%s': %s\n", dst, strerror(errno));
        exit(1);
    }
}

/* Move/rename file */
void sn_text_file_move(const char *src, const char *dst)
{
    if (src == NULL) {
        fprintf(stderr, "SnTextFile.move: source path is NULL\n");
        exit(1);
    }
    if (dst == NULL) {
        fprintf(stderr, "SnTextFile.move: destination path is NULL\n");
        exit(1);
    }

    if (rename(src, dst) != 0) {
        /* rename() may fail across filesystems, try copy+delete instead */
        sn_text_file_copy(src, dst);
        if (remove(src) != 0) {
            fprintf(stderr, "SnTextFile.move: failed to remove source file '%s' after copy: %s\n", src, strerror(errno));
            exit(1);
        }
    }
}

/* ============================================================================
 * Instance Reading Methods
 * ============================================================================ */

/* Read single character, returns -1 on EOF */
long sn_text_file_read_char(RtSnTextFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.readChar: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.readChar: file is not open\n");
        exit(1);
    }

    int c = fgetc((FILE *)file->fp);
    if (c == EOF) {
        if (ferror((FILE *)file->fp)) {
            fprintf(stderr, "SnTextFile.readChar: read error on file '%s': %s\n",
                    file->path ? file->path : "(unknown)", strerror(errno));
            exit(1);
        }
        return -1;  /* EOF */
    }
    return (long)c;
}

/* Read single line (strips trailing newline) */
RtHandleV2 *sn_text_file_read_line(RtArenaV2 *arena, RtSnTextFile *file)
{
    if (arena == NULL) {
        fprintf(stderr, "SnTextFile.readLine: arena is NULL\n");
        exit(1);
    }
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.readLine: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.readLine: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;

    /* Check for immediate EOF */
    int c = fgetc(fp);
    if (c == EOF) {
        if (ferror(fp)) {
            fprintf(stderr, "SnTextFile.readLine: read error on file '%s': %s\n",
                    file->path ? file->path : "(unknown)", strerror(errno));
            exit(1);
        }
        /* Return empty string on EOF */
        return rt_arena_v2_strdup(arena,"");
    }
    ungetc(c, fp);

    /* Read line into buffer */
    size_t capacity = 256;
    size_t length = 0;
    char *buffer = (char *)malloc(capacity);
    if (buffer == NULL) {
        fprintf(stderr, "SnTextFile.readLine: memory allocation failed\n");
        exit(1);
    }

    while ((c = fgetc(fp)) != EOF && c != '\n') {
        if (length >= capacity - 1) {
            size_t new_capacity = capacity * 2;
            char *new_buffer = (char *)realloc(buffer, new_capacity);
            if (new_buffer == NULL) {
                free(buffer);
                fprintf(stderr, "SnTextFile.readLine: memory allocation failed\n");
                exit(1);
            }
            buffer = new_buffer;
            capacity = new_capacity;
        }
        buffer[length++] = (char)c;
    }

    /* Strip trailing \r if present (for Windows line endings) */
    if (length > 0 && buffer[length - 1] == '\r') {
        length--;
    }

    buffer[length] = '\0';
    RtHandleV2 *h = rt_arena_v2_strdup(arena,buffer);
    free(buffer);
    return h;
}

/* Read all remaining content from open file */
RtHandleV2 *sn_text_file_read_remaining(RtArenaV2 *arena, RtSnTextFile *file)
{
    if (arena == NULL) {
        fprintf(stderr, "SnTextFile.readAll: arena is NULL\n");
        exit(1);
    }
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.readAll: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.readAll: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;

    /* Get current position and file size */
    long current_pos = ftell(fp);
    if (current_pos < 0) {
        fprintf(stderr, "SnTextFile.readAll: failed to get position in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "SnTextFile.readAll: failed to seek in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    long end_pos = ftell(fp);
    if (end_pos < 0) {
        fprintf(stderr, "SnTextFile.readAll: failed to get size of file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    /* Seek back to current position */
    if (fseek(fp, current_pos, SEEK_SET) != 0) {
        fprintf(stderr, "SnTextFile.readAll: failed to seek in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    /* Calculate remaining bytes */
    size_t remaining = (size_t)(end_pos - current_pos);

    /* Allocate temporary buffer */
    char *content = (char *)malloc(remaining + 1);
    if (content == NULL) {
        fprintf(stderr, "SnTextFile.readAll: memory allocation failed\n");
        exit(1);
    }

    /* Read remaining content */
    size_t bytes_read = fread(content, 1, remaining, fp);
    if (ferror(fp)) {
        free(content);
        fprintf(stderr, "SnTextFile.readAll: failed to read file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    content[bytes_read] = '\0';
    RtHandleV2 *h = rt_arena_v2_strdup(arena,content);
    free(content);
    return h;
}

/* Read all remaining lines as array of strings */
RtHandleV2 *sn_text_file_read_lines(RtArenaV2 *arena, RtSnTextFile *file)
{
    if (arena == NULL) {
        fprintf(stderr, "SnTextFile.readLines: arena is NULL\n");
        exit(1);
    }
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.readLines: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.readLines: file is not open\n");
        exit(1);
    }

    /* Start with empty array */
    RtHandleV2 *lines = rt_array_create_string_v2(arena, 0, NULL);

    /* Read lines until EOF */
    FILE *fp = (FILE *)file->fp;
    int c = fgetc(fp);
    while (c != EOF) {
        ungetc(c, fp);
        RtHandleV2 *line = sn_text_file_read_line(arena, file);
        lines = rt_array_push_string_v2(arena, lines, line);
        c = fgetc(fp);
    }

    return lines;
}

/* Read whitespace-delimited word */
RtHandleV2 *sn_text_file_read_word(RtArenaV2 *arena, RtSnTextFile *file)
{
    if (arena == NULL) {
        fprintf(stderr, "SnTextFile.readWord: arena is NULL\n");
        exit(1);
    }
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.readWord: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.readWord: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;

    /* Skip leading whitespace */
    int c;
    while ((c = fgetc(fp)) != EOF && (c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
        /* Skip whitespace */
    }

    if (c == EOF) {
        /* Return empty string on EOF */
        return rt_arena_v2_strdup(arena,"");
    }

    /* Read word into buffer */
    size_t capacity = 64;
    size_t length = 0;
    char *buffer = (char *)malloc(capacity);
    if (buffer == NULL) {
        fprintf(stderr, "SnTextFile.readWord: memory allocation failed\n");
        exit(1);
    }

    buffer[length++] = (char)c;

    while ((c = fgetc(fp)) != EOF && c != ' ' && c != '\t' && c != '\n' && c != '\r') {
        if (length >= capacity - 1) {
            size_t new_capacity = capacity * 2;
            char *new_buffer = (char *)realloc(buffer, new_capacity);
            if (new_buffer == NULL) {
                free(buffer);
                fprintf(stderr, "SnTextFile.readWord: memory allocation failed\n");
                exit(1);
            }
            buffer = new_buffer;
            capacity = new_capacity;
        }
        buffer[length++] = (char)c;
    }

    /* Put back the whitespace character if not EOF */
    if (c != EOF) {
        ungetc(c, fp);
    }

    buffer[length] = '\0';
    RtHandleV2 *h = rt_arena_v2_strdup(arena,buffer);
    free(buffer);
    return h;
}

/* ============================================================================
 * Instance Writing Methods
 * ============================================================================ */

/* Write single character */
void sn_text_file_write_char(RtSnTextFile *file, long ch)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.writeChar: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.writeChar: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    if (fputc((int)ch, fp) == EOF) {
        fprintf(stderr, "SnTextFile.writeChar: write error on file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }
}

/* Write string */
void sn_text_file_write(RtSnTextFile *file, const char *text)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.write: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.write: file is not open\n");
        exit(1);
    }
    if (text == NULL) {
        return;  /* Nothing to write */
    }

    FILE *fp = (FILE *)file->fp;
    size_t len = strlen(text);
    if (len > 0) {
        size_t written = fwrite(text, 1, len, fp);
        if (written != len) {
            fprintf(stderr, "SnTextFile.write: write error on file '%s': %s\n",
                    file->path ? file->path : "(unknown)", strerror(errno));
            exit(1);
        }
    }
}

/* Write string followed by newline */
void sn_text_file_write_line(RtSnTextFile *file, const char *text)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.writeLine: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.writeLine: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;

    /* Write the text if not null */
    if (text != NULL) {
        size_t len = strlen(text);
        if (len > 0) {
            size_t written = fwrite(text, 1, len, fp);
            if (written != len) {
                fprintf(stderr, "SnTextFile.writeLine: write error on file '%s': %s\n",
                        file->path ? file->path : "(unknown)", strerror(errno));
                exit(1);
            }
        }
    }

    /* Write the newline */
    if (fputc('\n', fp) == EOF) {
        fprintf(stderr, "SnTextFile.writeLine: write error on file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }
}

/* Write string (alias for write) */
void sn_text_file_print(RtSnTextFile *file, const char *text)
{
    sn_text_file_write(file, text);
}

/* Write string followed by newline (alias for writeLine) */
void sn_text_file_println(RtSnTextFile *file, const char *text)
{
    sn_text_file_write_line(file, text);
}

/* ============================================================================
 * State Methods
 * ============================================================================ */

/* Check if at end of file */
int sn_text_file_is_eof(RtSnTextFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.isEof: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.isEof: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    int c = fgetc(fp);
    if (c == EOF) {
        return 1;  /* At EOF */
    }
    ungetc(c, fp);
    return 0;  /* Not at EOF */
}

/* Check if more characters are available */
int sn_text_file_has_chars(RtSnTextFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.hasChars: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.hasChars: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    int c = fgetc(fp);
    if (c == EOF) {
        return 0;
    }
    ungetc(c, fp);
    return 1;
}

/* Check if more words are available */
int sn_text_file_has_words(RtSnTextFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.hasWords: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.hasWords: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    long original_pos = ftell(fp);

    /* Skip whitespace */
    int c;
    while ((c = fgetc(fp)) != EOF && (c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
        /* Skip whitespace */
    }

    int has_word = (c != EOF);

    /* Restore original position */
    fseek(fp, original_pos, SEEK_SET);

    return has_word;
}

/* Check if more lines are available */
int sn_text_file_has_lines(RtSnTextFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.hasLines: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.hasLines: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    int c = fgetc(fp);
    if (c == EOF) {
        return 0;
    }
    ungetc(c, fp);
    return 1;
}

/* Get current byte position */
long sn_text_file_position(RtSnTextFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.position: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.position: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    long pos = ftell(fp);
    if (pos < 0) {
        fprintf(stderr, "SnTextFile.position: failed to get position in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }
    return pos;
}

/* Seek to byte position */
void sn_text_file_seek(RtSnTextFile *file, long pos)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.seek: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.seek: file is not open\n");
        exit(1);
    }
    if (pos < 0) {
        fprintf(stderr, "SnTextFile.seek: invalid position %ld\n", pos);
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    if (fseek(fp, pos, SEEK_SET) != 0) {
        fprintf(stderr, "SnTextFile.seek: failed to seek in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }
}

/* Return to beginning of file */
void sn_text_file_rewind(RtSnTextFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.rewind: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.rewind: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    rewind(fp);
}

/* Force buffered data to disk */
void sn_text_file_flush(RtSnTextFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.flush: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.flush: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    if (fflush(fp) != 0) {
        fprintf(stderr, "SnTextFile.flush: failed to flush file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }
}

/* Close the file */
void sn_text_file_close(RtSnTextFile *file)
{
    if (file == NULL) {
        return;
    }

    FILE *fp_val = (FILE *)file->fp;
    RtArenaV2 *priv = file->arena;

    if (file->is_open && fp_val != NULL) {
        fclose(fp_val);
    }

    /* Destroy private arena — frees struct, path string */
    if (priv != NULL) {
        rt_arena_v2_destroy(priv, false);
    }
}

/* ============================================================================
 * Properties
 * ============================================================================ */

/* Get full file path */
RtHandleV2 *sn_text_file_get_path(RtArenaV2 *arena, RtSnTextFile *file)
{
    if (arena == NULL) {
        fprintf(stderr, "SnTextFile.path: arena is NULL\n");
        exit(1);
    }
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.path: file is NULL\n");
        exit(1);
    }

    if (file->path == NULL) {
        return rt_arena_v2_strdup(arena,"");
    }

    return rt_arena_v2_strdup(arena,file->path);
}

/* Get filename only (without directory) */
RtHandleV2 *sn_text_file_get_name(RtArenaV2 *arena, RtSnTextFile *file)
{
    if (arena == NULL) {
        fprintf(stderr, "SnTextFile.name: arena is NULL\n");
        exit(1);
    }
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.name: file is NULL\n");
        exit(1);
    }

    if (file->path == NULL) {
        return rt_arena_v2_strdup(arena,"");
    }

    /* Find last path separator */
    const char *path = file->path;
    const char *last_sep = strrchr(path, '/');
#ifdef _WIN32
    const char *last_backslash = strrchr(path, '\\');
    if (last_backslash != NULL && (last_sep == NULL || last_backslash > last_sep)) {
        last_sep = last_backslash;
    }
#endif

    const char *name = (last_sep != NULL) ? last_sep + 1 : path;
    return rt_arena_v2_strdup(arena,name);
}

/* Get file size in bytes */
long sn_text_file_get_size(RtSnTextFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnTextFile.size: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnTextFile.size: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;

    /* Save current position */
    long current_pos = ftell(fp);
    if (current_pos < 0) {
        fprintf(stderr, "SnTextFile.size: failed to get position in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    /* Seek to end to get size */
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "SnTextFile.size: failed to seek in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    long size = ftell(fp);
    if (size < 0) {
        fprintf(stderr, "SnTextFile.size: failed to get size of file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    /* Restore original position */
    if (fseek(fp, current_pos, SEEK_SET) != 0) {
        fprintf(stderr, "SnTextFile.size: failed to restore position in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    return size;
}
