/* ==============================================================================
 * sdk/binaryfile.sn.c - Self-contained BinaryFile Implementation for Sindarin SDK
 * ==============================================================================
 * This file provides the C implementation for the SnBinaryFile type.
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
 * BinaryFile Type Definition
 * ============================================================================ */

typedef struct RtSnBinaryFile {
    void *fp;                   /* FILE* pointer */
    char *path;                 /* Full path to file */
    int32_t is_open;            /* Whether file is still open */
    RtArenaV2 *arena;           /* Arena used for allocation */
    RtHandleV2 *self_handle;    /* Handle to this struct */
    RtHandleV2 *path_handle;    /* Handle to path string */
} RtSnBinaryFile;

/* ============================================================================
 * Static Methods
 * ============================================================================ */

/* Open binary file for reading and writing */
RtSnBinaryFile *sn_binary_file_open(RtArenaV2 *arena, const char *path)
{
    if (arena == NULL) {
        fprintf(stderr, "SnBinaryFile.open: arena is NULL\n");
        exit(1);
    }
    if (path == NULL) {
        fprintf(stderr, "SnBinaryFile.open: path is NULL\n");
        exit(1);
    }

    /* Try to open in r+b (read/write binary, must exist) */
    FILE *fp = fopen(path, "r+b");
    if (fp == NULL) {
        /* If file doesn't exist, create it with w+b */
        fp = fopen(path, "w+b");
        if (fp == NULL) {
            fprintf(stderr, "SnBinaryFile.open: failed to open file '%s': %s\n",
                    path, strerror(errno));
            exit(1);
        }
    }

    /* Allocate file handle */
    RtHandleV2 *_h = rt_arena_v2_alloc(arena, sizeof(RtSnBinaryFile));
    rt_handle_v2_pin(_h);
    RtSnBinaryFile *file = (RtSnBinaryFile *)_h->ptr;
    if (file == NULL) {
        fclose(fp);
        fprintf(stderr, "SnBinaryFile.open: memory allocation failed\n");
        exit(1);
    }

    file->fp = fp;
    file->arena = arena;
    file->self_handle = _h;
    { RtHandleV2 *_path_h = rt_arena_v2_strdup(arena, path); rt_handle_v2_pin(_path_h); file->path = (char *)_path_h->ptr; file->path_handle = _path_h; }
    file->is_open = 1;

    return file;
}

/* Check if binary file exists without opening */
int sn_binary_file_exists(const char *path)
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

/* Read entire binary file contents as byte array (static method) */
RtHandleV2 *sn_binary_file_read_all_static(RtArenaV2 *arena, const char *path)
{
    if (arena == NULL) {
        fprintf(stderr, "SnBinaryFile.readAll: arena is NULL\n");
        exit(1);
    }
    if (path == NULL) {
        fprintf(stderr, "SnBinaryFile.readAll: path is NULL\n");
        exit(1);
    }

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "SnBinaryFile.readAll: failed to open file '%s': %s\n",
                path, strerror(errno));
        exit(1);
    }

    /* Get file size */
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        fprintf(stderr, "SnBinaryFile.readAll: failed to seek in file '%s': %s\n",
                path, strerror(errno));
        exit(1);
    }

    long size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        fprintf(stderr, "SnBinaryFile.readAll: failed to get size of file '%s': %s\n",
                path, strerror(errno));
        exit(1);
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        fprintf(stderr, "SnBinaryFile.readAll: failed to rewind file '%s': %s\n",
                path, strerror(errno));
        exit(1);
    }

    /* Handle empty file case */
    if (size == 0) {
        fclose(fp);
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    /* Allocate temp buffer */
    unsigned char *buf = (unsigned char *)malloc((size_t)size);
    if (buf == NULL) {
        fclose(fp);
        fprintf(stderr, "SnBinaryFile.readAll: memory allocation failed\n");
        exit(1);
    }

    /* Read file contents */
    size_t bytes_read = fread(buf, 1, (size_t)size, fp);
    if (bytes_read != (size_t)size) {
        free(buf);
        fclose(fp);
        fprintf(stderr, "SnBinaryFile.readAll: failed to read file '%s': %s\n",
                path, strerror(errno));
        exit(1);
    }

    fclose(fp);

    /* Create handle-based array */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)size, sizeof(unsigned char), buf);
    free(buf);
    return result;
}

/* Write byte array to binary file (creates or overwrites) */
void sn_binary_file_write_all_static(const char *path, unsigned char *data)
{
    if (path == NULL) {
        fprintf(stderr, "SnBinaryFile.writeAll: path is NULL\n");
        exit(1);
    }

    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "SnBinaryFile.writeAll: failed to create file '%s': %s\n",
                path, strerror(errno));
        exit(1);
    }

    if (data != NULL) {
        size_t len = rt_v2_data_array_length(data);
        if (len > 0) {
            size_t written = fwrite(data, 1, len, fp);
            if (written != len) {
                fclose(fp);
                fprintf(stderr, "SnBinaryFile.writeAll: failed to write file '%s': %s\n",
                        path, strerror(errno));
                exit(1);
            }
        }
    }

    fclose(fp);
}

/* Delete binary file */
void sn_binary_file_delete(const char *path)
{
    if (path == NULL) {
        fprintf(stderr, "SnBinaryFile.delete: path is NULL\n");
        exit(1);
    }

    if (remove(path) != 0) {
        fprintf(stderr, "SnBinaryFile.delete: failed to delete file '%s': %s\n",
                path, strerror(errno));
        exit(1);
    }
}

/* Copy binary file to new location */
void sn_binary_file_copy(const char *src, const char *dst)
{
    if (src == NULL) {
        fprintf(stderr, "SnBinaryFile.copy: source path is NULL\n");
        exit(1);
    }
    if (dst == NULL) {
        fprintf(stderr, "SnBinaryFile.copy: destination path is NULL\n");
        exit(1);
    }

    FILE *src_fp = fopen(src, "rb");
    if (src_fp == NULL) {
        fprintf(stderr, "SnBinaryFile.copy: failed to open source file '%s': %s\n",
                src, strerror(errno));
        exit(1);
    }

    FILE *dst_fp = fopen(dst, "wb");
    if (dst_fp == NULL) {
        fclose(src_fp);
        fprintf(stderr, "SnBinaryFile.copy: failed to create destination file '%s': %s\n",
                dst, strerror(errno));
        exit(1);
    }

    /* Copy in chunks */
    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src_fp)) > 0) {
        size_t bytes_written = fwrite(buffer, 1, bytes_read, dst_fp);
        if (bytes_written != bytes_read) {
            fclose(src_fp);
            fclose(dst_fp);
            fprintf(stderr, "SnBinaryFile.copy: failed to write to '%s': %s\n",
                    dst, strerror(errno));
            exit(1);
        }
    }

    if (ferror(src_fp)) {
        fclose(src_fp);
        fclose(dst_fp);
        fprintf(stderr, "SnBinaryFile.copy: failed to read from '%s': %s\n",
                src, strerror(errno));
        exit(1);
    }

    fclose(src_fp);
    fclose(dst_fp);
}

/* Move/rename binary file */
void sn_binary_file_move(const char *src, const char *dst)
{
    if (src == NULL) {
        fprintf(stderr, "SnBinaryFile.move: source path is NULL\n");
        exit(1);
    }
    if (dst == NULL) {
        fprintf(stderr, "SnBinaryFile.move: destination path is NULL\n");
        exit(1);
    }

    /* Try rename first (efficient, same filesystem) */
    if (rename(src, dst) == 0) {
        return;
    }

    /* If rename fails, try copy + delete (cross-filesystem) */
    sn_binary_file_copy(src, dst);
    if (remove(src) != 0) {
        fprintf(stderr, "SnBinaryFile.move: failed to remove source file '%s': %s\n",
                src, strerror(errno));
        exit(1);
    }
}

/* ============================================================================
 * Instance Reading Methods
 * ============================================================================ */

/* Read single byte, returns -1 on EOF */
long sn_binary_file_read_byte(RtSnBinaryFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.readByte: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.readByte: file is not open\n");
        exit(1);
    }

    int c = fgetc((FILE *)file->fp);
    if (c == EOF) {
        if (ferror((FILE *)file->fp)) {
            fprintf(stderr, "SnBinaryFile.readByte: read error on file '%s': %s\n",
                    file->path ? file->path : "(unknown)", strerror(errno));
            exit(1);
        }
        return -1;  /* EOF */
    }
    return (long)(unsigned char)c;
}

/* Read N bytes into new array */
RtHandleV2 *sn_binary_file_read_bytes(RtArenaV2 *arena, RtSnBinaryFile *file, long count)
{
    if (arena == NULL) {
        fprintf(stderr, "SnBinaryFile.readBytes: arena is NULL\n");
        exit(1);
    }
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.readBytes: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.readBytes: file is not open\n");
        exit(1);
    }
    if (count < 0) {
        fprintf(stderr, "SnBinaryFile.readBytes: count cannot be negative\n");
        exit(1);
    }

    /* Handle zero count case */
    if (count == 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    /* Allocate temp buffer */
    unsigned char *buf = (unsigned char *)malloc((size_t)count);
    if (buf == NULL) {
        fprintf(stderr, "SnBinaryFile.readBytes: memory allocation failed\n");
        exit(1);
    }

    /* Read bytes */
    size_t bytes_read = fread(buf, 1, (size_t)count, (FILE *)file->fp);

    /* Create handle-based array with actual bytes read */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, bytes_read, sizeof(unsigned char), buf);
    free(buf);
    return result;
}

/* Read all remaining bytes from open file */
RtHandleV2 *sn_binary_file_read_remaining(RtArenaV2 *arena, RtSnBinaryFile *file)
{
    if (arena == NULL) {
        fprintf(stderr, "SnBinaryFile.readAll: arena is NULL\n");
        exit(1);
    }
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.readAll: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.readAll: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;

    /* Get current position and file size */
    long current_pos = ftell(fp);
    if (current_pos < 0) {
        fprintf(stderr, "SnBinaryFile.readAll: failed to get position in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "SnBinaryFile.readAll: failed to seek in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    long end_pos = ftell(fp);
    if (end_pos < 0) {
        fprintf(stderr, "SnBinaryFile.readAll: failed to get size of file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    /* Seek back to current position */
    if (fseek(fp, current_pos, SEEK_SET) != 0) {
        fprintf(stderr, "SnBinaryFile.readAll: failed to seek in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    /* Calculate remaining bytes */
    size_t remaining = (size_t)(end_pos - current_pos);

    /* Handle empty remaining case */
    if (remaining == 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    /* Allocate temp buffer */
    unsigned char *buf = (unsigned char *)malloc(remaining);
    if (buf == NULL) {
        fprintf(stderr, "SnBinaryFile.readAll: memory allocation failed\n");
        exit(1);
    }

    /* Read remaining content */
    size_t bytes_read = fread(buf, 1, remaining, fp);
    if (ferror(fp)) {
        free(buf);
        fprintf(stderr, "SnBinaryFile.readAll: failed to read file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    /* Create handle-based array with actual bytes read */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, bytes_read, sizeof(unsigned char), buf);
    free(buf);
    return result;
}

/* Read into byte buffer, returns number of bytes read */
long sn_binary_file_read_into(RtSnBinaryFile *file, unsigned char *buffer)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.readInto: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.readInto: file is not open\n");
        exit(1);
    }
    if (buffer == NULL) {
        fprintf(stderr, "SnBinaryFile.readInto: buffer is NULL\n");
        exit(1);
    }

    /* Get the buffer's length from its metadata */
    size_t buf_len = rt_v2_data_array_length(buffer);
    if (buf_len == 0) {
        return 0;  /* Empty buffer, nothing to read */
    }

    FILE *fp = (FILE *)file->fp;

    /* Read up to buf_len bytes */
    size_t bytes_read = fread(buffer, 1, buf_len, fp);
    if (ferror(fp)) {
        fprintf(stderr, "SnBinaryFile.readInto: read error on file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    return (long)bytes_read;
}

/* ============================================================================
 * Instance Writing Methods
 * ============================================================================ */

/* Write single byte */
void sn_binary_file_write_byte(RtSnBinaryFile *file, long b)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.writeByte: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.writeByte: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    if (fputc((unsigned char)b, fp) == EOF) {
        fprintf(stderr, "SnBinaryFile.writeByte: write error on file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }
}

/* Write byte array */
void sn_binary_file_write_bytes(RtSnBinaryFile *file, unsigned char *data)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.writeBytes: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.writeBytes: file is not open\n");
        exit(1);
    }
    if (data == NULL) {
        return;  /* Nothing to write */
    }

    FILE *fp = (FILE *)file->fp;
    size_t len = rt_v2_data_array_length(data);
    if (len > 0) {
        size_t written = fwrite(data, 1, len, fp);
        if (written != len) {
            fprintf(stderr, "SnBinaryFile.writeBytes: write error on file '%s': %s\n",
                    file->path ? file->path : "(unknown)", strerror(errno));
            exit(1);
        }
    }
}

/* ============================================================================
 * State Methods
 * ============================================================================ */

/* Check if at end of file */
int sn_binary_file_is_eof(RtSnBinaryFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.isEof: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.isEof: file is not open\n");
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

/* Check if more bytes are available */
int sn_binary_file_has_bytes(RtSnBinaryFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.hasBytes: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.hasBytes: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    int c = fgetc(fp);
    if (c == EOF) {
        return 0;  /* No more bytes */
    }
    ungetc(c, fp);
    return 1;  /* More bytes available */
}

/* Get current byte position */
long sn_binary_file_position(RtSnBinaryFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.position: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.position: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    long pos = ftell(fp);
    if (pos < 0) {
        fprintf(stderr, "SnBinaryFile.position: failed to get position in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }
    return pos;
}

/* Seek to byte position */
void sn_binary_file_seek(RtSnBinaryFile *file, long pos)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.seek: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.seek: file is not open\n");
        exit(1);
    }
    if (pos < 0) {
        fprintf(stderr, "SnBinaryFile.seek: invalid position %ld\n", pos);
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    if (fseek(fp, pos, SEEK_SET) != 0) {
        fprintf(stderr, "SnBinaryFile.seek: failed to seek in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }
}

/* Return to beginning of file */
void sn_binary_file_rewind(RtSnBinaryFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.rewind: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.rewind: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    rewind(fp);
}

/* Force buffered data to disk */
void sn_binary_file_flush(RtSnBinaryFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.flush: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.flush: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;
    if (fflush(fp) != 0) {
        fprintf(stderr, "SnBinaryFile.flush: failed to flush file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }
}

/* Close the file */
void sn_binary_file_close(RtSnBinaryFile *file)
{
    if (file == NULL) {
        return;
    }
    if (file->is_open && file->fp != NULL) {
        fclose((FILE *)file->fp);
        file->is_open = 0;
        file->fp = NULL;
    }

    /* Unpin/free path handle */
    if (file->path_handle != NULL) {
        rt_handle_v2_unpin(file->path_handle);
        rt_arena_v2_free(file->path_handle);
        file->path_handle = NULL;
        file->path = NULL;
    }

    /* Unpin/free self handle last */
    if (file->self_handle != NULL) {
        RtHandleV2 *self = file->self_handle;
        file->self_handle = NULL;
        file->arena = NULL;
        rt_handle_v2_unpin(self);
        rt_arena_v2_free(self);
    }
}

/* ============================================================================
 * Properties
 * ============================================================================ */

/* Get full file path */
RtHandleV2 *sn_binary_file_get_path(RtArenaV2 *arena, RtSnBinaryFile *file)
{
    if (arena == NULL) {
        fprintf(stderr, "SnBinaryFile.path: arena is NULL\n");
        exit(1);
    }
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.path: file is NULL\n");
        exit(1);
    }

    if (file->path == NULL) {
        return rt_arena_v2_strdup(arena,"");
    }

    return rt_arena_v2_strdup(arena,file->path);
}

/* Get filename only (without directory) */
RtHandleV2 *sn_binary_file_get_name(RtArenaV2 *arena, RtSnBinaryFile *file)
{
    if (arena == NULL) {
        fprintf(stderr, "SnBinaryFile.name: arena is NULL\n");
        exit(1);
    }
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.name: file is NULL\n");
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
long sn_binary_file_get_size(RtSnBinaryFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.size: file is NULL\n");
        exit(1);
    }
    if (!file->is_open || file->fp == NULL) {
        fprintf(stderr, "SnBinaryFile.size: file is not open\n");
        exit(1);
    }

    FILE *fp = (FILE *)file->fp;

    /* Save current position */
    long current_pos = ftell(fp);
    if (current_pos < 0) {
        fprintf(stderr, "SnBinaryFile.size: failed to get position in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    /* Seek to end to get size */
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "SnBinaryFile.size: failed to seek in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    long size = ftell(fp);
    if (size < 0) {
        fprintf(stderr, "SnBinaryFile.size: failed to get size of file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    /* Restore original position */
    if (fseek(fp, current_pos, SEEK_SET) != 0) {
        fprintf(stderr, "SnBinaryFile.size: failed to restore position in file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    return size;
}
