/* ==============================================================================
 * sdk/binaryfile.sn.c - Self-contained BinaryFile Implementation for Sindarin SDK
 * ==============================================================================
 * Minimal runtime version - no arena, uses SnArray for byte array returns.
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

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

/* ============================================================================
 * BinaryFile Type Definition
 * ============================================================================
 * The compiler generates __sn__BinaryFile with fields:
 *   void    *fp
 *   char    *path
 *   int32_t  is_open
 * ============================================================================ */

typedef __sn__BinaryFile BinaryFile;

/* ============================================================================
 * Static Methods
 * ============================================================================ */

/* Open binary file for reading and writing */
__sn__BinaryFile *sn_binary_file_open(char *path)
{
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

    BinaryFile *file = (BinaryFile *)calloc(1, sizeof(BinaryFile));
    if (file == NULL) {
        fclose(fp);
        fprintf(stderr, "SnBinaryFile.open: memory allocation failed\n");
        exit(1);
    }

    file->fp = fp;
    file->path = strdup(path);
    file->is_open = 1;

    return file;
}

/* Check if binary file exists without opening */
long long sn_binary_file_exists(char *path)
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
SnArray *sn_binary_file_read_all_static(char *path)
{
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
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
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

    /* Create SnArray from buffer */
    SnArray *arr = sn_array_new(sizeof(unsigned char), (long long)bytes_read);
    arr->elem_tag = SN_TAG_BYTE;
    for (size_t i = 0; i < bytes_read; i++) {
        sn_array_push(arr, &buf[i]);
    }

    free(buf);
    return arr;
}

/* Write byte array to binary file (creates or overwrites) */
void sn_binary_file_write_all_static(char *path, SnArray *data)
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
        long long len = sn_array_length(data);
        if (len > 0) {
            size_t written = fwrite((unsigned char *)data->data, 1, (size_t)len, fp);
            if (written != (size_t)len) {
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
void sn_binary_file_delete(char *path)
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
void sn_binary_file_copy(char *src, char *dst)
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
void sn_binary_file_move(char *src, char *dst)
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
long long sn_binary_file_read_byte(__sn__BinaryFile *file)
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
    return (long long)(unsigned char)c;
}

/* Read N bytes into new array */
SnArray *sn_binary_file_read_bytes(__sn__BinaryFile *file, long long count)
{
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
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
    }

    /* Allocate temp buffer */
    unsigned char *buf = (unsigned char *)malloc((size_t)count);
    if (buf == NULL) {
        fprintf(stderr, "SnBinaryFile.readBytes: memory allocation failed\n");
        exit(1);
    }

    /* Read bytes */
    size_t bytes_read = fread(buf, 1, (size_t)count, (FILE *)file->fp);

    /* Create SnArray with actual bytes read */
    SnArray *arr = sn_array_new(sizeof(unsigned char), (long long)bytes_read);
    arr->elem_tag = SN_TAG_BYTE;
    for (size_t i = 0; i < bytes_read; i++) {
        sn_array_push(arr, &buf[i]);
    }

    free(buf);
    return arr;
}

/* Read all remaining bytes from open file */
SnArray *sn_binary_file_read_remaining(__sn__BinaryFile *file)
{
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
        SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
        arr->elem_tag = SN_TAG_BYTE;
        return arr;
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

    /* Create SnArray with actual bytes read */
    SnArray *arr = sn_array_new(sizeof(unsigned char), (long long)bytes_read);
    arr->elem_tag = SN_TAG_BYTE;
    for (size_t i = 0; i < bytes_read; i++) {
        sn_array_push(arr, &buf[i]);
    }

    free(buf);
    return arr;
}

/* Read into byte buffer, returns number of bytes read */
long long sn_binary_file_read_into(__sn__BinaryFile *file, SnArray *buffer)
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

    /* Get the buffer's length */
    long long buf_len = sn_array_length(buffer);
    if (buf_len == 0) {
        return 0;  /* Empty buffer, nothing to read */
    }

    FILE *fp = (FILE *)file->fp;

    /* Read up to buf_len bytes directly into the array's data */
    size_t bytes_read = fread((unsigned char *)buffer->data, 1, (size_t)buf_len, fp);
    if (ferror(fp)) {
        fprintf(stderr, "SnBinaryFile.readInto: read error on file '%s': %s\n",
                file->path ? file->path : "(unknown)", strerror(errno));
        exit(1);
    }

    return (long long)bytes_read;
}

/* ============================================================================
 * Instance Writing Methods
 * ============================================================================ */

/* Write single byte */
void sn_binary_file_write_byte(__sn__BinaryFile *file, long long b)
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
void sn_binary_file_write_bytes(__sn__BinaryFile *file, SnArray *data)
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
    long long len = sn_array_length(data);
    if (len > 0) {
        size_t written = fwrite((unsigned char *)data->data, 1, (size_t)len, fp);
        if (written != (size_t)len) {
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
bool sn_binary_file_is_eof(__sn__BinaryFile *file)
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
bool sn_binary_file_has_bytes(__sn__BinaryFile *file)
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
long long sn_binary_file_position(__sn__BinaryFile *file)
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
void sn_binary_file_seek(__sn__BinaryFile *file, long long pos)
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
        fprintf(stderr, "SnBinaryFile.seek: invalid position %lld\n", pos);
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
void sn_binary_file_rewind(__sn__BinaryFile *file)
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
void sn_binary_file_flush(__sn__BinaryFile *file)
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

/* Dispose the file — closes file handle only (sn_auto cleanup frees path and struct) */
void sn_binary_file_dispose(__sn__BinaryFile *file)
{
    if (file == NULL) return;

    if (file->is_open && file->fp != NULL) {
        fclose((FILE *)file->fp);
        file->fp = NULL;
        file->is_open = 0;
    }
}

/* ============================================================================
 * Properties
 * ============================================================================ */

/* Get full file path */
char *sn_binary_file_get_path(__sn__BinaryFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.path: file is NULL\n");
        exit(1);
    }

    if (file->path == NULL) {
        return strdup("");
    }

    return strdup(file->path);
}

/* Get filename only (without directory) */
char *sn_binary_file_get_name(__sn__BinaryFile *file)
{
    if (file == NULL) {
        fprintf(stderr, "SnBinaryFile.name: file is NULL\n");
        exit(1);
    }

    if (file->path == NULL) {
        return strdup("");
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
    return strdup(name);
}

/* Get file size in bytes */
long long sn_binary_file_get_size(__sn__BinaryFile *file)
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
