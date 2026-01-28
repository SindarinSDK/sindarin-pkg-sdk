/* ==============================================================================
 * sdk/directory.sn.c - Self-contained Directory Implementation for Sindarin SDK
 * ==============================================================================
 * This file provides the C implementation for the SnDirectory type.
 * It is compiled via #pragma source and linked with Sindarin code.
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>

#ifdef _WIN32
    #if defined(__MINGW32__) || defined(__MINGW64__)
    #include <sys/stat.h>
    #include <unistd.h>
    #include <dirent.h>
    #define MKDIR(path, mode) mkdir(path)
    #else
    #include <sys/stat.h>
    #include <direct.h>
    #include <io.h>
    #define MKDIR(path, mode) _mkdir(path)
    #define rmdir _rmdir
    #define unlink _unlink
    /* Windows dirent.h emulation would be needed for MSVC */
    /* For simplicity, we'll use MinGW or include a compat layer */
    #include <dirent.h>
    #endif
    #define PATH_SEPARATOR '\\'
#else
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#define MKDIR(path, mode) mkdir(path, mode)
#define PATH_SEPARATOR '/'
#endif

/* Include runtime arena for proper memory management */
#include "runtime/runtime_arena.h"
#include "runtime/runtime_array.h"
#include "runtime/arena/managed_arena.h"
#include "runtime/runtime_array_h.h"

/* ============================================================================
 * Directory Type Definition (unused, just for namespace)
 * ============================================================================ */

typedef struct RtSnDirectory {
    int32_t _unused;
} RtSnDirectory;

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/* Check if character is a path separator */
static int is_path_separator(char c)
{
#ifdef _WIN32
    return c == '/' || c == '\\';
#else
    return c == '/';
#endif
}

/* Check if a path points to a directory */
static int path_is_directory(const char *path)
{
    if (path == NULL) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

/* Join two paths */
static char *join_path(RtArena *arena, const char *path1, const char *path2)
{
    if (path1 == NULL) path1 = "";
    if (path2 == NULL) path2 = "";

    size_t len1 = strlen(path1);
    size_t len2 = strlen(path2);

    /* If path1 is empty, return path2 */
    if (len1 == 0) {
        return rt_arena_strdup(arena, path2);
    }

    /* Check if path1 already ends with separator */
    int has_trailing_sep = is_path_separator(path1[len1 - 1]);

    /* Allocate: path1 + optional separator + path2 + null */
    size_t result_len = len1 + (has_trailing_sep ? 0 : 1) + len2 + 1;
    char *result = rt_arena_alloc(arena, result_len);

    memcpy(result, path1, len1);
    size_t pos = len1;
    if (!has_trailing_sep) {
        result[pos++] = '/';
    }
    memcpy(result + pos, path2, len2);
    result[pos + len2] = '\0';

    return result;
}

/* Join two paths with forward slash (for consistent cross-platform relative paths) */
static char *join_with_forward_slash(RtArena *arena, const char *prefix, const char *name)
{
    size_t prefix_len = strlen(prefix);
    size_t name_len = strlen(name);
    char *result = rt_arena_alloc(arena, prefix_len + 1 + name_len + 1);
    memcpy(result, prefix, prefix_len);
    result[prefix_len] = '/';
    memcpy(result + prefix_len + 1, name, name_len);
    result[prefix_len + 1 + name_len] = '\0';
    return result;
}

/* Create string array helper */
static char **create_string_array(RtArena *arena, size_t initial_capacity)
{
    size_t capacity = initial_capacity > 4 ? initial_capacity : 4;
    RtArrayMetadata *meta = rt_arena_alloc(arena, sizeof(RtArrayMetadata) + capacity * sizeof(char *));
    if (meta == NULL) {
        fprintf(stderr, "create_string_array: allocation failed\n");
        exit(1);
    }
    meta->arena = arena;
    meta->size = 0;
    meta->capacity = capacity;
    return (char **)(meta + 1);
}

/* Push string to array helper */
static char **push_string_to_array(RtArena *arena, char **arr, const char *str)
{
    RtArrayMetadata *meta = ((RtArrayMetadata *)arr) - 1;
    RtArena *alloc_arena = meta->arena ? meta->arena : arena;

    if ((size_t)meta->size >= meta->capacity) {
        /* Need to grow the array */
        size_t new_capacity = meta->capacity * 2;
        RtArrayMetadata *new_meta = rt_arena_alloc(alloc_arena, sizeof(RtArrayMetadata) + new_capacity * sizeof(char *));
        if (new_meta == NULL) {
            fprintf(stderr, "push_string_to_array: allocation failed\n");
            exit(1);
        }
        new_meta->arena = alloc_arena;
        new_meta->size = meta->size;
        new_meta->capacity = new_capacity;
        char **new_arr = (char **)(new_meta + 1);
        memcpy(new_arr, arr, meta->size * sizeof(char *));
        arr = new_arr;
        meta = new_meta;
    }

    arr[meta->size] = rt_arena_strdup(alloc_arena, str);
    meta->size++;
    return arr;
}

/* ============================================================================
 * Directory Operations
 * ============================================================================ */

/* List files in a directory (non-recursive) */
RtHandle sn_directory_list(RtManagedArena *arena, const char *path)
{
    if (path == NULL) {
        return rt_array_create_string_h(arena, 0, NULL);  /* Return empty array */
    }

    DIR *dir = opendir(path);
    if (dir == NULL) {
        /* Directory doesn't exist or can't be opened - return empty array */
        return rt_array_create_string_h(arena, 0, NULL);
    }

    /* Collect strings into temporary buffer */
    size_t capacity = 16;
    size_t count = 0;
    char **buf = malloc(capacity * sizeof(char *));
    if (buf == NULL) {
        closedir(dir);
        return RT_HANDLE_NULL;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Grow buffer if needed */
        if (count >= capacity) {
            capacity *= 2;
            char **new_buf = realloc(buf, capacity * sizeof(char *));
            if (new_buf == NULL) {
                for (size_t i = 0; i < count; i++) free(buf[i]);
                free(buf);
                closedir(dir);
                return RT_HANDLE_NULL;
            }
            buf = new_buf;
        }

        buf[count] = strdup(entry->d_name);
        if (buf[count] == NULL) {
            for (size_t i = 0; i < count; i++) free(buf[i]);
            free(buf);
            closedir(dir);
            return RT_HANDLE_NULL;
        }
        count++;
    }

    closedir(dir);

    /* Create handle-based array */
    RtHandle result = rt_array_create_string_h(arena, count, (const char **)buf);

    /* Free temporary buffer */
    for (size_t i = 0; i < count; i++) free(buf[i]);
    free(buf);

    return result;
}

/* Helper struct for collecting strings during recursive listing */
typedef struct {
    char **buf;
    size_t count;
    size_t capacity;
} StringCollector;

/* Initialize a string collector */
static int string_collector_init(StringCollector *sc, size_t initial_capacity)
{
    sc->buf = malloc(initial_capacity * sizeof(char *));
    if (sc->buf == NULL) return -1;
    sc->count = 0;
    sc->capacity = initial_capacity;
    return 0;
}

/* Add a string to the collector (takes ownership of the string) */
static int string_collector_add(StringCollector *sc, char *str)
{
    if (sc->count >= sc->capacity) {
        size_t new_capacity = sc->capacity * 2;
        char **new_buf = realloc(sc->buf, new_capacity * sizeof(char *));
        if (new_buf == NULL) return -1;
        sc->buf = new_buf;
        sc->capacity = new_capacity;
    }
    sc->buf[sc->count++] = str;
    return 0;
}

/* Free all strings and the buffer in the collector */
static void string_collector_free(StringCollector *sc)
{
    if (sc->buf) {
        for (size_t i = 0; i < sc->count; i++) {
            free(sc->buf[i]);
        }
        free(sc->buf);
        sc->buf = NULL;
    }
    sc->count = 0;
    sc->capacity = 0;
}

/* Build a relative path by joining prefix and name with forward slash */
static char *build_rel_path(const char *prefix, const char *name)
{
    if (prefix[0] == '\0') {
        return strdup(name);
    }
    size_t prefix_len = strlen(prefix);
    size_t name_len = strlen(name);
    char *result = malloc(prefix_len + 1 + name_len + 1);
    if (result == NULL) return NULL;
    memcpy(result, prefix, prefix_len);
    result[prefix_len] = '/';
    memcpy(result + prefix_len + 1, name, name_len);
    result[prefix_len + 1 + name_len] = '\0';
    return result;
}

/* Build a full path by joining base and name */
static char *build_full_path(const char *base, const char *name)
{
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    int has_sep = (base_len > 0 && is_path_separator(base[base_len - 1]));
    char *result = malloc(base_len + (has_sep ? 0 : 1) + name_len + 1);
    if (result == NULL) return NULL;
    memcpy(result, base, base_len);
    size_t pos = base_len;
    if (!has_sep) {
        result[pos++] = '/';
    }
    memcpy(result + pos, name, name_len);
    result[pos + name_len] = '\0';
    return result;
}

/* Helper for recursive directory listing - collects into StringCollector */
static int list_recursive_helper_collect(StringCollector *sc, const char *base_path, const char *rel_prefix)
{
    DIR *dir = opendir(base_path);
    if (dir == NULL) {
        return 0;  /* Skip directories we can't open - not an error */
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Build full path for stat check */
        char *full_path = build_full_path(base_path, entry->d_name);
        if (full_path == NULL) {
            closedir(dir);
            return -1;
        }

        /* Build relative path for result (always use '/' for cross-platform consistency) */
        char *rel_path = build_rel_path(rel_prefix, entry->d_name);
        if (rel_path == NULL) {
            free(full_path);
            closedir(dir);
            return -1;
        }

        /* Add this entry to collector */
        if (string_collector_add(sc, rel_path) != 0) {
            free(rel_path);
            free(full_path);
            closedir(dir);
            return -1;
        }
        /* rel_path is now owned by collector */

        /* If it's a directory, recurse */
        struct stat st;
        if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            /* Get the rel_path we just added (it's at count-1) */
            const char *added_rel_path = sc->buf[sc->count - 1];
            if (list_recursive_helper_collect(sc, full_path, added_rel_path) != 0) {
                free(full_path);
                closedir(dir);
                return -1;
            }
        }

        free(full_path);
    }

    closedir(dir);
    return 0;
}

/* List files in a directory recursively */
RtHandle sn_directory_list_recursive(RtManagedArena *arena, const char *path)
{
    if (path == NULL) {
        fprintf(stderr, "SnDirectory.listRecursive: path cannot be null\n");
        exit(1);
    }

    if (!path_is_directory(path)) {
        fprintf(stderr, "SnDirectory.listRecursive: '%s' is not a directory\n", path);
        exit(1);
    }

    /* Initialize collector */
    StringCollector sc;
    if (string_collector_init(&sc, 64) != 0) {
        return RT_HANDLE_NULL;
    }

    /* Collect all paths recursively */
    if (list_recursive_helper_collect(&sc, path, "") != 0) {
        string_collector_free(&sc);
        return RT_HANDLE_NULL;
    }

    /* Create handle-based array */
    RtHandle result = rt_array_create_string_h(arena, sc.count, (const char **)sc.buf);

    /* Free temporary buffer */
    string_collector_free(&sc);

    return result;
}

/* Helper: Create directory and all parents */
static int create_directory_recursive(const char *path)
{
    if (path == NULL || *path == '\0') return 0;

    /* Check if it already exists */
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;  /* Already exists and is a directory */
        }
        return -1;  /* Exists but is not a directory */
    }

    /* Make a copy we can modify */
    size_t len = strlen(path);
    char *path_copy = malloc(len + 1);
    if (path_copy == NULL) return -1;
    strcpy(path_copy, path);

    /* Create parent directories first */
    char *p = path_copy;

#ifdef _WIN32
    /* Skip Windows drive letter (e.g., C:\) */
    if (len >= 3 && path_copy[1] == ':' && is_path_separator(path_copy[2])) {
        p = path_copy + 3;
    }
#endif

    /* Skip leading path separators for absolute paths */
    while (is_path_separator(*p)) p++;

    while (*p) {
        /* Find next path separator */
        while (*p && !is_path_separator(*p)) p++;

        if (is_path_separator(*p)) {
            char saved = *p;
            *p = '\0';
            if (path_copy[0] != '\0') {
                if (stat(path_copy, &st) != 0) {
                    if (MKDIR(path_copy, 0755) != 0 && errno != EEXIST) {
                        free(path_copy);
                        return -1;
                    }
                }
            }
            *p = saved;
            p++;
        }
    }

    /* Create final directory */
    int result = MKDIR(path_copy, 0755);
    free(path_copy);

    if (result != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

/* Create a directory (including parents if needed) */
void sn_directory_create(const char *path)
{
    if (path == NULL) {
        fprintf(stderr, "SnDirectory.create: path cannot be null\n");
        exit(1);
    }

    if (create_directory_recursive(path) != 0) {
        fprintf(stderr, "SnDirectory.create: failed to create directory '%s': %s\n",
                path, strerror(errno));
        exit(1);
    }
}

/* Delete an empty directory */
void sn_directory_delete(const char *path)
{
    if (path == NULL) {
        fprintf(stderr, "SnDirectory.delete: path cannot be null\n");
        exit(1);
    }

    if (rmdir(path) != 0) {
        if (errno == ENOTEMPTY) {
            fprintf(stderr, "SnDirectory.delete: directory '%s' is not empty\n", path);
        } else {
            fprintf(stderr, "SnDirectory.delete: failed to delete directory '%s': %s\n",
                    path, strerror(errno));
        }
        exit(1);
    }
}

/* Helper: Recursively delete directory contents */
static int delete_recursive_helper(const char *path)
{
    DIR *dir = opendir(path);
    if (dir == NULL) {
        return -1;
    }

    struct dirent *entry;
    int result = 0;

    while ((entry = readdir(dir)) != NULL && result == 0) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Build full path */
        size_t path_len = strlen(path);
        size_t name_len = strlen(entry->d_name);
        int has_sep = (path_len > 0 && is_path_separator(path[path_len - 1]));
        char *full_path = malloc(path_len + (has_sep ? 0 : 1) + name_len + 1);
        if (full_path == NULL) {
            result = -1;
            break;
        }

        strcpy(full_path, path);
        if (!has_sep) {
            full_path[path_len] = PATH_SEPARATOR;
            strcpy(full_path + path_len + 1, entry->d_name);
        } else {
            strcpy(full_path + path_len, entry->d_name);
        }

        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                /* Recursively delete subdirectory */
                result = delete_recursive_helper(full_path);
                if (result == 0) {
                    result = rmdir(full_path);
                }
            } else {
                /* Delete file - handle read-only files (e.g. .git/objects) */
                result = unlink(full_path);
                if (result != 0) {
                    chmod(full_path, S_IRUSR | S_IWUSR);
                    result = unlink(full_path);
                }
            }
        }

        free(full_path);
    }

    closedir(dir);
    return result;
}

/* Delete a directory and all its contents recursively */
void sn_directory_delete_recursive(const char *path)
{
    if (path == NULL) {
        fprintf(stderr, "SnDirectory.deleteRecursive: path cannot be null\n");
        exit(1);
    }

    if (!path_is_directory(path)) {
        fprintf(stderr, "SnDirectory.deleteRecursive: '%s' is not a directory\n", path);
        exit(1);
    }

    /* First delete contents recursively */
    if (delete_recursive_helper(path) != 0) {
        fprintf(stderr, "SnDirectory.deleteRecursive: failed to delete contents of '%s': %s\n",
                path, strerror(errno));
        exit(1);
    }

    /* Then delete the directory itself */
    if (rmdir(path) != 0) {
        fprintf(stderr, "SnDirectory.deleteRecursive: failed to delete directory '%s': %s\n",
                path, strerror(errno));
        exit(1);
    }
}
