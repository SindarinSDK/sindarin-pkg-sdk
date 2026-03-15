/* ==============================================================================
 * sdk/directory.sn.c - Self-contained Directory Implementation for Sindarin SDK
 * ==============================================================================
 * Minimal runtime version - no arena, uses SnArray for string array returns.
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

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static int is_path_separator(char c)
{
#ifdef _WIN32
    return c == '/' || c == '\\';
#else
    return c == '/';
#endif
}

static int path_is_directory(const char *path)
{
    if (path == NULL) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

/* ============================================================================
 * Directory Operations
 * ============================================================================ */

/* List files in a directory (non-recursive) */
SnArray *sn_directory_list(char *path)
{
    SnArray *arr = sn_array_new(sizeof(char *), 16);
    arr->elem_tag = SN_TAG_STRING;
    arr->elem_release = (void (*)(void *))sn_cleanup_str;
    arr->elem_copy = sn_copy_str;

    if (path == NULL) return arr;

    DIR *dir = opendir(path);
    if (dir == NULL) return arr;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char *name = strdup(entry->d_name);
        sn_array_push(arr, &name);
    }

    closedir(dir);
    return arr;
}

/* Helper struct for collecting strings during recursive listing */
typedef struct {
    char **buf;
    size_t count;
    size_t capacity;
} StringCollector;

static int string_collector_init(StringCollector *sc, size_t initial_capacity)
{
    sc->buf = malloc(initial_capacity * sizeof(char *));
    if (sc->buf == NULL) return -1;
    sc->count = 0;
    sc->capacity = initial_capacity;
    return 0;
}

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

static int list_recursive_helper_collect(StringCollector *sc, const char *base_path, const char *rel_prefix)
{
    DIR *dir = opendir(base_path);
    if (dir == NULL) return 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char *full_path = build_full_path(base_path, entry->d_name);
        if (full_path == NULL) { closedir(dir); return -1; }

        char *rel_path = build_rel_path(rel_prefix, entry->d_name);
        if (rel_path == NULL) { free(full_path); closedir(dir); return -1; }

        if (string_collector_add(sc, rel_path) != 0) {
            free(rel_path); free(full_path); closedir(dir); return -1;
        }

        struct stat st;
        if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            const char *added_rel_path = sc->buf[sc->count - 1];
            if (list_recursive_helper_collect(sc, full_path, added_rel_path) != 0) {
                free(full_path); closedir(dir); return -1;
            }
        }

        free(full_path);
    }

    closedir(dir);
    return 0;
}

/* List files in a directory recursively */
SnArray *sn_directory_list_recursive(char *path)
{
    if (path == NULL) {
        fprintf(stderr, "SnDirectory.listRecursive: path cannot be null\n");
        exit(1);
    }

    if (!path_is_directory(path)) {
        fprintf(stderr, "SnDirectory.listRecursive: '%s' is not a directory\n", path);
        exit(1);
    }

    StringCollector sc;
    if (string_collector_init(&sc, 64) != 0) {
        fprintf(stderr, "SnDirectory.listRecursive: allocation failed\n");
        exit(1);
    }

    if (list_recursive_helper_collect(&sc, path, "") != 0) {
        string_collector_free(&sc);
        fprintf(stderr, "SnDirectory.listRecursive: failed\n");
        exit(1);
    }

    /* Build SnArray from collected strings */
    SnArray *arr = sn_array_new(sizeof(char *), (long long)sc.count);
    arr->elem_tag = SN_TAG_STRING;
    arr->elem_release = (void (*)(void *))sn_cleanup_str;
    arr->elem_copy = sn_copy_str;

    for (size_t i = 0; i < sc.count; i++) {
        char *s = strdup(sc.buf[i]);
        sn_array_push(arr, &s);
    }

    string_collector_free(&sc);
    return arr;
}

/* ============================================================================
 * Directory Create/Delete
 * ============================================================================ */

static int create_directory_recursive(const char *path)
{
    if (path == NULL || *path == '\0') return 0;

    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;
    }

    size_t len = strlen(path);
    char *path_copy = malloc(len + 1);
    if (path_copy == NULL) return -1;
    strcpy(path_copy, path);

    char *p = path_copy;

#ifdef _WIN32
    if (len >= 3 && path_copy[1] == ':' && is_path_separator(path_copy[2])) {
        p = path_copy + 3;
    }
#endif

    while (is_path_separator(*p)) p++;

    while (*p) {
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

    int result = MKDIR(path_copy, 0755);
    free(path_copy);

    if (result != 0 && errno != EEXIST) return -1;
    return 0;
}

void sn_directory_create(char *path)
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

void sn_directory_delete(char *path)
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

static int delete_recursive_helper(const char *path)
{
    DIR *dir = opendir(path);
    if (dir == NULL) return -1;

    struct dirent *entry;
    int result = 0;

    while ((entry = readdir(dir)) != NULL && result == 0) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        size_t path_len = strlen(path);
        size_t name_len = strlen(entry->d_name);
        int has_sep = (path_len > 0 && is_path_separator(path[path_len - 1]));
        char *full_path = malloc(path_len + (has_sep ? 0 : 1) + name_len + 1);
        if (full_path == NULL) { result = -1; break; }

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
                result = delete_recursive_helper(full_path);
                if (result == 0) result = rmdir(full_path);
            } else {
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

void sn_directory_delete_recursive(char *path)
{
    if (path == NULL) {
        fprintf(stderr, "SnDirectory.deleteRecursive: path cannot be null\n");
        exit(1);
    }

    if (!path_is_directory(path)) {
        fprintf(stderr, "SnDirectory.deleteRecursive: '%s' is not a directory\n", path);
        exit(1);
    }

    if (delete_recursive_helper(path) != 0) {
        fprintf(stderr, "SnDirectory.deleteRecursive: failed to delete contents of '%s': %s\n",
                path, strerror(errno));
        exit(1);
    }

    if (rmdir(path) != 0) {
        fprintf(stderr, "SnDirectory.deleteRecursive: failed to delete directory '%s': %s\n",
                path, strerror(errno));
        exit(1);
    }
}
