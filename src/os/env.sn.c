/* ==============================================================================
 * sdk/env.sn.c - Self-contained Environment Implementation for Sindarin SDK
 * ==============================================================================
 * Minimal runtime version - no arena, uses malloc/strdup for allocations.
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Platform-Specific Includes
 * ============================================================================ */

#ifdef _WIN32
#include <windows.h>
#else
/* POSIX systems */
extern char **environ;
#endif

/* ============================================================================
 * RtEnvironment Type Definition (Static-only, never instantiated)
 * ============================================================================ */

typedef struct RtEnvironment {
    int _unused;  /* Placeholder - this struct is never instantiated */
} RtEnvironment;

/* ============================================================================
 * Helper: cleanup function for inner SnArray* elements in the outer array
 * ============================================================================ */

static void sn_cleanup_inner_array(void *elem)
{
    SnArray **arr_ptr = (SnArray **)elem;
    if (*arr_ptr) {
        sn_cleanup_array(arr_ptr);
    }
}

/* ============================================================================
 * Environment Variable Access Functions
 * ============================================================================ */

#ifdef _WIN32

/* Windows implementation using GetEnvironmentVariable */
char *sn_env_get_required(char *name)
{
    if (name == NULL) {
        fprintf(stderr, "RuntimeError: Environment variable name cannot be null\n");
        exit(1);
    }

    DWORD size = GetEnvironmentVariableA(name, NULL, 0);
    if (size == 0) {
        fprintf(stderr, "RuntimeError: Environment variable '%s' is not set\n", name);
        exit(1);
    }

    char *buffer = (char *)malloc(size);
    if (buffer == NULL) {
        fprintf(stderr, "sn_env_get_required: allocation failed\n");
        exit(1);
    }

    DWORD result = GetEnvironmentVariableA(name, buffer, size);
    if (result == 0 || result >= size) {
        free(buffer);
        fprintf(stderr, "RuntimeError: Failed to read environment variable '%s'\n", name);
        exit(1);
    }

    return buffer;
}

char *sn_env_get_default(char *name, char *default_value)
{
    if (name == NULL) {
        return default_value ? strdup(default_value) : strdup("");
    }

    DWORD size = GetEnvironmentVariableA(name, NULL, 0);
    if (size == 0) {
        return default_value ? strdup(default_value) : strdup("");
    }

    char *buffer = (char *)malloc(size);
    if (buffer == NULL) {
        fprintf(stderr, "sn_env_get_default: allocation failed\n");
        exit(1);
    }

    DWORD result = GetEnvironmentVariableA(name, buffer, size);
    if (result == 0 || result >= size) {
        free(buffer);
        return default_value ? strdup(default_value) : strdup("");
    }

    return buffer;
}

long long sn_env_has(char *name)
{
    if (name == NULL) {
        return 0;
    }
    DWORD size = GetEnvironmentVariableA(name, NULL, 0);
    return size > 0 ? 1 : 0;
}

void sn_env_set(char *name, char *value)
{
    if (name == NULL) {
        fprintf(stderr, "RuntimeError: Environment variable name cannot be null\n");
        exit(1);
    }
    if (value == NULL) {
        fprintf(stderr, "RuntimeError: Environment variable value cannot be null\n");
        exit(1);
    }
    if (!SetEnvironmentVariableA(name, value)) {
        fprintf(stderr, "RuntimeError: Failed to set environment variable '%s'\n", name);
        exit(1);
    }
    _putenv_s(name, value);
}

SnArray *sn_env_all(void)
{
    /* Create outer array of SnArray* (each inner is a str[] pair) */
    SnArray *outer = sn_array_new(sizeof(SnArray *), 64);
    outer->elem_tag = SN_TAG_ARRAY;
    outer->elem_release = sn_cleanup_inner_array;

    LPCH envStrings = GetEnvironmentStringsA();
    if (envStrings == NULL) {
        return outer;
    }

    LPCH ptr = envStrings;
    while (*ptr) {
        if (*ptr != '=') {
            char *eq = strchr(ptr, '=');
            if (eq != NULL) {
                size_t name_len = eq - ptr;

                /* Create inner string array pair */
                SnArray *pair = sn_array_new(sizeof(char *), 2);
                pair->elem_tag = SN_TAG_STRING;
                pair->elem_release = (void (*)(void *))sn_cleanup_str;
                pair->elem_copy = sn_copy_str;

                char *name_str = (char *)malloc(name_len + 1);
                memcpy(name_str, ptr, name_len);
                name_str[name_len] = '\0';
                char *value_str = strdup(eq + 1);

                sn_array_push(pair, &name_str);
                sn_array_push(pair, &value_str);

                sn_array_push(outer, &pair);
            }
        }
        ptr += strlen(ptr) + 1;
    }

    FreeEnvironmentStringsA(envStrings);
    return outer;
}

#else

/* POSIX implementation using getenv and environ */

char *sn_env_get_required(char *name)
{
    if (name == NULL) {
        fprintf(stderr, "RuntimeError: Environment variable name cannot be null\n");
        exit(1);
    }

    const char *value = getenv(name);
    if (value == NULL) {
        fprintf(stderr, "RuntimeError: Environment variable '%s' is not set\n", name);
        exit(1);
    }

    return strdup(value);
}

char *sn_env_get_default(char *name, char *default_value)
{
    if (name == NULL) {
        return default_value ? strdup(default_value) : strdup("");
    }

    const char *value = getenv(name);
    if (value != NULL) {
        return strdup(value);
    }

    return default_value ? strdup(default_value) : strdup("");
}

long long sn_env_has(char *name)
{
    if (name == NULL) {
        return 0;
    }
    return getenv(name) != NULL ? 1 : 0;
}

void sn_env_set(char *name, char *value)
{
    if (name == NULL) {
        fprintf(stderr, "RuntimeError: Environment variable name cannot be null\n");
        exit(1);
    }
    if (value == NULL) {
        fprintf(stderr, "RuntimeError: Environment variable value cannot be null\n");
        exit(1);
    }
    if (setenv(name, value, 1) != 0) {
        fprintf(stderr, "RuntimeError: Failed to set environment variable '%s'\n", name);
        exit(1);
    }
}

SnArray *sn_env_all(void)
{
    /* Create outer array of SnArray* (each inner is a str[] pair) */
    SnArray *outer = sn_array_new(sizeof(SnArray *), 64);
    outer->elem_tag = SN_TAG_ARRAY;
    outer->elem_release = sn_cleanup_inner_array;

    for (char **e = environ; *e != NULL; e++) {
        const char *entry = *e;
        const char *eq = strchr(entry, '=');

        /* Create inner string array pair */
        SnArray *pair = sn_array_new(sizeof(char *), 2);
        pair->elem_tag = SN_TAG_STRING;
        pair->elem_release = (void (*)(void *))sn_cleanup_str;
        pair->elem_copy = sn_copy_str;

        char *name_str;
        char *value_str;
        if (eq != NULL) {
            size_t name_len = eq - entry;
            name_str = (char *)malloc(name_len + 1);
            memcpy(name_str, entry, name_len);
            name_str[name_len] = '\0';
            value_str = strdup(eq + 1);
        } else {
            name_str = strdup(entry);
            value_str = strdup("");
        }

        sn_array_push(pair, &name_str);
        sn_array_push(pair, &value_str);

        sn_array_push(outer, &pair);
    }

    return outer;
}

#endif
