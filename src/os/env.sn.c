/* ==============================================================================
 * sdk/env.sn.c - Self-contained Environment Implementation for Sindarin SDK
 * ==============================================================================
 * This file provides the C implementation for the SnEnvironment type.
 * It is compiled via #pragma source and linked with Sindarin code.
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Include runtime arena and array for proper memory management */
#include "runtime/runtime_arena.h"
#include "runtime/arena/managed_arena.h"
#include "runtime/runtime_array_h.h"

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
 * Array Metadata Structure (must match runtime)
 * ============================================================================ */

typedef struct {
    RtArena *arena;
    size_t size;
    size_t capacity;
} RtArrayMetadata;

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/* Create a string array in the arena */
static char **sn_create_string_array(RtArena *arena, size_t count)
{
    char **result = rt_arena_alloc(arena, sizeof(RtArrayMetadata) + count * sizeof(char *));
    if (result == NULL) {
        fprintf(stderr, "sn_create_string_array: allocation failed\n");
        exit(1);
    }

    RtArrayMetadata *meta = (RtArrayMetadata *)result;
    meta->arena = arena;
    meta->size = count;
    meta->capacity = count;

    return (char **)(meta + 1);
}

/* ============================================================================
 * Environment Variable Access Functions
 * ============================================================================ */

#ifdef _WIN32

/* Windows implementation using GetEnvironmentVariable */
RtHandle sn_env_get_required(RtManagedArena *arena, const char *name)
{
    if (arena == NULL || name == NULL) {
        fprintf(stderr, "RuntimeError: Environment variable name cannot be null\n");
        exit(1);
    }

    /* First call to get required buffer size */
    DWORD size = GetEnvironmentVariableA(name, NULL, 0);
    if (size == 0) {
        /* Variable not found */
        fprintf(stderr, "RuntimeError: Environment variable '%s' is not set\n", name);
        exit(1);
    }

    /* Allocate stack buffer and get the value */
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

    RtHandle h = rt_managed_strdup(arena, RT_HANDLE_NULL, buffer);
    free(buffer);
    return h;
}

RtHandle sn_env_get_default(RtManagedArena *arena, const char *name, const char *default_value)
{
    if (arena == NULL || name == NULL) {
        return default_value ? rt_managed_strdup(arena, RT_HANDLE_NULL, default_value) : RT_HANDLE_NULL;
    }

    /* First call to get required buffer size */
    DWORD size = GetEnvironmentVariableA(name, NULL, 0);
    if (size == 0) {
        /* Variable not found, return default */
        if (default_value != NULL) {
            return rt_managed_strdup(arena, RT_HANDLE_NULL, default_value);
        }
        return RT_HANDLE_NULL;
    }

    /* Allocate temporary buffer and get the value */
    char *buffer = (char *)malloc(size);
    if (buffer == NULL) {
        fprintf(stderr, "sn_env_get_default: allocation failed\n");
        exit(1);
    }

    DWORD result = GetEnvironmentVariableA(name, buffer, size);
    if (result == 0 || result >= size) {
        free(buffer);
        /* Error, return default */
        if (default_value != NULL) {
            return rt_managed_strdup(arena, RT_HANDLE_NULL, default_value);
        }
        return RT_HANDLE_NULL;
    }

    RtHandle h = rt_managed_strdup(arena, RT_HANDLE_NULL, buffer);
    free(buffer);
    return h;
}

int sn_env_has(const char *name)
{
    if (name == NULL) {
        return 0;
    }
    DWORD size = GetEnvironmentVariableA(name, NULL, 0);
    return size > 0 ? 1 : 0;
}

void sn_env_set(const char *name, const char *value)
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
    /* Also set for CRT so getenv() sees the change */
    _putenv_s(name, value);
}

RtHandle sn_env_all(RtManagedArena *arena)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }

    /* Get the environment block */
    LPCH envStrings = GetEnvironmentStringsA();
    if (envStrings == NULL) {
        return RT_HANDLE_NULL;
    }

    /* First pass: count entries */
    size_t count = 0;
    LPCH ptr = envStrings;
    while (*ptr) {
        /* Skip entries that start with '=' (Windows internal variables) */
        if (*ptr != '=') {
            count++;
        }
        ptr += strlen(ptr) + 1;
    }

    /* Allocate temporary storage for inner handles */
    RtHandle *temp_handles = NULL;
    if (count > 0) {
        temp_handles = (RtHandle *)malloc(count * sizeof(RtHandle));
        if (temp_handles == NULL) {
            FreeEnvironmentStringsA(envStrings);
            fprintf(stderr, "sn_env_all: allocation failed\n");
            exit(1);
        }
    }

    /* Second pass: populate temporary array */
    ptr = envStrings;
    size_t idx = 0;
    while (*ptr && idx < count) {
        if (*ptr != '=') {
            /* Find the '=' separator */
            char *eq = strchr(ptr, '=');
            if (eq != NULL) {
                size_t name_len = eq - ptr;

                /* Create pair as string handles */
                RtHandle name_h = rt_managed_strndup(arena, RT_HANDLE_NULL, ptr, name_len);
                RtHandle value_h = rt_managed_strdup(arena, RT_HANDLE_NULL, eq + 1);

                /* Create inner array of 2 string handles */
                RtHandle pair_handles[2] = { name_h, value_h };
                RtHandle inner_h = rt_array_create_uint32_h(arena, 2, pair_handles);
                temp_handles[idx++] = inner_h;
            }
        }
        ptr += strlen(ptr) + 1;
    }

    FreeEnvironmentStringsA(envStrings);

    /* Create outer array handle from temporary handles */
    RtHandle result = rt_array_create_uint32_h(arena, idx, temp_handles);
    free(temp_handles);
    return result;
}

#else

/* POSIX implementation using getenv and environ */

RtHandle sn_env_get_required(RtManagedArena *arena, const char *name)
{
    if (arena == NULL || name == NULL) {
        fprintf(stderr, "RuntimeError: Environment variable name cannot be null\n");
        exit(1);
    }

    const char *value = getenv(name);
    if (value == NULL) {
        fprintf(stderr, "RuntimeError: Environment variable '%s' is not set\n", name);
        exit(1);
    }

    /* Copy to managed arena (getenv returns pointer to static storage) */
    return rt_managed_strdup(arena, RT_HANDLE_NULL, value);
}

RtHandle sn_env_get_default(RtManagedArena *arena, const char *name, const char *default_value)
{
    if (arena == NULL || name == NULL) {
        return default_value ? rt_managed_strdup(arena, RT_HANDLE_NULL, default_value) : RT_HANDLE_NULL;
    }

    const char *value = getenv(name);
    if (value != NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, value);
    }

    /* Variable not set, return default */
    if (default_value != NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, default_value);
    }
    return RT_HANDLE_NULL;
}

int sn_env_has(const char *name)
{
    if (name == NULL) {
        return 0;
    }
    return getenv(name) != NULL ? 1 : 0;
}

void sn_env_set(const char *name, const char *value)
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

RtHandle sn_env_all(RtManagedArena *arena)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }

    /* Count entries */
    size_t count = 0;
    for (char **e = environ; *e != NULL; e++) {
        count++;
    }

    /* Allocate temporary storage for inner handles */
    RtHandle *temp_handles = NULL;
    if (count > 0) {
        temp_handles = (RtHandle *)malloc(count * sizeof(RtHandle));
        if (temp_handles == NULL) {
            fprintf(stderr, "sn_env_all: allocation failed\n");
            exit(1);
        }
    }

    /* Populate temporary array with inner string array handles */
    for (size_t i = 0; i < count; i++) {
        const char *entry = environ[i];
        const char *eq = strchr(entry, '=');

        /* Create inner pair as handle array using handle-based allocation */
        RtHandle name_h, value_h;
        if (eq != NULL) {
            size_t name_len = eq - entry;
            name_h = rt_managed_strndup(arena, RT_HANDLE_NULL, entry, name_len);
            value_h = rt_managed_strdup(arena, RT_HANDLE_NULL, eq + 1);
        } else {
            /* Malformed entry (no '='), use empty value */
            name_h = rt_managed_strdup(arena, RT_HANDLE_NULL, entry);
            value_h = rt_managed_strdup(arena, RT_HANDLE_NULL, "");
        }

        /* Create inner array of 2 string handles using handle-based allocation */
        RtHandle pair_handles[2] = { name_h, value_h };
        RtHandle inner_h = rt_array_create_uint32_h(arena, 2, pair_handles);
        temp_handles[i] = inner_h;
    }

    /* Create outer array handle from temporary handles */
    RtHandle result = rt_array_create_uint32_h(arena, count, temp_handles);
    free(temp_handles);
    return result;
}

#endif
