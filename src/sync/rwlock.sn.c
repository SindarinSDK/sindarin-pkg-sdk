/* ============================================================================
 * sdk/sync/rwlock.sn.c - Read-Write Lock implementation
 * ============================================================================
 * Wraps pthread_rwlock_t for POSIX systems.
 * Multiple readers can hold the lock concurrently; writers get exclusive access.
 * ============================================================================ */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

/* ============================================================================
 * RtRwLock — maps to the Sindarin RwLock struct
 * ============================================================================ */

typedef __sn__RwLock RtRwLock;

/* Internal state: the actual pthread rwlock */
typedef struct {
    pthread_rwlock_t rwlock;
} RwLockInternal;

/* ---- Internal state table ---- */

#define RWLOCK_TABLE_SIZE 64
static struct { RtRwLock *key; RwLockInternal *val; } rwlock_table[RWLOCK_TABLE_SIZE];
static int rwlock_table_count = 0;
static pthread_mutex_t rwlock_table_mutex = PTHREAD_MUTEX_INITIALIZER;

static RwLockInternal *rwlock_get_internal(RtRwLock *lock) {
    for (int i = 0; i < rwlock_table_count; i++) {
        if (rwlock_table[i].key == lock) return rwlock_table[i].val;
    }
    return NULL;
}

static void rwlock_register_internal(RtRwLock *lock, RwLockInternal *internal) {
    pthread_mutex_lock(&rwlock_table_mutex);
    if (rwlock_table_count < RWLOCK_TABLE_SIZE) {
        rwlock_table[rwlock_table_count].key = lock;
        rwlock_table[rwlock_table_count].val = internal;
        rwlock_table_count++;
    }
    pthread_mutex_unlock(&rwlock_table_mutex);
}

static void rwlock_unregister_internal(RtRwLock *lock) {
    pthread_mutex_lock(&rwlock_table_mutex);
    for (int i = 0; i < rwlock_table_count; i++) {
        if (rwlock_table[i].key == lock) {
            rwlock_table[i] = rwlock_table[--rwlock_table_count];
            break;
        }
    }
    pthread_mutex_unlock(&rwlock_table_mutex);
}

/* ============================================================================
 * Public API
 * ============================================================================ */

RtRwLock *sn_rwlock_new(void) {
    RtRwLock *lock = (RtRwLock *)calloc(1, sizeof(RtRwLock));
    if (!lock) {
        fprintf(stderr, "sn_rwlock_new: allocation failed\n");
        exit(1);
    }

    RwLockInternal *internal = (RwLockInternal *)calloc(1, sizeof(RwLockInternal));
    if (!internal) {
        fprintf(stderr, "sn_rwlock_new: allocation failed\n");
        exit(1);
    }

    pthread_rwlock_init(&internal->rwlock, NULL);
    rwlock_register_internal(lock, internal);

    return lock;
}

void sn_rwlock_read_lock(RtRwLock *lock) {
    RwLockInternal *internal = rwlock_get_internal(lock);
    if (internal) pthread_rwlock_rdlock(&internal->rwlock);
}

void sn_rwlock_read_unlock(RtRwLock *lock) {
    RwLockInternal *internal = rwlock_get_internal(lock);
    if (internal) pthread_rwlock_unlock(&internal->rwlock);
}

void sn_rwlock_write_lock(RtRwLock *lock) {
    RwLockInternal *internal = rwlock_get_internal(lock);
    if (internal) pthread_rwlock_wrlock(&internal->rwlock);
}

void sn_rwlock_write_unlock(RtRwLock *lock) {
    RwLockInternal *internal = rwlock_get_internal(lock);
    if (internal) pthread_rwlock_unlock(&internal->rwlock);
}

void sn_rwlock_dispose(RtRwLock *lock) {
    RwLockInternal *internal = rwlock_get_internal(lock);
    if (internal) {
        pthread_rwlock_destroy(&internal->rwlock);
        rwlock_unregister_internal(lock);
        free(internal);
    }
}
