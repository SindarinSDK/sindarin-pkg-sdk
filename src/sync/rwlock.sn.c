/* ============================================================================
 * sdk/sync/rwlock.sn.c - Fair Read-Write Lock (Go-style fairness)
 * ============================================================================
 * Fair RwLock using mutex + condition variables + atomic reader count.
 *
 * Fairness: when a writer arrives, it sets a flag that blocks new readers.
 * Only existing active readers continue. Once they finish, the writer runs.
 * After the writer finishes, all blocked readers are released before the
 * next writer can acquire. This gives natural reader/writer interleaving.
 * ============================================================================ */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>

/* ============================================================================
 * RtRwLock — maps to the Sindarin RwLock struct
 * ============================================================================ */

typedef __sn__RwLock RtRwLock;

#define RW_MAX_READERS (1 << 30)

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t  writer_cond;    /* writer waits here for readers to drain */
    pthread_cond_t  reader_cond;    /* readers wait here when writer is pending */
    int             reader_count;   /* active readers (negative = writer pending) */
    int             reader_wait;    /* readers the writer is waiting for */
    pthread_mutex_t writer_mutex;   /* serializes writers */
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

    pthread_mutex_init(&internal->mutex, NULL);
    pthread_cond_init(&internal->writer_cond, NULL);
    pthread_cond_init(&internal->reader_cond, NULL);
    pthread_mutex_init(&internal->writer_mutex, NULL);
    internal->reader_count = 0;
    internal->reader_wait = 0;

    rwlock_register_internal(lock, internal);
    return lock;
}

void sn_rwlock_read_lock(RtRwLock *lock) {
    RwLockInternal *rw = rwlock_get_internal(lock);
    if (!rw) return;

    pthread_mutex_lock(&rw->mutex);
    rw->reader_count++;
    if (rw->reader_count <= 0) {
        /* reader_count was negative → writer is pending. Block. */
        pthread_cond_wait(&rw->reader_cond, &rw->mutex);
    }
    pthread_mutex_unlock(&rw->mutex);
}

void sn_rwlock_read_unlock(RtRwLock *lock) {
    RwLockInternal *rw = rwlock_get_internal(lock);
    if (!rw) return;

    pthread_mutex_lock(&rw->mutex);
    rw->reader_count--;
    if (rw->reader_count < 0) {
        /* Writer is pending. Decrement departing count. */
        rw->reader_wait--;
        if (rw->reader_wait == 0) {
            /* Last departing reader — wake the writer */
            pthread_cond_signal(&rw->writer_cond);
        }
    }
    pthread_mutex_unlock(&rw->mutex);
}

void sn_rwlock_write_lock(RtRwLock *lock) {
    RwLockInternal *rw = rwlock_get_internal(lock);
    if (!rw) return;

    /* Serialize writers */
    pthread_mutex_lock(&rw->writer_mutex);

    pthread_mutex_lock(&rw->mutex);
    /* Make reader_count negative — blocks new readers */
    rw->reader_count -= RW_MAX_READERS;
    /* Number of active readers we need to wait for */
    int active = rw->reader_count + RW_MAX_READERS;
    rw->reader_wait += active;
    if (rw->reader_wait != 0) {
        /* Wait for active readers to finish */
        pthread_cond_wait(&rw->writer_cond, &rw->mutex);
    }
    pthread_mutex_unlock(&rw->mutex);
}

void sn_rwlock_write_unlock(RtRwLock *lock) {
    RwLockInternal *rw = rwlock_get_internal(lock);
    if (!rw) return;

    pthread_mutex_lock(&rw->mutex);
    /* Make reader_count positive again */
    rw->reader_count += RW_MAX_READERS;
    int blocked = rw->reader_count;
    /* Wake all blocked readers */
    for (int i = 0; i < blocked; i++) {
        pthread_cond_signal(&rw->reader_cond);
    }
    pthread_mutex_unlock(&rw->mutex);

    /* Let next writer try */
    pthread_mutex_unlock(&rw->writer_mutex);
}

void sn_rwlock_dispose(RtRwLock *lock) {
    RwLockInternal *rw = rwlock_get_internal(lock);
    if (rw) {
        pthread_mutex_destroy(&rw->mutex);
        pthread_cond_destroy(&rw->writer_cond);
        pthread_cond_destroy(&rw->reader_cond);
        pthread_mutex_destroy(&rw->writer_mutex);
        rwlock_unregister_internal(lock);
        free(rw);
    }
}
