/* ============================================================================
 * sdk/sync/rwlock.sn.c - Fair Read-Write Lock implementation
 * ============================================================================
 * Fair userspace RwLock using mutex + condition variables.
 * When a writer is waiting, new readers block until the writer finishes.
 * This prevents writer starvation under read-heavy workloads.
 *
 * Fairness policy (matches Go's sync.RWMutex):
 *   - Multiple readers can hold the lock concurrently
 *   - Writers get exclusive access
 *   - When a writer is waiting, new readers block
 *   - After a writer finishes, waiting writers take priority over readers
 * ============================================================================ */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

/* ============================================================================
 * RtRwLock — maps to the Sindarin RwLock struct
 * ============================================================================ */

typedef __sn__RwLock RtRwLock;

/* Fair RwLock internal state */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t  readers_ok;
    pthread_cond_t  writers_ok;
    int             active_readers;
    int             active_writers;     /* 0 or 1 */
    int             waiting_writers;
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
    pthread_cond_init(&internal->readers_ok, NULL);
    pthread_cond_init(&internal->writers_ok, NULL);
    internal->active_readers = 0;
    internal->active_writers = 0;
    internal->waiting_writers = 0;

    rwlock_register_internal(lock, internal);
    return lock;
}

void sn_rwlock_read_lock(RtRwLock *lock) {
    RwLockInternal *rw = rwlock_get_internal(lock);
    if (!rw) return;

    pthread_mutex_lock(&rw->mutex);
    /* Block if a writer is active or writers are waiting (fairness) */
    while (rw->active_writers > 0 || rw->waiting_writers > 0) {
        pthread_cond_wait(&rw->readers_ok, &rw->mutex);
    }
    rw->active_readers++;
    pthread_mutex_unlock(&rw->mutex);
}

void sn_rwlock_read_unlock(RtRwLock *lock) {
    RwLockInternal *rw = rwlock_get_internal(lock);
    if (!rw) return;

    pthread_mutex_lock(&rw->mutex);
    rw->active_readers--;
    if (rw->active_readers == 0 && rw->waiting_writers > 0) {
        /* Last reader — wake one waiting writer */
        pthread_cond_signal(&rw->writers_ok);
    }
    pthread_mutex_unlock(&rw->mutex);
}

void sn_rwlock_write_lock(RtRwLock *lock) {
    RwLockInternal *rw = rwlock_get_internal(lock);
    if (!rw) return;

    pthread_mutex_lock(&rw->mutex);
    rw->waiting_writers++;
    while (rw->active_readers > 0 || rw->active_writers > 0) {
        pthread_cond_wait(&rw->writers_ok, &rw->mutex);
    }
    rw->waiting_writers--;
    rw->active_writers = 1;
    pthread_mutex_unlock(&rw->mutex);
}

void sn_rwlock_write_unlock(RtRwLock *lock) {
    RwLockInternal *rw = rwlock_get_internal(lock);
    if (!rw) return;

    pthread_mutex_lock(&rw->mutex);
    rw->active_writers = 0;
    if (rw->waiting_writers > 0) {
        /* Writers take priority — wake one writer */
        pthread_cond_signal(&rw->writers_ok);
    } else {
        /* No waiting writers — wake all blocked readers */
        pthread_cond_broadcast(&rw->readers_ok);
    }
    pthread_mutex_unlock(&rw->mutex);
}

void sn_rwlock_dispose(RtRwLock *lock) {
    RwLockInternal *rw = rwlock_get_internal(lock);
    if (rw) {
        pthread_mutex_destroy(&rw->mutex);
        pthread_cond_destroy(&rw->readers_ok);
        pthread_cond_destroy(&rw->writers_ok);
        rwlock_unregister_internal(lock);
        free(rw);
    }
}
