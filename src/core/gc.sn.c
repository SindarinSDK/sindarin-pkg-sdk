/* ==============================================================================
 * sdk/core/gc.sn.c - GC Native Implementation
 * ==============================================================================
 * Provides Sindarin-callable wrappers for the rt_arena_v2_gc and
 * rt_arena_stats_* C APIs.
 * All functions use arena->root to access the root (main) arena.
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include "runtime/arena/arena_v2.h"

/* ==============================================================================
 * GCStats struct - must match the Sindarin struct layout
 * ============================================================================== */

typedef struct SnGCStats {
    RtArenaV2 *__arena__;
    long long handles_local;
    long long handles_children;
    long long handles_total;
    long long bytes_local;
    long long bytes_children;
    long long bytes_total;
    long long dead_handles;
    long long dead_bytes;
    long long gc_runs;
    long long last_handles_freed;
    long long last_bytes_freed;
} SnGCStats;

/* ==============================================================================
 * Native function implementations
 * ============================================================================== */

long long sn_gc_collect(RtArenaV2 *arena)
{
    RtArenaV2 *root = arena ? arena->root : NULL;
    if (root == NULL) return 0;
    return (long long)rt_arena_v2_gc(root);
}

SnGCStats sn_gc_stats(RtArenaV2 *arena)
{
    SnGCStats result;
    memset(&result, 0, sizeof(result));

    RtArenaV2 *root = arena ? arena->root : NULL;
    if (root == NULL) return result;

    RtArenaV2Stats stats;
    rt_arena_stats_get(root, &stats);

    result.handles_local    = (long long)stats.handles.local;
    result.handles_children = (long long)stats.handles.children;
    result.handles_total    = (long long)stats.handles.total;
    result.bytes_local      = (long long)stats.bytes.local;
    result.bytes_children   = (long long)stats.bytes.children;
    result.bytes_total      = (long long)stats.bytes.total;
    result.dead_handles     = (long long)stats.dead_handles;
    result.dead_bytes       = (long long)stats.dead_bytes;
    result.gc_runs          = (long long)stats.gc_runs;
    result.last_handles_freed = (long long)stats.last_handles_freed;
    result.last_bytes_freed   = (long long)stats.last_bytes_freed;

    return result;
}

void sn_gc_print(RtArenaV2 *arena)
{
    RtArenaV2 *root = arena ? arena->root : NULL;
    if (root == NULL) return;
    rt_arena_stats_print(root);
}

void sn_gc_snapshot(RtArenaV2 *arena)
{
    RtArenaV2 *root = arena ? arena->root : NULL;
    if (root == NULL) return;
    rt_arena_stats_snapshot(root);
}

void sn_gc_enable_log(RtArenaV2 *arena)
{
    RtArenaV2 *root = arena ? arena->root : NULL;
    if (root == NULL) return;
    rt_arena_stats_enable_gc_log(root);
}

void sn_gc_disable_log(RtArenaV2 *arena)
{
    RtArenaV2 *root = arena ? arena->root : NULL;
    if (root == NULL) return;
    rt_arena_stats_disable_gc_log(root);
}
