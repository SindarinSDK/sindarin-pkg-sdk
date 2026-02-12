/* ==============================================================================
 * sdk/core/arena_stats.sn.c - Arena Statistics Native Implementation
 * ==============================================================================
 * Provides Sindarin-callable wrappers for the rt_arena_stats_* C API.
 * All functions use arena->root to access the root (main) arena.
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include "runtime/arena/arena_v2.h"

/* ==============================================================================
 * ArenaStats struct - must match the Sindarin struct layout
 * ============================================================================== */

typedef struct SnArenaStats {
    long long handle_count;
    long long dead_handle_count;
    long long handles_created;
    long long handles_collected;
    long long live_bytes;
    long long dead_bytes;
    long long total_allocated;
    long long total_freed;
    long long block_count;
    long long block_capacity_total;
    long long block_used_total;
    long long blocks_created;
    long long blocks_freed;
    long long gc_runs;
    double fragmentation;
} SnArenaStats;

/* ==============================================================================
 * ArenaGCReport struct - must match the Sindarin struct layout
 * ============================================================================== */

typedef struct SnArenaGCReport {
    long long handles_swept;
    long long handles_collected;
    long long blocks_swept;
    long long blocks_freed;
    long long bytes_collected;
} SnArenaGCReport;

/* ==============================================================================
 * Native function implementations
 * ============================================================================== */

SnArenaStats sn_arena_stats_get(RtArenaV2 *arena)
{
    SnArenaStats result;
    memset(&result, 0, sizeof(result));

    RtArenaV2 *root = arena ? arena->root : NULL;
    if (root == NULL) return result;

    RtArenaV2Stats stats;
    rt_arena_stats_get(root, &stats);

    result.handle_count = (long long)stats.handle_count;
    result.dead_handle_count = (long long)stats.dead_handle_count;
    result.handles_created = (long long)stats.handles_created;
    result.handles_collected = (long long)stats.handles_collected;
    result.live_bytes = (long long)stats.live_bytes;
    result.dead_bytes = (long long)stats.dead_bytes;
    result.total_allocated = (long long)stats.total_allocated;
    result.total_freed = (long long)stats.total_freed;
    result.block_count = (long long)stats.block_count;
    result.block_capacity_total = (long long)stats.block_capacity_total;
    result.block_used_total = (long long)stats.block_used_total;
    result.blocks_created = (long long)stats.blocks_created;
    result.blocks_freed = (long long)stats.blocks_freed;
    result.gc_runs = (long long)stats.gc_runs;
    result.fragmentation = stats.fragmentation * 100.0;

    return result;
}

void sn_arena_stats_print(RtArenaV2 *arena)
{
    RtArenaV2 *root = arena ? arena->root : NULL;
    if (root == NULL) return;
    rt_arena_stats_print(root);
}

SnArenaGCReport sn_arena_stats_last_gc(RtArenaV2 *arena)
{
    SnArenaGCReport result;
    memset(&result, 0, sizeof(result));

    RtArenaV2 *root = arena ? arena->root : NULL;
    if (root == NULL) return result;

    RtArenaV2GCReport report;
    rt_arena_stats_last_gc(root, &report);

    result.handles_swept = (long long)report.handles_swept;
    result.handles_collected = (long long)report.handles_collected;
    result.blocks_swept = (long long)report.blocks_swept;
    result.blocks_freed = (long long)report.blocks_freed;
    result.bytes_collected = (long long)report.bytes_collected;

    return result;
}

void sn_arena_stats_snapshot(RtArenaV2 *arena)
{
    RtArenaV2 *root = arena ? arena->root : NULL;
    if (root == NULL) return;
    rt_arena_stats_snapshot(root);
}

void sn_arena_stats_enable_gc_log(RtArenaV2 *arena)
{
    RtArenaV2 *root = arena ? arena->root : NULL;
    if (root == NULL) return;
    rt_arena_stats_enable_gc_log(root);
}

void sn_arena_stats_disable_gc_log(RtArenaV2 *arena)
{
    RtArenaV2 *root = arena ? arena->root : NULL;
    if (root == NULL) return;
    rt_arena_stats_disable_gc_log(root);
}
