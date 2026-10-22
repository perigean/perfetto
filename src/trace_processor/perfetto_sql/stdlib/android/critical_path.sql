--
-- Copyright 2026 The Android Open Source Project
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     https://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

INCLUDE PERFETTO MODULE intervals.intersect;

INCLUDE PERFETTO MODULE slices.with_context;

-- Work-passing wakeup graph nodes for Android critical path analysis.
--
-- The first 7 columns (`id, utid, ts, dur, idle_dur, waker_id, prev_id`) match
-- the signature of `__intrinsic_wakeup_graph_agg` directly:
--   * `ts` is when `ready_utid` readied or passed work to `utid`, so the C++
--     walker delegates `[$query_ts, ts)` to `waker_id` and attributes
--     `[max($query_ts, ts), window_end)` to this node.
--   * `exec_ts` is when `utid` finished waiting on the ready event and started
--     executing (`[ts, exec_ts)` is the ready/waiting interval, and
--     `[exec_ts, window_end)` is the running/execution interval).
--   * `dur` extends to `trace_end() - ts`. For most nodes `idle_dur` and
--     `prev_id` are `NULL` (open idle window before `ts`). For synchronous
--     binder replies, `idle_dur` is `(reply_ts + reply_dur) - tx_ts` and
--     `prev_id` points to the client thread's node at `tx_ts`, ensuring the
--     critical path always returns to the caller at the start of the binder
--     transaction.
CREATE PERFETTO TABLE _android_wakeup_graph(
  id LONG,
  utid JOINID(thread.id),
  ts TIMESTAMP,
  dur DURATION,
  idle_dur DURATION,
  waker_id LONG,
  prev_id LONG,
  exec_ts TIMESTAMP,
  ready_utid JOINID(thread.id),
  ready_type STRING,
  ready_info STRING
)
AS
WITH
  -- thread_ready, if we don't match any work passing types, we follow the waker_utid on thread_ready
  -- slices. With the exception that we don't follow if the previous state was uninterruptible sleep.
  thread_state_previous AS (
    SELECT *, lag(state) OVER (PARTITION BY utid ORDER BY ts ASC) AS prev_state
    FROM thread_state
  ),
  thread_ready AS (
    SELECT
      utid,
      ts,
      ts + dur AS exec_ts,
      CAST(NULL AS INT) AS idle_dur,
      CASE WHEN irq_context = 1 THEN NULL ELSE waker_utid END AS ready_utid,
      'thread_ready' AS ready_type,
      '' AS ready_info
    FROM thread_state_previous
    WHERE
      waker_utid IS NOT NULL
      -- Ignore ready that wake us after uninterruptible sleep, but follow
      -- ready if there is no previous state (thread is new).
      AND (prev_state != 'D' OR prev_state IS NULL)
      -- dur can be -1 when we're missing data, usually at the beginning and
      -- end of traces
      AND dur >= 0
  ),
  -- hardware_drm_waits are waits for hardware to be in a specific state. If we followed the
  -- thread_ready rows above we would end up at a dead end when we are woken by an
  -- interrupt. Instead we follow backwards to the beginning of the wait.
  hardware_drm_waits AS (
    SELECT
      utid,
      ts,
      ts + dur AS exec_ts,
      CAST(NULL AS INT) AS idle_dur,
      utid AS ready_utid,
      'hardware DRM wait' AS ready_type,
      name AS ready_info
    FROM thread_slice
    WHERE
      process_name = '/vendor/bin/hw/android.hardware.composer.hwc3-service.drm'
      AND is_main_thread = 1
      AND (name = 'EbusyRetryWait'
      OR name = 'WaitForPresentTime'
      OR name = 'WaitPriorFramePresented')
      AND dur > 0
  ),
  -- monitor_lock_contention skip over regions where we are trying to acquire a lock. We don't want to
  -- follow path of the lock holder, because that is incidental to the actual critical path. Instead
  -- skip back to the beginning of the lock contention and keep following back on the same thread.
  monitor_lock_contention AS (
    SELECT
      utid,
      ts,
      ts + dur AS exec_ts,
      CAST(NULL AS INT) AS idle_dur,
      utid AS ready_utid,
      'lock contention' AS ready_type,
      name AS ready_info
    FROM thread_slice
    WHERE
      name GLOB 'Lock contention on a monitor lock*'
      AND dur > 0
  ),
  -- vsync follows Choreographer#onVsync slices back to the scheduleVsyncLocked call. If we did not,
  -- then we would reach a dead end when woken by the vsync timer interrupt.
  vsync_slices AS (
    SELECT
      ts,
      utid,
      name,
      lead(name) OVER (PARTITION BY utid ORDER BY ts ASC) AS next_name,
      lead(ts + dur) OVER (PARTITION BY utid ORDER BY ts ASC) AS next_end_ts
    FROM thread_slice
    WHERE
      name = 'Choreographer#scheduleVsyncLocked'
      OR (name GLOB 'Choreographer#onVsync *' AND dur >= 0)
  ),
  vsync AS (
    SELECT
      utid,
      ts,
      next_end_ts AS exec_ts,
      CAST(NULL AS INT) AS idle_dur,
      utid AS ready_utid,
      'vsync' AS ready_type,
      substr(next_name, 23) AS ready_info
    FROM vsync_slices
    WHERE
      name = 'Choreographer#scheduleVsyncLocked'
      AND next_name GLOB 'Choreographer#onVsync *'
  ),
  -- binder transactions follow both synchronous and asynchronous transactions.
  binder_sync_txns AS (
    SELECT
      tx.ts AS tx_ts,
      tx.dur AS tx_dur,
      tx.utid AS tx_utid,
      reply.ts AS reply_ts,
      reply.dur AS reply_dur,
      reply.utid AS reply_utid,
      CASE WHEN parent.name GLOB 'AIDL::*' THEN parent.name ELSE '' END AS ready_info
    FROM thread_slice AS tx
    JOIN flow
      ON flow.slice_out = tx.id
    JOIN thread_slice AS reply
      ON reply.id = flow.slice_in
    LEFT JOIN slice AS parent
      ON parent.id = tx.parent_id
    WHERE
      tx.name = 'binder transaction'
      AND reply.name = 'binder reply'
  ),
  binder_sync_call AS (
    SELECT
      reply_utid AS utid,
      tx_ts AS ts,
      reply_ts AS exec_ts,
      CAST(NULL AS INT) AS idle_dur,
      tx_utid AS ready_utid,
      'binder transaction' AS ready_type,
      ready_info
    FROM binder_sync_txns
  ),
  binder_sync_reply AS (
    SELECT
      tx_utid AS utid,
      reply_ts + reply_dur AS ts,
      tx_ts + tx_dur AS exec_ts,
      (reply_ts + reply_dur) - tx_ts AS idle_dur,
      reply_utid AS ready_utid,
      'binder reply' AS ready_type,
      ready_info
    FROM binder_sync_txns
    WHERE
      tx_dur > 0
      AND reply_dur >= 0
      AND reply_ts + reply_dur >= tx_ts
  ),
  binder_async AS (
    SELECT
      rcv.utid AS utid,
      tx.ts AS ts,
      rcv.ts AS exec_ts,
      CAST(NULL AS INT) AS idle_dur,
      tx.utid AS ready_utid,
      'binder transaction async' AS ready_type,
      CASE WHEN parent.name GLOB 'AIDL::*' THEN parent.name ELSE '' END AS ready_info
    FROM thread_slice AS tx
    JOIN flow
      ON flow.slice_out = tx.id
    JOIN thread_slice AS rcv
      ON rcv.id = flow.slice_in
    LEFT JOIN slice AS parent
      ON parent.id = tx.parent_id
    WHERE
      tx.name = 'binder transaction async'
      AND rcv.name = 'binder async rcv'
  ),
  -- input_channel follows receiveMessage calls back the the corresponding sendMessage call.
  -- NB: Materializing ic_send prevents SQLite from flattening the CTE and performing a nested-loop
  -- scan of thread_slice for every ic_recv row, allowing SQLite to build an automatic index on
  -- message_id instead.
  ic_send AS MATERIALIZED (
    SELECT ts, utid, substr(name, 26, length(name) - 27) AS message_id
    FROM thread_slice
    WHERE
      name GLOB 'sendMessage(inputChannel=*'
  ),
  ic_recv AS (
    SELECT ts, utid, substr(name, 29, length(name) - 30) AS message_id
    FROM thread_slice
    WHERE
      name GLOB 'receiveMessage(inputChannel=*'
  ),
  input_channel AS (
    SELECT
      ic_recv.utid AS utid,
      ic_send.ts AS ts,
      ic_recv.ts AS exec_ts,
      CAST(NULL AS INT) AS idle_dur,
      ic_send.utid AS ready_utid,
      'input channel' AS ready_type,
      message_id AS ready_info
    FROM ic_recv
    JOIN ic_send USING (message_id)
  ),
  -- TODO: mojo
  -- TODO: post task, looper, etc.
  raw_edges AS (
    SELECT * FROM thread_ready
    UNION ALL
    SELECT * FROM hardware_drm_waits
    UNION ALL
    SELECT * FROM monitor_lock_contention
    UNION ALL
    SELECT * FROM vsync
    UNION ALL
    SELECT * FROM binder_sync_call
    UNION ALL
    SELECT * FROM binder_sync_reply
    UNION ALL
    SELECT * FROM binder_async
    UNION ALL
    SELECT * FROM input_channel
  ),
  nodes AS (
    SELECT
      row_number() OVER (ORDER BY exec_ts ASC, ts ASC, utid ASC) AS id,
      utid,
      ts,
      exec_ts,
      idle_dur,
      ready_utid,
      ready_type,
      ready_info
    FROM raw_edges
  ),
  -- Interleave node-start events (kind = 0, at `exec_ts` on `utid`) with
  -- ready-lookup events (kind = 1, at `ts` on `ready_utid`) and prev-lookup
  -- events (kind = 2, at `ts - idle_dur` on `utid`). Because node `id`
  -- increases monotonically with `exec_ts`, `max(node_id)` over all preceding
  -- events on the same thread yields the latest node active at that timestamp.
  events AS (
    SELECT
      utid,
      exec_ts AS event_ts,
      0 AS kind,
      id AS node_id,
      NULL AS lookup_id
    FROM nodes
    UNION ALL
    SELECT
      ready_utid AS utid,
      ts AS event_ts,
      1 AS kind,
      NULL AS node_id,
      id AS lookup_id
    FROM nodes
    WHERE
      ready_utid IS NOT NULL
    UNION ALL
    SELECT
      utid,
      ts - idle_dur AS event_ts,
      2 AS kind,
      NULL AS node_id,
      id AS lookup_id
    FROM nodes
    WHERE
      idle_dur IS NOT NULL
  ),
  resolved AS (
    SELECT
      kind,
      lookup_id,
      max(node_id) OVER (
        PARTITION BY
          utid
        ORDER BY event_ts ASC, kind ASC, node_id ASC
      ) AS target_id
    FROM events
  )
SELECT
  n.id,
  n.utid,
  n.ts,
  trace_end() - n.ts AS dur,
  n.idle_dur,
  waker.target_id AS waker_id,
  prev.target_id AS prev_id,
  n.exec_ts,
  n.ready_utid,
  n.ready_type,
  n.ready_info
FROM nodes AS n
LEFT JOIN resolved AS waker
  ON waker.kind = 1
  AND waker.lookup_id = n.id
LEFT JOIN resolved AS prev
  ON prev.kind = 2
  AND prev.lookup_id = n.id
ORDER BY
  n.id ASC;

CREATE PERFETTO INDEX _android_wakeup_graph_index ON _android_wakeup_graph(
  utid,
  exec_ts
);

-- Wrapper macro around `__intrinsic_wakeup_graph_agg` and
-- `__intrinsic_critical_path_walk` (mirrors `_critical_path_with_depth_by_roots`
-- in `sched/thread_executing_span.sql`).
CREATE PERFETTO MACRO _critical_path_walk_by_roots(
  _roots_table TableOrSubQuery,
  _node_table TableOrSubQuery
)
RETURNS TableOrSubQuery
AS (
  SELECT
    c0 AS root_id,
    c1 AS depth,
    c2 AS ts,
    c3 AS dur,
    c4 AS id,
    c6 AS parent_id
  FROM __intrinsic_table_ptr(
    __intrinsic_critical_path_walk(
      (
        SELECT
          __intrinsic_wakeup_graph_agg(id, utid, ts, dur, idle_dur, waker_id, prev_id)
        FROM $_node_table
      ),
      (
        SELECT
          __intrinsic_array_agg(root_node_id)
        FROM $_roots_table
      )
    )
  )
  WHERE
    __intrinsic_table_ptr_bind(c0, 'root_id')
    AND __intrinsic_table_ptr_bind(c1, 'depth')
    AND __intrinsic_table_ptr_bind(c2, 'ts')
    AND __intrinsic_table_ptr_bind(c3, 'dur')
    AND __intrinsic_table_ptr_bind(c4, 'blocker_id')
    AND __intrinsic_table_ptr_bind(c5, 'blocker_utid')
    AND __intrinsic_table_ptr_bind(c6, 'parent_id')
);

-- Builds a path of thread activity by starting at the end of a span and working
-- backwards to the start following RPCs and thread_ready events. The advantage of working backwards
-- is that we don't need to branch the path if there are multiple parallel work items that need to
-- finish before the end of the span. We follow the one that finished last and ended up waking the
-- thread that completed the work. So reducing cost on the critical path by X ms may not improve
-- responsiveness by the same amount.
--
-- ready_type and ready_info values:
-- * 'thread_ready': Woken from sleep via kernel scheduler wakeup (ready_utid is waker_utid, or NULL
--   if woken from interrupt context).
--   * '': Always empty.
-- * 'hardware DRM wait': HWC DRM main thread wait slice, passing from the start to the end of the
--   wait on the same thread.
--   * 'EbusyRetryWait': Waiting to retry after a DRM operation returned EBUSY.
--   * 'WaitForPresentTime': Waiting until the target presentation time arrives.
--   * 'WaitPriorFramePresented': Waiting for the prior frame to finish presenting.
-- * 'lock contention': Blocked waiting to acquire a Java monitor lock, passing work from the start
--   to the end of the contention slice on the same thread.
--   * 'Lock contention on a monitor lock*': Slice name, including the lock owner tid (e.g.
--     'Lock contention on a monitor lock (owner tid: 1234)').
-- * 'vsync': Waiting for a scheduled vsync callback, passing from the start of
--   'Choreographer#scheduleVsyncLocked' to the end of the next 'Choreographer#onVsync *' slice on
--   the same thread.
--   * '<vsync_id>': The vsync ID extracted from 'Choreographer#onVsync <vsync_id>'.
-- * 'binder transaction': Synchronous binder call from the client thread (ready_utid) at the start
--   of 'binder transaction' to the server thread (utid) at the start of 'binder reply'.
--   * 'AIDL::*': Name of the parent slice of 'binder transaction' if it starts with 'AIDL::'.
--   * '': Empty if there is no 'AIDL::*' parent slice.
-- * 'binder reply': Synchronous binder reply from the server thread (ready_utid) at the end of
--   'binder reply' back to the client thread (utid) at the end of 'binder transaction'.
--   * 'AIDL::*': Name of the parent slice of the corresponding 'binder transaction' if it starts
--     with 'AIDL::'.
--   * '': Empty if there is no 'AIDL::*' parent slice.
-- * 'binder transaction async': Asynchronous (one-way) binder call from the sender thread
--   (ready_utid) at 'binder transaction async' to the receiver thread (utid) at 'binder async rcv'.
--   * 'AIDL::*': Name of the parent slice of 'binder transaction async' if it starts with 'AIDL::'.
--   * '': Empty if there is no 'AIDL::*' parent slice.
-- * 'input channel': Input event sent over an InputChannel from the sender thread (ready_utid) at
--   'sendMessage(inputChannel=...)' to the receiver thread (utid) at
--   'receiveMessage(inputChannel=...)'.
--   * '<message_id>': The channel name, sequence number, and message type extracted from the slice
--     name.
CREATE PERFETTO FUNCTION android_critical_path(
  -- Start timestamp of the span.
  ts TIMESTAMP,
  -- Duration of the span.
  dur DURATION,
  -- Utid of the thread at the end of the span.
  end_utid JOINID(thread.id)
)
RETURNS TABLE(
  -- Ready timestamp, same as the previous thread's ts + dur.
  ready_ts TIMESTAMP,
  -- Start timestamp of the thread after ready.
  ts TIMESTAMP,
  -- Thread run duration until the next ready.
  dur DURATION,
  -- Utid of the running thread.
  utid JOINID(thread.id),
  -- Utid of the thread that readied this thread.
  ready_utid JOINID(thread.id),
  -- Type of event that readied this thread (see function docs).
  ready_type STRING,
  -- Additional info for ready_type (see function docs).
  ready_info STRING,
  -- Name of the running thread.
  thread_name STRING,
  -- Name of the process of the running thread.
  process_name STRING
)
AS
WITH
  -- Synthetic root node at `$ts + $dur` with `idle_dur = $dur` and `dur = 0`.
  -- Its initial walk window is `[$ts, $ts + $dur)`, which it immediately
  -- delegates to `end_node_id` (the latest node on `$end_utid` at `$ts + $dur`).
  synthetic_root AS (
    SELECT
      (SELECT coalesce(max(id), 0) + 1 FROM _android_wakeup_graph) AS root_node_id,
      (
        SELECT max(id)
        FROM _android_wakeup_graph
        WHERE
          utid = $end_utid
          AND exec_ts <= $ts + $dur
      ) AS end_node_id
    WHERE
      $dur > 0
  ),
  graph_nodes AS (
    SELECT id, utid, ts, dur, idle_dur, waker_id, prev_id
    FROM _android_wakeup_graph
    WHERE
      ts <= $ts + $dur
    UNION ALL
    SELECT
      root_node_id AS id,
      $end_utid AS utid,
      $ts + $dur AS ts,
      0 AS dur,
      $dur AS idle_dur,
      end_node_id AS waker_id,
      NULL AS prev_id
    FROM synthetic_root
    WHERE
      end_node_id IS NOT NULL
  ),
  walked AS (
    SELECT *
    FROM _critical_path_walk_by_roots!(
      (SELECT root_node_id FROM synthetic_root WHERE end_node_id IS NOT NULL),
      graph_nodes
    )
  )
SELECT
  CASE WHEN n.ts <= $ts OR n.ts < w.ts THEN NULL ELSE n.ts END AS ready_ts,
  max(w.ts, n.exec_ts) AS ts,
  (w.ts + w.dur) - max(w.ts, n.exec_ts) AS dur,
  n.utid,
  n.ready_utid,
  n.ready_type,
  n.ready_info,
  t.name AS thread_name,
  proc.name AS process_name
FROM walked AS w
JOIN _android_wakeup_graph AS n USING (id)
JOIN thread AS t USING (utid)
JOIN process AS proc USING (upid)
ORDER BY
  w.ts ASC;

-- Computes the critical path of a time span [ts, ts + dur] ending on `end_utid`
-- (see `android_critical_path`), annotated with the time each step spent in
-- each scheduler `thread_state`.
CREATE PERFETTO FUNCTION android_critical_path_thread_state(
  -- Start timestamp of the span.
  ts TIMESTAMP,
  -- Duration of the span.
  dur DURATION,
  -- Utid of the thread at the end of the span.
  end_utid JOINID(thread.id)
)
RETURNS TABLE(
  -- Ready timestamp, same as the previous thread's ts + dur.
  ready_ts TIMESTAMP,
  -- Start timestamp of the thread after ready.
  ts TIMESTAMP,
  -- Thread run duration until the next ready.
  dur DURATION,
  -- Utid of the running thread.
  utid JOINID(thread.id),
  -- Utid of the thread that readied this thread.
  ready_utid JOINID(thread.id),
  -- Type of event that readied this thread (see `android_critical_path` docs).
  ready_type STRING,
  -- Additional info for ready_type (see `android_critical_path` docs).
  ready_info STRING,
  -- Name of the running thread.
  thread_name STRING,
  -- Name of the process of the running thread.
  process_name STRING,
  -- Time spent in 'Running' state.
  running_dur DURATION,
  -- Time spent in 'R' or 'R+' (runnable / preempted) states.
  runnable_dur DURATION,
  -- Time spent in 'S' (interruptible sleep) state.
  sleeping_dur DURATION,
  -- Time spent in 'D' (uninterruptible sleep) state.
  uninterruptible_sleep_dur DURATION
)
AS
WITH
  path_with_step_id AS (
    SELECT row_number() OVER (ORDER BY ts ASC) AS id, *
    FROM android_critical_path($ts, $dur, $end_utid)
  ),
  positive_hops AS (
    SELECT id, ts, dur, utid FROM path_with_step_id WHERE dur > 0
  ),
  valid_thread_states AS (
    SELECT
      id,
      ts,
      CASE WHEN dur = -1 THEN ($ts + $dur) - ts ELSE dur END AS dur,
      utid,
      state
    FROM thread_state
    WHERE
      ts < $ts + $dur
      AND (dur = -1 OR ts + dur > $ts)
  ),
  state_intersections AS (
    SELECT ii.id_0 AS step_id, ii.dur AS overlap_dur, s.state
    FROM _interval_intersect!((positive_hops, valid_thread_states), (utid)) AS ii
    JOIN valid_thread_states AS s
      ON s.id = ii.id_1
  ),
  aggregated_states AS (
    SELECT
      step_id AS id,
      sum(CASE WHEN state = 'Running' THEN overlap_dur ELSE 0 END) AS running_dur,
      sum(CASE WHEN state IN ('R', 'R+') THEN overlap_dur ELSE 0 END) AS runnable_dur,
      sum(CASE WHEN state = 'S' THEN overlap_dur ELSE 0 END) AS sleeping_dur,
      sum(CASE WHEN state = 'D' THEN overlap_dur ELSE 0 END) AS uninterruptible_sleep_dur
    FROM state_intersections
    GROUP BY
      step_id
  )
SELECT
  p.ready_ts,
  p.ts,
  p.dur,
  p.utid,
  p.ready_utid,
  p.ready_type,
  p.ready_info,
  p.thread_name,
  p.process_name,
  coalesce(a.running_dur, 0) AS running_dur,
  coalesce(a.runnable_dur, 0) AS runnable_dur,
  coalesce(a.sleeping_dur, 0) AS sleeping_dur,
  coalesce(a.uninterruptible_sleep_dur, 0) AS uninterruptible_sleep_dur
FROM path_with_step_id AS p
LEFT JOIN aggregated_states AS a USING (id)
ORDER BY
  p.ts ASC;

-- Formats the critical path of a time span [ts, ts + dur] ending on `utid`
-- as intervals suitable for a Perfetto UI debug track.
CREATE PERFETTO FUNCTION android_critical_path_debug_track(
  -- Start timestamp of the span.
  ts TIMESTAMP,
  -- Duration of the span.
  dur DURATION,
  -- Utid of the thread at the end of the span.
  utid JOINID(thread.id)
)
RETURNS TABLE(
  -- Start timestamp of the debug track slice.
  ts TIMESTAMP,
  -- Duration of the debug track slice.
  dur DURATION,
  -- Display name of the debug track slice.
  name STRING,
  -- Color key for the debug track slice.
  color STRING,
  -- Time spent in 'Running' state in milliseconds.
  running_dur_ms DOUBLE,
  -- Time spent in 'R' or 'R+' states in milliseconds.
  runnable_dur_ms DOUBLE,
  -- Time spent in 'S' state in milliseconds.
  sleeping_dur_ms DOUBLE,
  -- Time spent in 'D' state in milliseconds.
  uninterruptible_sleep_dur_ms DOUBLE
)
AS
WITH
  path AS (SELECT * FROM android_critical_path_thread_state($ts, $dur, $utid))
SELECT
  ts,
  dur,
  'run: ' || process_name || ' ' || thread_name AS name,
  process_name AS color,
  CAST(path.running_dur AS DOUBLE) / 1000000.0 AS running_dur_ms,
  CAST(path.runnable_dur AS DOUBLE) / 1000000.0 AS runnable_dur_ms,
  CAST(path.sleeping_dur AS DOUBLE) / 1000000.0 AS sleeping_dur_ms,
  CAST(path.uninterruptible_sleep_dur AS DOUBLE) / 1000000.0 AS uninterruptible_sleep_dur_ms
FROM path
WHERE
  dur > 0
UNION ALL
SELECT
  ready_ts AS ts,
  ts - ready_ts AS dur,
  ready_type || ' ' || ready_info AS name,
  ready_type AS color,
  NULL AS running_dur_ms,
  NULL AS runnable_dur_ms,
  NULL AS sleeping_dur_ms,
  NULL AS uninterruptible_sleep_dur_ms
FROM path
WHERE
  ready_ts IS NOT NULL;
