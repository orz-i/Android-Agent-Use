package com.agent.use.common.shell

import android.annotation.SuppressLint
import android.os.Binder
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Parcel
import android.os.RemoteException
import android.os.SystemClock
import android.util.Log
import com.agent.use.common.CustodyArrival
import com.agent.use.common.IAgentCustodyListener
import com.agent.use.common.LaunchOrigin
import java.util.Collections
import java.util.IdentityHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 纯状态机：维护每块托管虚拟屏的 `managed(D)` UID 集合（当前在屏 + 30s 内离开），
 * 并对任务帧快照进行差分以识别主屏到达、跨屏迁移、同任务页切换、托管屏新任务到达与任务消失。
 */
class CustodyTracker(
    private val leaveRetentionMs: Long = LEAVE_RETENTION_MS,
) {
    /** 一条任务栈快照行，对应 `ActivityTaskManager.getTasks` 的单条任务信息。 */
    data class TaskRow(
        val taskId: Int,
        val displayId: Int,
        val packageName: String?,
        val userId: Int,
        val topActivity: String?,
        val standard: Boolean = true,
        val uids: Set<Int> = emptySet(),
        val primaryUid: Int = LaunchOrigin.UNKNOWN_UID,
    ) {
        fun allUids(): Set<Int> {
            if (primaryUid < 0) return uids.filterTo(LinkedHashSet()) { it >= 0 }
            if (uids.isEmpty()) return setOf(primaryUid)
            val combined = LinkedHashSet<Int>(uids.size + 1)
            combined.add(primaryUid)
            uids.forEach { if (it >= 0) combined.add(it) }
            return combined
        }
    }

    /** 尚未附带 LaunchOrigin 的任务到达事件。 */
    data class PendingArrival(
        val taskId: Int,
        val packageName: String,
        val userId: Int,
        val uid: Int,
        val activity: String?,
        val displayId: Int,
        val fromDisplayId: Int,
        val newTask: Boolean,
        val sameTask: Boolean,
        val standard: Boolean,
        val at: Long,
    )

    /** 消失的任务事件。 */
    data class VanishedTask(
        val taskId: Int,
        val lastDisplayId: Int,
        val at: Long,
    )

    /** 单次任务快照差分产出。 */
    data class StepResult(
        val arrivals: List<PendingArrival>,
        val vanished: List<VanishedTask>,
    )

    private val managedDisplays = LinkedHashSet<Int>()
    private val currentUids = HashMap<Int, MutableSet<Int>>()
    private val leftUids = HashMap<Int, MutableMap<Int, Long>>()

    private var hasBaseline = false
    private val prevTasks = LinkedHashMap<Int, TaskRow>()
    private val prevTopByDisplay = HashMap<Int, TaskRow>()

    val isActive: Boolean get() = managedDisplays.isNotEmpty()

    fun managedDisplayIds(): Set<Int> = managedDisplays.toSet()

    /**
     * 注册托管屏 [displayId] 并以 [snapshot] 建立或补充基准；
     * 对首个托管屏建立全量基准（不派发历史事件），对后续新增托管屏仅补充该屏基准，避免丢掉主屏在途差分。
     */
    fun startDisplay(displayId: Int, snapshot: List<TaskRow>, now: Long) {
        managedDisplays.add(displayId)
        val onDisplay = snapshot.filter { it.displayId == displayId }
        val uids = currentUids.getOrPut(displayId) { LinkedHashSet() }
        uids.clear()
        onDisplay.forEach { row ->
            uids.addAll(row.allUids())
        }
        val leftMap = leftUids[displayId]
        if (leftMap != null) {
            uids.forEach { leftMap.remove(it) }
        }

        if (!hasBaseline) {
            hasBaseline = true
            prevTasks.clear()
            prevTopByDisplay.clear()
            snapshot.forEach { row ->
                prevTasks.putIfAbsent(row.taskId, row)
                prevTopByDisplay.putIfAbsent(row.displayId, row)
            }
        } else {
            onDisplay.firstOrNull()?.let { prevTopByDisplay[displayId] = it }
            onDisplay.forEach { row -> prevTasks.putIfAbsent(row.taskId, row) }
        }
    }

    /** 停止托管 [displayId]；最后一个托管屏移除时清空全部基线状态。 */
    fun stopDisplay(displayId: Int) {
        managedDisplays.remove(displayId)
        currentUids.remove(displayId)
        leftUids.remove(displayId)
        prevTopByDisplay.remove(displayId)
        if (managedDisplays.isEmpty()) {
            clearBaseline()
        }
    }

    /** 清空全部托管状态。 */
    fun stopAll() {
        managedDisplays.clear()
        currentUids.clear()
        leftUids.clear()
        clearBaseline()
    }

    private fun clearBaseline() {
        hasBaseline = false
        prevTasks.clear()
        prevTopByDisplay.clear()
    }

    /** 返回时刻 [now] 时托管屏 [displayId] 归属的完整 UID 集合（当前在屏 + 30s 内离开）。 */
    fun managedUids(displayId: Int, now: Long): Set<Int> {
        if (displayId !in managedDisplays) return emptySet()
        pruneExpired(now)
        val cur = currentUids[displayId].orEmpty()
        val recent = leftUids[displayId]?.keys.orEmpty()
        if (recent.isEmpty()) return cur.toSet()
        return LinkedHashSet<Int>(cur.size + recent.size).apply {
            addAll(cur)
            addAll(recent)
        }
    }

    /**
     * 查询 [uid] 在时刻 [now] 所属的托管屏 ID；不在任何 `managed(D)` 中返回 `-1`。
     * 优先匹配当前仍在该屏运行的 UID，其次匹配最近离开的托管屏。
     */
    fun managedDisplayForUid(uid: Int, now: Long): Int {
        if (uid < 0 || managedDisplays.isEmpty()) return LaunchOrigin.NO_MANAGED_DISPLAY
        pruneExpired(now)
        for (d in managedDisplays) {
            if (currentUids[d]?.contains(uid) == true) return d
        }
        var bestDisplay = LaunchOrigin.NO_MANAGED_DISPLAY
        var latestLeftAt = Long.MIN_VALUE
        for (d in managedDisplays) {
            val leftAt = leftUids[d]?.get(uid) ?: continue
            if (leftAt > latestLeftAt) {
                latestLeftAt = leftAt
                bestDisplay = d
            }
        }
        return bestDisplay
    }

    /** 对当前任务栈快照 [snapshot] 执行帧差分并更新 `managed(D)` 与基线。 */
    fun step(snapshot: List<TaskRow>, now: Long): StepResult {
        if (managedDisplays.isEmpty() || !hasBaseline) {
            return StepResult(emptyList(), emptyList())
        }
        pruneExpired(now)
        updateManagedUids(snapshot, now)

        val currentById = LinkedHashMap<Int, TaskRow>(snapshot.size)
        val currentTopByDisplay = HashMap<Int, TaskRow>()
        for (row in snapshot) {
            currentById.putIfAbsent(row.taskId, row)
            currentTopByDisplay.putIfAbsent(row.displayId, row)
        }

        val vanished = ArrayList<VanishedTask>()
        for ((taskId, prev) in prevTasks) {
            if (taskId !in currentById && (prev.displayId == MAIN_DISPLAY || prev.displayId in managedDisplays)) {
                vanished += VanishedTask(taskId = taskId, lastDisplayId = prev.displayId, at = now)
            }
        }

        val arrivals = ArrayList<PendingArrival>()
        val emitted = HashSet<Int>()

        // 1. 主屏 (Display 0) 到达：新任务到达 / 从它屏切到主屏顶部 / 主屏顶部 topActivity 变化
        val newOnMain = snapshot.filter { it.displayId == MAIN_DISPLAY && it.taskId !in prevTasks }
        for (row in newOnMain.asReversed()) {
            emitted += row.taskId
            arrivals += row.toPendingArrival(
                fromDisplayId = CustodyArrival.FROM_NEW,
                newTask = true,
                sameTask = false,
                at = now,
            )
        }

        val mainTop = currentTopByDisplay[MAIN_DISPLAY]
        val prevMainTop = prevTopByDisplay[MAIN_DISPLAY]
        if (mainTop != null && mainTop.taskId !in emitted) {
            if (mainTop.taskId != prevMainTop?.taskId) {
                val prev = prevTasks[mainTop.taskId]
                emitted += mainTop.taskId
                arrivals += mainTop.toPendingArrival(
                    fromDisplayId = prev?.displayId ?: CustodyArrival.FROM_NEW,
                    newTask = prev == null,
                    sameTask = false,
                    at = now,
                )
            } else if (mainTop.topActivity != prevMainTop.topActivity) {
                emitted += mainTop.taskId
                arrivals += mainTop.toPendingArrival(
                    fromDisplayId = MAIN_DISPLAY,
                    newTask = false,
                    sameTask = true,
                    at = now,
                )
            }
        }

        // 2. 托管虚拟屏 D 上到达：新任务到达 / 从它屏迁入顶部
        for (d in managedDisplays) {
            val newOnManaged = snapshot.filter { it.displayId == d && it.taskId !in prevTasks }
            for (row in newOnManaged.asReversed()) {
                if (emitted.add(row.taskId)) {
                    arrivals += row.toPendingArrival(
                        fromDisplayId = CustodyArrival.FROM_NEW,
                        newTask = true,
                        sameTask = false,
                        at = now,
                    )
                }
            }
            val dTop = currentTopByDisplay[d]
            val prevDTop = prevTopByDisplay[d]
            if (dTop != null && dTop.taskId !in emitted && dTop.taskId != prevDTop?.taskId) {
                val prev = prevTasks[dTop.taskId]
                if (prev != null && prev.displayId != d) {
                    emitted += dTop.taskId
                    arrivals += dTop.toPendingArrival(
                        fromDisplayId = prev.displayId,
                        newTask = false,
                        sameTask = false,
                        at = now,
                    )
                }
            }
        }

        prevTasks.clear()
        prevTasks.putAll(currentById)
        prevTopByDisplay.clear()
        prevTopByDisplay.putAll(currentTopByDisplay)

        return StepResult(arrivals = arrivals, vanished = vanished)
    }

    private fun updateManagedUids(snapshot: List<TaskRow>, now: Long) {
        val byDisplay = HashMap<Int, MutableSet<Int>>()
        for (row in snapshot) {
            if (row.displayId !in managedDisplays) continue
            val set = byDisplay.getOrPut(row.displayId) { LinkedHashSet() }
            set.addAll(row.allUids())
        }
        for (d in managedDisplays) {
            val newSet = byDisplay[d] ?: LinkedHashSet()
            val oldSet = currentUids[d].orEmpty()
            for (u in oldSet) {
                if (u !in newSet) {
                    leftUids.getOrPut(d) { HashMap() }[u] = now
                }
            }
            val leftMap = leftUids[d]
            if (leftMap != null) {
                newSet.forEach { leftMap.remove(it) }
            }
            currentUids[d] = newSet
        }
    }

    private fun pruneExpired(now: Long) {
        val it = leftUids.values.iterator()
        while (it.hasNext()) {
            val map = it.next()
            val entryIt = map.entries.iterator()
            while (entryIt.hasNext()) {
                val entry = entryIt.next()
                if (now - entry.value > leaveRetentionMs) {
                    entryIt.remove()
                }
            }
            if (map.isEmpty()) it.remove()
        }
    }

    private fun TaskRow.toPendingArrival(
        fromDisplayId: Int,
        newTask: Boolean,
        sameTask: Boolean,
        at: Long,
    ): PendingArrival = PendingArrival(
        taskId = taskId,
        packageName = packageName.orEmpty(),
        userId = userId,
        uid = primaryUid,
        activity = topActivity,
        displayId = displayId,
        fromDisplayId = fromDisplayId,
        newTask = newTask,
        sameTask = sameTask,
        standard = standard,
        at = at,
    )

    companion object {
        const val MAIN_DISPLAY = CustodyArrival.MAIN_DISPLAY
        const val LEAVE_RETENTION_MS = 30_000L
    }
}

/**
 * 常驻虚拟屏任务托管引擎（事件驱动实时托管，无观察时间窗限制）。
 *
 * - 只要仍有任意虚拟屏在托管，即通过 `ITaskStackListener`（失败时自动降级轮询）维持常驻监听，并做 30ms 合并扫描；
 * - 所有托管屏停止或客户端断连（`linkToDeath`）后自动注销底层监听；
 * - 主屏到达时调用 [resolveOrigin] 获取真实启动来源并与 `managed(D)` 归属信息一起经 [IAgentCustodyListener] 派发。
 */
@SuppressLint("PrivateApi")
class CustodyEngine(
    private val taskManager: () -> Any,
    private val tasks: () -> List<CustodyTracker.TaskRow>,
    private val resolveOrigin: (taskId: Int, packageName: String?) -> LaunchOrigin,
    private val canManageDisplay: (Int) -> Boolean = { it > 0 },
    private val nowMs: () -> Long = { SystemClock.uptimeMillis() },
    private val tag: String = DEFAULT_TAG,
    private val stackListenerStubFactory: (IBinder) -> Any? = ::defaultTaskStackListenerStub,
) {
    private class BinderRecord(
        val binder: IBinder,
        val displays: MutableSet<Int>,
        val recipient: IBinder.DeathRecipient,
    )

    private val lock = Any()
    private val tracker = CustodyTracker()
    private val listeners = LinkedHashMap<Int, IAgentCustodyListener>()
    private val binderRecords = IdentityHashMap<IBinder, BinderRecord>()

    private val thread = HandlerThread("agent-custody").apply { start() }
    private val handler = Handler(thread.looper)

    @Volatile
    private var closed = false

    @Volatile
    private var stackListenerRegistered = false
    private val polling = AtomicBoolean(false)
    private val signal = StackSignal()

    private val coalescedScan = CoalescedScan(
        schedule = { handler.postDelayed(it, COALESCE_MS) },
        cancel = { handler.removeCallbacks(it) },
        scan = { scanAndDispatch() },
    )

    private val pollRunnable = object : Runnable {
        override fun run() {
            if (closed || !synchronized(lock) { tracker.isActive }) {
                polling.set(false)
                return
            }
            scanAndDispatch()
            if (!closed && synchronized(lock) { tracker.isActive } && !stackListenerRegistered) {
                handler.postDelayed(this, POLL_MS)
            } else {
                polling.set(false)
            }
        }
    }

    /**
     * 为托管虚拟屏 [displayId] 开启常驻托管并绑定 [listener]。
     * 支持多托管屏并存及同一客户端 Binder 复用；若 [listener] 所属进程已死亡则返回 `false`。
     */
    fun startCustody(displayId: Int, listener: IAgentCustodyListener?): Boolean {
        if (closed || listener == null || !canManageDisplay(displayId)) return false
        val snapshot = runCatching { tasks() }.getOrElse {
            Log.w(tag, "startCustody($displayId): cannot inspect tasks", it)
            return false
        }
        val now = nowMs()
        val binder = runCatching { listener.asBinder() }.getOrNull()
        val needActivateListener: Boolean
        var hasMultiple = false

        synchronized(lock) {
            if (closed) return false
            val previous = listeners[displayId]
            if (previous != null) {
                val prevBinder = runCatching { previous.asBinder() }.getOrNull()
                if (prevBinder != null && prevBinder !== binder) {
                    detachBinderDisplayLocked(prevBinder, displayId)
                }
            }

            if (binder != null && !attachBinderDisplayLocked(binder, displayId)) {
                return false
            }

            val wasActive = tracker.isActive
            listeners[displayId] = listener
            tracker.startDisplay(displayId, snapshot, now)
            needActivateListener = !wasActive && tracker.isActive
            hasMultiple = wasActive
        }

        if (needActivateListener) {
            ensureListening()
        } else if (hasMultiple) {
            coalescedScan.request()
        }
        return true
    }

    /** 停止 [displayId] 的托管；若已无任何托管屏则自动注销底层任务栈监听。 */
    fun stopCustody(displayId: Int) {
        val shouldDeactivate: Boolean
        synchronized(lock) {
            val removed = listeners.remove(displayId) ?: return
            val binder = runCatching { removed.asBinder() }.getOrNull()
            if (binder != null) detachBinderDisplayLocked(binder, displayId)
            tracker.stopDisplay(displayId)
            shouldDeactivate = !tracker.isActive
        }
        if (shouldDeactivate) {
            stopListening()
        }
    }

    /** 停止全部虚拟屏托管并注销底层任务栈监听（引擎仍可后续复用）。 */
    fun stopAll() {
        synchronized(lock) {
            listeners.clear()
            binderRecords.values.forEach { record ->
                runCatching { record.binder.unlinkToDeath(record.recipient, 0) }
            }
            binderRecords.clear()
            tracker.stopAll()
        }
        stopListening()
    }

    /** 彻底释放后台线程与全部监听资源（仅用于进程销毁或单测清理）。 */
    fun close() {
        closed = true
        coalescedScan.close()
        stopAll()
        handler.removeCallbacksAndMessages(null)
        thread.quitSafely()
    }

    /** 查询任务 [taskId] 的启动来源及归属托管屏，打包为契约 Bundle。 */
    fun launchOrigin(taskId: Int, packageName: String? = null): Bundle {
        if (taskId < 0) return LaunchOrigin.unknown().toBundle(taskId, LaunchOrigin.NO_MANAGED_DISPLAY)
        val pkg = packageName ?: runCatching {
            tasks().firstOrNull { it.taskId == taskId }?.packageName
        }.getOrNull()
        val origin = runCatching { resolveOrigin(taskId, pkg) }.getOrElse {
            Log.w(tag, "resolveOrigin($taskId) failed", it)
            LaunchOrigin.unknown()
        }
        val managedDisplay = synchronized(lock) {
            tracker.managedDisplayForUid(origin.uid, nowMs())
        }
        return origin.toBundle(taskId = taskId, managedDisplayId = managedDisplay)
    }

    fun managedDisplayForUid(uid: Int): Int = synchronized(lock) {
        tracker.managedDisplayForUid(uid, nowMs())
    }

    fun managedUids(displayId: Int): Set<Int> = synchronized(lock) {
        tracker.managedUids(displayId, nowMs())
    }

    private fun attachBinderDisplayLocked(binder: IBinder, displayId: Int): Boolean {
        val existing = binderRecords[binder]
        if (existing != null) {
            existing.displays.add(displayId)
            return true
        }
        val recipient = IBinder.DeathRecipient { onBinderDied(binder) }
        return try {
            binder.linkToDeath(recipient, 0)
            binderRecords[binder] = BinderRecord(
                binder = binder,
                displays = LinkedHashSet<Int>().apply { add(displayId) },
                recipient = recipient,
            )
            true
        } catch (t: Throwable) {
            Log.w(tag, "linkToDeath failed for custody listener on display $displayId", t)
            false
        }
    }

    private fun detachBinderDisplayLocked(binder: IBinder, displayId: Int) {
        val record = binderRecords[binder] ?: return
        record.displays.remove(displayId)
        if (record.displays.isEmpty()) {
            binderRecords.remove(binder)
            runCatching { binder.unlinkToDeath(record.recipient, 0) }
        }
    }

    private fun onBinderDied(binder: IBinder) {
        val shouldDeactivate: Boolean
        synchronized(lock) {
            val record = binderRecords.remove(binder) ?: return
            for (d in record.displays) {
                val cur = listeners[d]
                val curBinder = cur?.let { runCatching { it.asBinder() }.getOrNull() }
                if (curBinder === binder) {
                    listeners.remove(d)
                    tracker.stopDisplay(d)
                }
            }
            shouldDeactivate = !tracker.isActive
        }
        Log.i(tag, "Custody client died; cleaned up registrations")
        if (shouldDeactivate) {
            stopListening()
        }
    }

    private fun ensureListening() {
        if (closed) return
        if (!stackListenerRegistered) {
            stackListenerRegistered = registerStackListener()
        }
        if (!stackListenerRegistered && polling.compareAndSet(false, true)) {
            handler.post(pollRunnable)
        }
    }

    private fun stopListening() {
        polling.set(false)
        handler.removeCallbacks(pollRunnable)
        if (stackListenerRegistered) {
            unregisterStackListener()
            stackListenerRegistered = false
        }
    }

    internal fun scanOnce() {
        scanAndDispatch()
    }

    private fun scanAndDispatch() {
        if (closed || !synchronized(lock) { tracker.isActive }) return
        val snapshot = try {
            tasks()
        } catch (t: Throwable) {
            Log.w(tag, "cannot list tasks during custody scan", t)
            return
        }
        val now = nowMs()
        val stepResult: CustodyTracker.StepResult
        synchronized(lock) {
            if (closed || !tracker.isActive) return
            stepResult = tracker.step(snapshot, now)
        }

        for (vanished in stepResult.vanished) {
            dispatchVanished(vanished)
        }
        for (pending in stepResult.arrivals) {
            dispatchArrival(pending)
        }
    }

    private fun dispatchVanished(vanished: CustodyTracker.VanishedTask) {
        val targets = synchronized(lock) {
            if (vanished.lastDisplayId == CustodyTracker.MAIN_DISPLAY) {
                uniqueListenersLocked()
            } else {
                listOfNotNull(listeners[vanished.lastDisplayId])
            }
        }
        for (listener in targets) {
            try {
                listener.onTaskVanished(vanished.taskId, vanished.lastDisplayId, vanished.at)
            } catch (e: RemoteException) {
                Log.w(tag, "onTaskVanished delivery failed", e)
                handleDeadListener(listener)
            }
        }
    }

    private fun dispatchArrival(pending: CustodyTracker.PendingArrival) {
        val origin: LaunchOrigin
        val managedDisplay: Int
        val targets: List<IAgentCustodyListener>

        if (pending.displayId == CustodyTracker.MAIN_DISPLAY) {
            origin = runCatching {
                resolveOrigin(pending.taskId, pending.packageName.ifEmpty { null })
            }.getOrElse {
                Log.w(tag, "resolveOrigin(${pending.taskId}) failed", it)
                LaunchOrigin.unknown()
            }
            synchronized(lock) {
                managedDisplay = tracker.managedDisplayForUid(origin.uid, pending.at)
                targets = uniqueListenersLocked()
            }
        } else {
            origin = LaunchOrigin.unknown()
            synchronized(lock) {
                managedDisplay = if (pending.displayId in tracker.managedDisplayIds()) {
                    pending.displayId
                } else {
                    LaunchOrigin.NO_MANAGED_DISPLAY
                }
                targets = listOfNotNull(listeners[pending.displayId])
            }
        }

        if (targets.isEmpty()) return
        val bundle = CustodyArrival(
            taskId = pending.taskId,
            packageName = pending.packageName,
            userId = pending.userId,
            activity = pending.activity,
            displayId = pending.displayId,
            fromDisplayId = pending.fromDisplayId,
            newTask = pending.newTask,
            sameTask = pending.sameTask,
            originUid = origin.uid,
            originPackage = origin.packageName,
            originConfidence = origin.confidence,
            managedDisplayId = managedDisplay,
            at = pending.at,
            standard = pending.standard,
            uid = pending.uid,
        ).toBundle()

        for (listener in targets) {
            try {
                listener.onTaskArrived(bundle)
            } catch (e: RemoteException) {
                Log.w(tag, "onTaskArrived delivery failed", e)
                handleDeadListener(listener)
            }
        }
    }

    private fun uniqueListenersLocked(): List<IAgentCustodyListener> {
        if (listeners.isEmpty()) return emptyList()
        val seenBinders = Collections.newSetFromMap(IdentityHashMap<IBinder, Boolean>())
        val unique = ArrayList<IAgentCustodyListener>(listeners.size)
        for (l in listeners.values) {
            val binder = runCatching { l.asBinder() }.getOrNull()
            if (binder == null || seenBinders.add(binder)) {
                unique += l
            }
        }
        return unique
    }

    private fun handleDeadListener(listener: IAgentCustodyListener) {
        val binder = runCatching { listener.asBinder() }.getOrNull() ?: return
        onBinderDied(binder)
    }

    private fun taskStackListenerInterface(): Any? = runCatching {
        stackListenerStubFactory(signal)
    }.getOrNull()

    private fun registerStackListener(): Boolean = try {
        val am = taskManager()
        val stub = taskStackListenerInterface() ?: return false
        am.javaClass.methods.first { it.name == "registerTaskStackListener" && it.parameterTypes.size == 1 }
            .invoke(am, stub)
        Log.i(tag, "custody task stack listener registered")
        true
    } catch (t: Throwable) {
        Log.w(tag, "custody task stack listener unavailable, falling back to polling", t)
        false
    }

    private fun unregisterStackListener() {
        runCatching {
            val am = taskManager()
            val stub = taskStackListenerInterface() ?: return
            am.javaClass.methods.first { it.name == "unregisterTaskStackListener" && it.parameterTypes.size == 1 }
                .invoke(am, stub)
            Log.i(tag, "custody task stack listener unregistered")
        }
    }

    private inner class StackSignal : Binder() {
        init {
            attachInterface(null, DESCRIPTOR)
        }

        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code in FIRST_CALL_TRANSACTION..LAST_CALL_TRANSACTION) {
                if (!closed && synchronized(lock) { tracker.isActive }) {
                    coalescedScan.request()
                }
                return true
            }
            return super.onTransact(code, data, reply, flags)
        }
    }

    companion object {
        private const val DEFAULT_TAG = "AgentCustody"
        private const val DESCRIPTOR = "android.app.ITaskStackListener"
        const val COALESCE_MS = 30L
        const val POLL_MS = 100L

        private fun defaultTaskStackListenerStub(binder: IBinder): Any? =
            Class.forName("android.app.ITaskStackListener\$Stub")
                .getMethod("asInterface", IBinder::class.java)
                .invoke(null, binder)
    }
}
