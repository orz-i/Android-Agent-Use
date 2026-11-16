package com.agent.use.common.shell

import android.os.IBinder
import com.agent.use.common.CustodyArrival
import com.agent.use.common.IAgentCustodyListener
import com.agent.use.common.LaunchOrigin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Proxy
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class CustodyEngineTest {

    private fun row(
        taskId: Int,
        displayId: Int,
        pkg: String = "com.example.app",
        userId: Int = 0,
        activity: String = "$pkg/.MainActivity",
        primaryUid: Int = userId * 100_000 + 10_000 + (pkg.hashCode() and 0x0FFF),
        uids: Set<Int> = setOf(primaryUid),
        standard: Boolean = true,
    ) = CustodyTracker.TaskRow(
        taskId = taskId,
        displayId = displayId,
        packageName = pkg,
        userId = userId,
        topActivity = activity,
        standard = standard,
        uids = uids,
        primaryUid = primaryUid,
    )

    @Test
    fun mainScreenArrivalsCoverNewCrossDisplaySameTaskAndReorder() {
        val tracker = CustodyTracker()
        tracker.startDisplay(
            displayId = 5,
            snapshot = listOf(
                row(1, 0, "com.home", activity = "com.home/.Home", primaryUid = 10001),
                row(2, 0, "com.notes", activity = "com.notes/.List", primaryUid = 10002),
                row(10, 5, "com.agent.app", activity = "com.agent.app/.Home", primaryUid = 10100),
            ),
            now = 1_000L,
        )

        // 1. 新任务到达主屏（含父/子连续创建顺序）
        val s1 = tracker.step(
            snapshot = listOf(
                row(21, 0, "com.pay", activity = "com.pay/.Confirm", primaryUid = 10201),
                row(20, 0, "com.pay", activity = "com.pay/.Bridge", primaryUid = 10201),
                row(1, 0, "com.home", activity = "com.home/.Home", primaryUid = 10001),
                row(2, 0, "com.notes", activity = "com.notes/.List", primaryUid = 10002),
                row(10, 5, "com.agent.app", activity = "com.agent.app/.Home", primaryUid = 10100),
            ),
            now = 1_100L,
        )
        assertEquals(listOf(20, 21), s1.arrivals.map { it.taskId })
        assertTrue(s1.arrivals.all { it.newTask && !it.sameTask && it.fromDisplayId == CustodyArrival.FROM_NEW && it.displayId == 0 })

        // 2. 同任务顶层 Activity 变化 (sameTask = true)
        val s2 = tracker.step(
            snapshot = listOf(
                row(21, 0, "com.pay", activity = "com.pay/.Result", primaryUid = 10201),
                row(20, 0, "com.pay", activity = "com.pay/.Bridge", primaryUid = 10201),
                row(1, 0, "com.home", activity = "com.home/.Home", primaryUid = 10001),
                row(10, 5, "com.agent.app", activity = "com.agent.app/.Home", primaryUid = 10100),
            ),
            now = 1_200L,
        )
        assertEquals(1, s2.arrivals.size)
        assertEquals(21, s2.arrivals.single().taskId)
        assertTrue(s2.arrivals.single().sameTask)
        assertFalse(s2.arrivals.single().newTask)
        assertEquals(0, s2.arrivals.single().fromDisplayId)
        assertEquals(listOf(2), s2.vanished.map { it.taskId })

        // 3. 从托管屏 5 切到主屏顶部 (from = 5)
        val s3 = tracker.step(
            snapshot = listOf(
                row(10, 0, "com.agent.app", activity = "com.agent.app/.Home", primaryUid = 10100),
                row(21, 0, "com.pay", activity = "com.pay/.Result", primaryUid = 10201),
                row(1, 0, "com.home", activity = "com.home/.Home", primaryUid = 10001),
            ),
            now = 1_300L,
        )
        assertEquals(1, s3.arrivals.size)
        val moveArrival = s3.arrivals.single()
        assertEquals(10, moveArrival.taskId)
        assertEquals(0, moveArrival.displayId)
        assertEquals(5, moveArrival.fromDisplayId)
        assertFalse(moveArrival.newTask)
        assertFalse(moveArrival.sameTask)
        assertEquals(listOf(20), s3.vanished.map { it.taskId })
    }

    @Test
    fun managedDisplayArrivalsAndVanishingsTrackPerDisplayLifecycle() {
        val tracker = CustodyTracker()
        tracker.startDisplay(
            displayId = 5,
            snapshot = listOf(
                row(1, 0, "com.home", primaryUid = 10001),
                row(2, 99, "com.unmanaged", primaryUid = 10099),
            ),
            now = 1_000L,
        )

        // 新任务到达托管屏 5，同时非托管屏 99 上的任务消失不触发 vanished
        val s1 = tracker.step(
            snapshot = listOf(
                row(1, 0, "com.home", primaryUid = 10001),
                row(11, 5, "com.shop", primaryUid = 10111),
            ),
            now = 1_100L,
        )
        assertEquals(1, s1.arrivals.size)
        assertEquals(11, s1.arrivals.single().taskId)
        assertEquals(5, s1.arrivals.single().displayId)
        assertEquals(CustodyArrival.FROM_NEW, s1.arrivals.single().fromDisplayId)
        assertTrue(s1.arrivals.single().newTask)
        assertTrue(s1.vanished.isEmpty())

        // 托管屏 5 任务关闭 -> onTaskVanished(11, lastDisplayId=5)
        val s2 = tracker.step(
            snapshot = listOf(
                row(1, 0, "com.home", primaryUid = 10001),
            ),
            now = 1_200L,
        )
        assertEquals(1, s2.vanished.size)
        assertEquals(11, s2.vanished.single().taskId)
        assertEquals(5, s2.vanished.single().lastDisplayId)
    }

    @Test
    fun managedUidRetentionExpiresAfter30sAndDistinguishesUserProfiles() {
        val tracker = CustodyTracker(leaveRetentionMs = 30_000L)
        val mainWechatUid = 10100
        val cloneWechatUid = 999 * 100_000 + 10100
        val helperUid = 10200

        tracker.startDisplay(
            displayId = 5,
            snapshot = listOf(
                row(10, 5, "com.tencent.mm", userId = 0, primaryUid = mainWechatUid, uids = setOf(mainWechatUid, helperUid)),
                row(11, 6, "com.tencent.mm", userId = 999, primaryUid = cloneWechatUid),
            ),
            now = 10_000L,
        )
        tracker.startDisplay(
            displayId = 6,
            snapshot = listOf(
                row(10, 5, "com.tencent.mm", userId = 0, primaryUid = mainWechatUid, uids = setOf(mainWechatUid, helperUid)),
                row(11, 6, "com.tencent.mm", userId = 999, primaryUid = cloneWechatUid),
            ),
            now = 10_000L,
        )

        // 按完整 uid 隔离分身/工作资料，不混淆用户 0 与用户 999
        assertEquals(5, tracker.managedDisplayForUid(mainWechatUid, 10_000L))
        assertEquals(5, tracker.managedDisplayForUid(helperUid, 10_000L))
        assertEquals(6, tracker.managedDisplayForUid(cloneWechatUid, 10_000L))
        assertEquals(LaunchOrigin.NO_MANAGED_DISPLAY, tracker.managedDisplayForUid(10999, 10_000L))

        // mainWechatUid 离开屏幕 5；在 30_000ms 内仍保留在 managed(5)
        tracker.step(
            snapshot = listOf(
                row(10, 0, "com.tencent.mm", userId = 0, primaryUid = mainWechatUid),
                row(11, 6, "com.tencent.mm", userId = 999, primaryUid = cloneWechatUid),
            ),
            now = 15_000L,
        )
        assertTrue(mainWechatUid in tracker.managedUids(5, 44_999L))
        assertEquals(5, tracker.managedDisplayForUid(mainWechatUid, 45_000L))

        // 超过 30s 后回收
        assertFalse(mainWechatUid in tracker.managedUids(5, 45_001L))
        assertEquals(LaunchOrigin.NO_MANAGED_DISPLAY, tracker.managedDisplayForUid(mainWechatUid, 45_001L))
        // 仍在屏 6 的分身 UID 不受影响
        assertEquals(6, tracker.managedDisplayForUid(cloneWechatUid, 45_001L))
    }

    @Test
    fun custodyEngineManagesStackListenerAndMultiDisplayRouting() {
        val registerCount = AtomicInteger(0)
        val unregisterCount = AtomicInteger(0)
        val fakeTaskManager = FakeTaskManager(
            onRegister = { registerCount.incrementAndGet() },
            onUnregister = { unregisterCount.incrementAndGet() },
        )
        val snapshot = CopyOnWriteArrayList<CustodyTracker.TaskRow>(
            listOf(
                row(1, 0, "com.home", primaryUid = 10001),
                row(2, 5, "com.agent.a", primaryUid = 10200),
            ),
        )
        val now = AtomicLong(1_000L)

        val resolvedRequests = CopyOnWriteArrayList<Int>()
        val engine = CustodyEngine(
            taskManager = { fakeTaskManager },
            tasks = { snapshot.toList() },
            resolveOrigin = { taskId, _ ->
                resolvedRequests += taskId
                if (taskId == 30) LaunchOrigin(10200, "com.agent.a", LaunchOrigin.CONFIDENCE_HIGH)
                else LaunchOrigin.unknown()
            },
            nowMs = { now.get() },
            stackListenerStubFactory = { binder -> binder },
        )

        try {
            val eventsA = CopyOnWriteArrayList<String>()
            val deathRecipientsA = CopyOnWriteArrayList<IBinder.DeathRecipient>()
            val binderA = fakeBinder(deathRecipientsA)
            val listenerA = mockCustodyListener(binderA) { method, args ->
                eventsA += "$method:${args?.size}"
            }

            val eventsB = CopyOnWriteArrayList<String>()
            val deathRecipientsB = CopyOnWriteArrayList<IBinder.DeathRecipient>()
            val binderB = fakeBinder(deathRecipientsB)
            val listenerB = mockCustodyListener(binderB) { method, args ->
                eventsB += "$method:${args?.size}"
            }

            assertFalse(engine.startCustody(0, listenerA))
            assertFalse(engine.startCustody(5, null))

            assertTrue(engine.startCustody(5, listenerA))
            assertEquals(1, registerCount.get())
            assertEquals(0, unregisterCount.get())

            // 同一个 Binder 再托管屏 6 不重复注册底层监听，且主屏到达对其仅派发一次
            assertTrue(engine.startCustody(6, listenerA))
            assertEquals(1, registerCount.get())

            // 另一个独立客户端 Binder 托管屏 7
            assertTrue(engine.startCustody(7, listenerB))
            assertEquals(1, registerCount.get())

            // 1. 屏 7 新任务到达仅派发给 listenerB
            snapshot += row(20, 7, "com.agent.b", primaryUid = 10300)
            engine.scanOnce()
            assertEquals(0, eventsA.size)
            assertEquals(1, eventsB.size)

            // 2. 主屏新任务到达对每个唯一活跃 Binder 各派发一次并解析来源
            snapshot.add(0, row(30, 0, "com.target.pay", primaryUid = 10400))
            engine.scanOnce()
            assertEquals(listOf("onTaskArrived:1"), eventsA.toList())
            assertEquals(2, eventsB.size)
            assertTrue(30 in resolvedRequests)

            // 3. 停掉 5 和 6 后仍有 7，不注销底层监听
            engine.stopCustody(5)
            engine.stopCustody(6)
            assertEquals(0, unregisterCount.get())

            // 4. 模拟客户端 B 进程死亡 (linkToDeath 回调) -> 自动清理屏 7 并注销底层监听
            assertEquals(1, deathRecipientsB.size)
            deathRecipientsB.single().binderDied()
            assertEquals(1, unregisterCount.get())

            // 确认 Binder 去重时再次启动能重新注册
            assertTrue(engine.startCustody(5, listenerA))
            assertEquals(2, registerCount.get())

            val originBundle = engine.launchOrigin(30)
            assertNotNull(originBundle)
        } finally {
            engine.close()
        }
    }

    private fun fakeBinder(recipients: MutableList<IBinder.DeathRecipient>): IBinder {
        return Proxy.newProxyInstance(
            IBinder::class.java.classLoader,
            arrayOf(IBinder::class.java),
        ) { proxy, method, args ->
            when (method.name) {
                "equals" -> args?.getOrNull(0) === proxy
                "hashCode" -> System.identityHashCode(proxy)
                "linkToDeath" -> {
                    (args?.getOrNull(0) as? IBinder.DeathRecipient)?.let { recipients += it }
                    Unit
                }
                "unlinkToDeath" -> {
                    val target = args?.getOrNull(0) as? IBinder.DeathRecipient
                    if (target != null) recipients.remove(target) else true
                }
                else -> if (method.returnType == java.lang.Boolean.TYPE) true else null
            }
        } as IBinder
    }

    private fun mockCustodyListener(
        binder: IBinder,
        onEvent: (method: String, args: Array<out Any?>?) -> Unit,
    ): IAgentCustodyListener {
        return Proxy.newProxyInstance(
            IAgentCustodyListener::class.java.classLoader,
            arrayOf(IAgentCustodyListener::class.java),
        ) { _, method, args ->
            when (method.name) {
                "asBinder" -> binder
                "onTaskArrived", "onTaskVanished" -> {
                    onEvent(method.name, args)
                    Unit
                }
                else -> Unit
            }
        } as IAgentCustodyListener
    }

    class FakeTaskManager(
        private val onRegister: () -> Unit,
        private val onUnregister: () -> Unit,
    ) {
        @Suppress("UNUSED_PARAMETER")
        fun registerTaskStackListener(listener: Any?) {
            onRegister()
        }

        @Suppress("UNUSED_PARAMETER")
        fun unregisterTaskStackListener(listener: Any?) {
            onUnregister()
        }
    }
}
