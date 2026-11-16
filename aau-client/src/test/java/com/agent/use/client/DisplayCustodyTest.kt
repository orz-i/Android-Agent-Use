package com.agent.use.client

import android.os.IBinder
import com.agent.use.common.IAgentCustodyListener
import com.agent.use.common.IAgentShell
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Proxy
import java.util.concurrent.CopyOnWriteArrayList

class DisplayCustodyTest {

    @Test
    fun delegatesCustodyAndForwardsVanishedCallbacks() {
        val calls = CopyOnWriteArrayList<String>()
        var registeredListener: IAgentCustodyListener? = null
        val binder = Proxy.newProxyInstance(
            IBinder::class.java.classLoader,
            arrayOf(IBinder::class.java),
        ) { proxy, method, args ->
            when (method.name) {
                "equals" -> args?.getOrNull(0) === proxy
                "hashCode" -> System.identityHashCode(proxy)
                else -> true
            }
        } as IBinder

        val shell = Proxy.newProxyInstance(
            IAgentShell::class.java.classLoader,
            arrayOf(IAgentShell::class.java),
        ) { proxy, method, args ->
            calls += method.name
            when (method.name) {
                "equals" -> args?.getOrNull(0) === proxy
                "hashCode" -> System.identityHashCode(proxy)
                "asBinder" -> binder
                "startCustody" -> {
                    registeredListener = args?.getOrNull(1) as? IAgentCustodyListener
                    true
                }
                "stopCustody" -> Unit
                "visibleOnMainScreen" -> true
                "moveTask" -> true
                "launchOrigin" -> null
                else -> if (method.returnType == java.lang.Boolean.TYPE) true else null
            }
        } as IAgentShell

        val custody = DisplayCustody(shell)
        val vanishedEvents = ArrayList<Triple<Int, Int, Long>>()
        val listener = object : DisplayCustody.Listener {
            override fun onTaskVanished(taskId: Int, lastDisplayId: Int, at: Long) {
                vanishedEvents += Triple(taskId, lastDisplayId, at)
            }
        }

        assertFalse(custody.startCustody(0, listener))
        assertTrue(custody.startCustody(9, listener))
        assertNotNull(registeredListener)

        registeredListener?.onTaskVanished(42, 0, 123456L)
        assertEquals(listOf(Triple(42, 0, 123456L)), vanishedEvents)

        assertTrue(custody.isPackageInUseOnMainScreen("com.example.app", 0))
        assertTrue(custody.moveTaskToDisplay(42, 9))
        assertFalse(custody.launchOrigin(42).isKnown)

        custody.close()
        assertTrue("stopCustody" in calls)
    }
}
