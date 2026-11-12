package com.agent.use.common.api

import android.content.Context
import android.os.Bundle
import android.os.IBinder
import com.agent.use.common.DisplayConfig
import com.agent.use.common.IAgentShell
import com.agent.use.common.network.INetworkCapture
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Proxy

class AAUManagerTest {

    private fun createMockShell(): IAgentShell {
        val mockBinder = Proxy.newProxyInstance(
            IBinder::class.java.classLoader,
            arrayOf(IBinder::class.java)
        ) { proxy, method, args ->
            when (method.name) {
                "equals" -> args?.getOrNull(0) === proxy
                "hashCode" -> System.identityHashCode(proxy)
                "toString" -> "MockBinder"
                "linkToDeath" -> Unit
                "unlinkToDeath" -> true
                else -> if (method.returnType == java.lang.Boolean.TYPE) true else null
            }
        } as IBinder

        return Proxy.newProxyInstance(
            IAgentShell::class.java.classLoader,
            arrayOf(IAgentShell::class.java)
        ) { proxy, method, args ->
            when (method.name) {
                "equals" -> args?.getOrNull(0) === proxy
                "hashCode" -> System.identityHashCode(proxy)
                "toString" -> "MockShell"
                "asBinder" -> mockBinder
                "runCommand" -> Bundle().apply {
                    putInt("exitCode", 0)
                    putString("output", "uid=2000(shell)")
                }
                "wakeDevice" -> true
                "dismissDeviceKeyguard" -> true
                "releaseAll" -> Unit
                else -> if (method.returnType == java.lang.Boolean.TYPE) true else null
            }
        } as IAgentShell
    }

    private fun createMockContext(): Context {
        return object : android.content.ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getSystemService(name: String): Any? = null
        }
    }

    @Test
    fun testAAUManagerCreationAndExecution() {
        val shell = createMockShell()
        val context = createMockContext()

        val manager: AAUManager = AAUManager.fromInterface(context, shell)
        assertNotNull(manager)
        assertEquals(shell, manager.shell)

        val cmdResult = manager.executeCommand("id")
        assertEquals(0, cmdResult.exitCode)
        assertNotNull(cmdResult.output)

        val wakeSuccess = manager.wakeAndDismissKeyguard()
        assertTrue(wakeSuccess)

        manager.close()
    }

    @Test
    @Suppress("DEPRECATION")
    fun testBackwardsCompatibleTypealias() {
        val shell = createMockShell()
        val context = createMockContext()

        // Test that legacy AgentDisplayManager reference compiles and works identically
        val legacyManager: AgentDisplayManager = AgentDisplayManager.fromInterface(context, shell)
        assertNotNull(legacyManager)
        assertTrue(legacyManager is AAUManager)
        legacyManager.close()
    }
}
