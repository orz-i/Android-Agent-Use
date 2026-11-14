package com.agent.use.a11y

import com.agent.use.a11y.model.A11yNode
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class A11yNodeModelTest {

    @Test
    fun testA11yNodeTreeAndQuery() {
        val child1 = A11yNode(
            text = "确认",
            viewId = "com.example:id/btn_confirm",
            className = "android.widget.Button",
            isClickable = true
        )
        val child2 = A11yNode(
            contentDescription = "返回",
            viewId = "com.example:id/btn_back",
            className = "android.widget.ImageButton",
            isClickable = true
        )
        val child3 = A11yNode(
            hintText = "请输入搜索关键词",
            viewId = "com.example:id/a1",
            className = "android.widget.EditText",
            isEditable = true,
            isShowingHintText = true,
            isCheckable = true,
            isChecked = false
        )
        val root = A11yNode(
            className = "android.widget.FrameLayout",
            children = listOf(child1, child2, child3)
        )

        assertEquals("确认", child1.label)
        assertEquals("返回", child2.label)
        assertEquals("请输入搜索关键词", child3.label)

        assertEquals("Button", child1.role)
        assertEquals("ImageButton", child2.role)
        assertEquals("EditText", child3.role)

        assertEquals("btn_confirm", child1.readableResourceId)
        assertEquals("btn_back", child2.readableResourceId)
        assertNull(child3.readableResourceId)
        assertTrue(child3.canSetText)
        assertTrue(child3.isShowingHintText)

        val buttons = root.findNodes { it.isClickable }
        assertEquals(2, buttons.size)

        val confirmBtn = root.findNodes { it.text == "确认" }.firstOrNull()
        assertNotNull(confirmBtn)
        assertEquals("com.example:id/btn_confirm", confirmBtn?.viewId)
    }

    @Test
    fun testReadableResourceIdFilteringAndMixHash() {
        assertEquals("cart_icon", DisplayWindowInspector.readableResourceId("com.example:id/cart_icon"))
        assertEquals("search_bar_1", DisplayWindowInspector.readableResourceId("search_bar_1"))
        assertNull(DisplayWindowInspector.readableResourceId("com.example:id/a1b"))
        assertNull(DisplayWindowInspector.readableResourceId("com.example:id/123456"))
        assertNull(DisplayWindowInspector.readableResourceId(null))

        val h1 = DisplayWindowInspector.mixHash(DisplayWindowInspector.FNV_OFFSET, "Button", "OK", "[0,0][100,50]")
        val h2 = DisplayWindowInspector.mixHash(DisplayWindowInspector.FNV_OFFSET, "Button", "Cancel", "[0,0][100,50]")
        assertNotEquals(h1, h2)
    }

    @Test
    fun testDisplayEventStreamSignalsAndNotifications() = runBlocking {
        val beforeGen = AgentAccessibilityService.windowGeneration()
        val afterGen = DisplayEventStream.incrementWindowGeneration()
        assertEquals(beforeGen + 1, afterGen)
        assertEquals(afterGen, AgentAccessibilityService.windowGeneration())
        assertEquals(afterGen, DisplayEventStream.windowGeneration())

        val windowChanged = async(start = CoroutineStart.UNDISPATCHED) {
            DisplayEventStream.windowChanges().first()
        }
        DisplayEventStream.emitWindowChanged()
        windowChanged.await()

        val notification = async(start = CoroutineStart.UNDISPATCHED) {
            DisplayEventStream.notificationEvents().first { it.packageName == "com.example.chat" }
        }
        DisplayEventStream.emitNotification("com.example.chat", "你好")
        val received = notification.await()
        assertEquals("com.example.chat", received.packageName)
        assertEquals("你好", received.text)
    }

    @Test
    fun testAgentAccessibilityServiceIsRunningReflectionContract() {
        assertFalse(AgentAccessibilityService.isConnected)
        assertFalse(AgentAccessibilityService.isRunning())

        val runningViaReflection = AgentAccessibilityService::class.java
            .getMethod("isRunning")
            .invoke(null) as Boolean
        assertFalse(runningViaReflection)
    }
}
