package com.agent.display.a11y

import android.graphics.Rect
import com.agent.display.a11y.model.A11yNode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
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
        val root = A11yNode(
            className = "android.widget.FrameLayout",
            children = listOf(child1, child2)
        )

        assertEquals("确认", child1.label)
        assertEquals("返回", child2.label)

        val buttons = root.findNodes { it.isClickable }
        assertEquals(2, buttons.size)

        val confirmBtn = root.findNodes { it.text == "确认" }.firstOrNull()
        assertNotNull(confirmBtn)
        assertEquals("com.example:id/btn_confirm", confirmBtn?.viewId)
    }
}
