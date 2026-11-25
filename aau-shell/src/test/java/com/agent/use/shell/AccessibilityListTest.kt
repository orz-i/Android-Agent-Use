package com.agent.use.shell

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AccessibilityListTest {
    companion object {
        init { configureExampleBrand() }
    }

    private val host = PermissionCommands.accessibilityService("com.example.app")
    private val hostLong = "com.example.app/com.example.app.a11y.ExampleAccessibilityService"
    private val other = "com.example.reader/.ReaderService"
    private val other2 = "org.sample.keys/org.sample.keys.KeyService"

    @Test
    fun emptyOrUnsetValues() {
        listOf(null, "", "   ", "null", "null\n", ":", " : ").forEach { raw ->
            assertEquals("raw=$raw", emptyList<String>(), AccessibilityList.entries(raw))
            assertFalse(AccessibilityList.contains(raw, host))
            assertEquals(host, AccessibilityList.with(raw, host))
            assertEquals("", AccessibilityList.without(raw, host))
        }
    }

    @Test
    fun appendKeepsOtherServicesInOrder() {
        assertEquals("$other:$host", AccessibilityList.with(other, host))
        assertEquals("$other:$other2:$host", AccessibilityList.with("$other:$other2\n", host))
    }

    @Test
    fun alreadyPresentIsNotDuplicated() {
        assertEquals("$other:$host", AccessibilityList.with("$other:$host", host))
        // 系统里存的是完整类名写法,也算已经有了
        assertEquals("$hostLong:$other", AccessibilityList.with("$hostLong:$other", host))
        assertTrue(AccessibilityList.contains(hostLong, host))
    }

    @Test
    fun removeKeepsOthersAndHandlesBothSpellings() {
        assertEquals("$other:$other2", AccessibilityList.without("$other:$host:$other2", host))
        assertEquals(other, AccessibilityList.without("$hostLong:$other", host))
        assertEquals(other, AccessibilityList.without(other, host))
        assertEquals("", AccessibilityList.without(host, host))
    }

    @Test
    fun strayColonsAndSpacesAreCleanedUp() {
        assertEquals("$other:$other2:$host", AccessibilityList.with(":$other:: $other2 :", host))
        assertEquals("$other:$other2", AccessibilityList.without("$other::$host:$other2:", host))
    }

    @Test
    fun differentServiceOfSamePackageIsNotConfused() {
        val sibling = "com.example.app/.a11y.OtherService"
        assertFalse(AccessibilityList.contains(sibling, host))
        assertEquals(sibling, AccessibilityList.without("$sibling:$host", host))
    }
}
