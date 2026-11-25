package com.agent.use.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AtlasModelsTest {
    @Test
    fun evictsScreensByLruAndHitsAndPrunesDanglingEdges() {
        val hotOld = AtlasScreen(
            sigId = "Main#hot",
            shortActivity = "Main",
            fingerprint = 1L,
            hits = 50,
            lastSeenMs = 100L,
        )
        val coldOld = AtlasScreen(
            sigId = "Temp#cold",
            shortActivity = "Temp",
            fingerprint = 2L,
            hits = 1,
            lastSeenMs = 10L,
        )
        val recentScreens = (1..MAX_ATLAS_SCREENS).map { i ->
            AtlasScreen(
                sigId = "Page#$i",
                shortActivity = "Page$i",
                fingerprint = i.toLong() + 10L,
                hits = 1,
                lastSeenMs = 1000L + i,
            )
        }
        val allScreens = listOf(coldOld, hotOld) + recentScreens
        val validEdge = AtlasEdge("Main#hot", "Page#$MAX_ATLAS_SCREENS", "phone_tap", ok = 3, lastOkMs = 2000L)
        val danglingEdge = AtlasEdge("Temp#cold", "Main#hot", "phone_tap", ok = 1, lastOkMs = 10L)

        val atlas = AppAtlas(
            packageName = "com.example.app",
            screens = allScreens,
            edges = listOf(validEdge, danglingEdge),
        ).compacted()

        assertEquals(MAX_ATLAS_SCREENS, atlas.screens.size)
        // 高频核心页与最近页保留，最冷单次页被淘汰
        assertNull(atlas.findScreen("Temp#cold"))
        assertTrue(atlas.findScreen("Main#hot") != null)
        assertTrue(atlas.findScreen("Page#$MAX_ATLAS_SCREENS") != null)
        // 指向被淘汰页面的悬空边被自动清理
        assertEquals(listOf(validEdge), atlas.edges)

        // 若全部都是低频（如全 hits=1，或很老的 hits=2），严格按 LRU 淘汰最老页面
        val ancientTwoHits = coldOld.copy(sigId = "Old#2hits", hits = 2, lastSeenMs = 10L)
        val pureLru = AppAtlas(
            packageName = "com.example.app",
            screens = listOf(ancientTwoHits) + recentScreens,
        ).compacted()
        assertEquals(MAX_ATLAS_SCREENS, pureLru.screens.size)
        assertNull(pureLru.findScreen("Old#2hits"))
    }

    @Test
    fun evictsExcessEdgesAndControlsByLruAndHits() {
        val s1 = AtlasScreen(
            sigId = "S1#1",
            fingerprint = 1L,
            controls = (1..(MAX_SCREEN_CONTROLS + 10)).map { i ->
                AtlasControl(
                    selector = Selector("button", "B$i", "id/$i", listOf(0, 0, 10, 10), 0),
                    used = if (i == 1) 100 else 1,
                    lastUsedMs = if (i == 1) 500L else 1000L + i,
                )
            },
        )
        val s2 = AtlasScreen(sigId = "S2#2", fingerprint = 2L)
        val edges = (1..(MAX_ATLAS_EDGES + 20)).map { i ->
            AtlasEdge(
                fromSigId = s1.sigId,
                toSigId = s2.sigId,
                tool = "phone_tap",
                target = Selector("button", "E$i", "id/e$i", listOf(0, 0, 10, 10), 0),
                ok = if (i == 1) 80 else 1,
                lastOkMs = if (i == 1) 500L else 1000L + i,
            )
        }
        val compacted = AppAtlas("com.example.app", screens = listOf(s1, s2), edges = edges).compacted()
        assertEquals(MAX_SCREEN_CONTROLS, compacted.findScreen(s1.sigId)!!.controls.size)
        assertTrue(compacted.findScreen(s1.sigId)!!.controls.any { it.selector.name == "B1" })
        assertEquals(MAX_ATLAS_EDGES, compacted.edges.size)
        assertTrue(compacted.edges.any { it.target?.name == "E1" })
    }

    @Test
    fun screenSigActivityHelpersAndSimilarityWorkAcrossFormats() {
        assertEquals("LauncherUI", ScreenSig.shortActivityName("com.tencent.mm", "com.tencent.mm/.ui.LauncherUI"))
        assertEquals("LauncherUI", ScreenSig.shortActivityName("com.tencent.mm", "com.tencent.mm.ui.LauncherUI"))
        assertEquals("MainActivity", ScreenSig.shortActivityName("com.a", ".MainActivity"))
        assertNull(ScreenSig.shortActivityName("com.a", "com.a"))
        assertNull(ScreenSig.shortActivityName("com.a", "  "))

        val sigA = ScreenSig("a#1", "com.tencent.mm/.ui.LauncherUI", 0x12345678L, listOf("微信", "通讯录"), listOf("tab_chat"), "com.tencent.mm", "LauncherUI")
        val sigB = ScreenSig("b#1", "com.tencent.mm/com.tencent.mm.ui.LauncherUI", 0x12345678L, listOf("微信", "通讯录"), listOf("tab_chat"), "com.tencent.mm", "LauncherUI")
        val sigOtherAct = sigB.copy(activity = "com.tencent.mm/.plugin.setting.SettingsUI", shortActivity = "SettingsUI")
        val blank = ScreenSig("empty", fingerprint = 0L)

        assertTrue(sigA.matches(sigB))
        assertEquals(0.0, sigA.similarity(sigOtherAct), 1e-6)
        assertFalse(sigA.matches(blank))
        assertFalse(blank.matches(blank))
    }

    @Test
    fun shortcutLifecycleAutoDisableAndCapsWorkCorrectly() {
        val pkg = "com.example.shop"
        val step = RouteStep(
            tool = "phone_tap",
            argsJson = "{}",
            target = Selector("button", "搜索", "btn_search", emptyList(), 0),
            before = Anchors(pkg, listOf("首页")),
            after = Anchors(pkg, listOf("搜索页")),
        )
        val sc = AtlasShortcut(
            id = "sc_search",
            name = "打开搜索",
            description = "tap 搜索",
            slots = 0,
            entrySigId = "Main#1",
            steps = listOf(step, step),
        )
        val extraShortcuts = (1..(MAX_ATLAS_SHORTCUTS + 5)).map { i ->
            sc.copy(id = "sc_$i", name = "快捷$i", successes = if (i == 1) 30 else 1, lastUsedMs = 100L + i)
        }
        val atlas = AppAtlas(
            packageName = pkg,
            screens = listOf(AtlasScreen("Main#1", fingerprint = 1L), AtlasScreen("Old#9", fingerprint = 9L)),
            edges = listOf(AtlasEdge("Main#1", "Old#9", "phone_tap", step.target, ok = 3)),
            shortcuts = listOf(sc, sc.copy(id = "sc_dangling", entrySigId = "Missing#99")) + extraShortcuts,
        )

        val compacted = atlas.compacted()
        assertEquals(MAX_ATLAS_SHORTCUTS, compacted.shortcuts.size)
        assertNull(compacted.findShortcut("sc_dangling"))
        assertTrue(compacted.findShortcut("sc_1") != null)

        // 连续失败 3 次自动停用；重新启用清零失败计数；成功执行累加 successes
        var cur = AppAtlas(pkg, screens = listOf(AtlasScreen("Main#1", fingerprint = 1L)), shortcuts = listOf(sc))
        cur = cur.recordShortcutOutcome("sc_search", succeeded = false, missStep = 0, nowMs = 1000L)
        assertEquals(1, cur.findShortcut("sc_search")!!.consecutiveMisses)
        assertFalse(cur.findShortcut("sc_search")!!.disabled)
        cur = cur.recordShortcutOutcome("sc_search", succeeded = false, missStep = 1, nowMs = 2000L)
        cur = cur.recordShortcutOutcome("sc_search", succeeded = false, missStep = 1, nowMs = 3000L)
        assertTrue(cur.findShortcut("sc_search")!!.disabled)
        assertTrue(cur.activeShortcutsFor("Main#1").isEmpty())

        cur = cur.withShortcutDisabled("sc_search", false)
        assertFalse(cur.findShortcut("sc_search")!!.disabled)
        assertEquals(0, cur.findShortcut("sc_search")!!.consecutiveMisses)
        cur = cur.recordShortcutOutcome("sc_search", succeeded = true, nowMs = 4000L)
        assertEquals(1, cur.findShortcut("sc_search")!!.successes)
        assertEquals(4000L, cur.findShortcut("sc_search")!!.lastUsedMs)

        // recordEdgeMiss 仅累加 miss 不增加 ok
        val edgeAtlas = AppAtlas(
            pkg,
            screens = listOf(AtlasScreen("Main#1", fingerprint = 1L), AtlasScreen("Old#9", fingerprint = 9L)),
            edges = listOf(AtlasEdge("Main#1", "Old#9", "phone_tap", step.target, ok = 2, miss = 0)),
        ).recordEdgeMiss("Main#1", "Old#9", "phone_tap", step.target, nowMs = 5000L)
        assertEquals(2, edgeAtlas.edges.single().ok)
        assertEquals(1, edgeAtlas.edges.single().miss)

        assertTrue(cur.withoutShortcut("sc_search").shortcuts.isEmpty())
    }
}
