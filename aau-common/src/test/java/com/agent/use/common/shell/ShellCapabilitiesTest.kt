package com.agent.use.common.shell

import android.content.Intent
import android.content.pm.ActivityInfo
import android.os.Build
import com.agent.use.common.AppAudioKey
import com.agent.use.common.DisplayConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class ShellCapabilitiesTest {

    @get:Rule
    val tmp = TemporaryFolder()

    @Test
    fun activityQueryBuildsAndParsesBriefOutput() {
        val args = ActivityQuery.args(
            action = Intent.ACTION_SEND,
            type = "text/plain",
            uri = "https://example.com",
            category = Intent.CATEGORY_BROWSABLE,
            packageName = "com.example.app",
            user = "10",
        )
        assertEquals(
            listOf(
                "cmd", "package", "query-activities", "--brief", "--user", "10",
                "-a", Intent.ACTION_SEND,
                "-t", "text/plain",
                "-d", "https://example.com",
                "-c", Intent.CATEGORY_BROWSABLE,
                "-p", "com.example.app",
            ),
            args,
        )

        val parsed = ActivityQuery.parse(
            """
            priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true
              com.example.app/.ShareActivity
              com.example.app/com.example.app.FullActivity
              com.example.app/.ShareActivity
            bad line
            """.trimIndent(),
        )
        assertEquals(
            listOf(
                "com.example.app" to "com.example.app.ShareActivity",
                "com.example.app" to "com.example.app.FullActivity",
            ),
            parsed,
        )
    }

    @Test
    fun appsAfterTaskDecidesAndRechecksCorrectly() {
        assertEquals("com.foo", AppsAfterTask.keyOf("com.foo", 0, 0))
        assertEquals("com.foo@10", AppsAfterTask.keyOf("com.foo", 10, 0))
        assertEquals("com.foo", AppsAfterTask.keyOf("com.foo", 10, 10))
        assertEquals(setOf("com.a", "com.b@999"), AppsAfterTask.normalize(arrayOf("com.a", "com.b@999", "bad key!", "com.c@abc"), 0))

        val tasks = listOf(
            AppsAfterTask.Task(1, listOf("com.own"), standard = true, own = true, playing = false),
            AppsAfterTask.Task(2, listOf("com.pip"), standard = false, own = true.not(), playing = false),
            AppsAfterTask.Task(3, listOf("com.marked.close"), standard = true, own = false, playing = false),
            AppsAfterTask.Task(4, listOf("com.marked.keep"), standard = true, own = false, playing = true),
            AppsAfterTask.Task(5, listOf("com.music"), standard = true, own = false, playing = true),
            AppsAfterTask.Task(6, listOf("com.muted.unknown"), standard = true, own = false, playing = null, muted = true),
            AppsAfterTask.Task(7, listOf("com.reader"), standard = true, own = false, playing = false),
        )
        val fates = AppsAfterTask.decide(tasks, keep = setOf("com.marked.keep"), close = setOf("com.marked.close"))
        assertEquals(
            listOf(
                false to AppsAfterTask.Why.Own,
                false to AppsAfterTask.Why.NotApp,
                false to AppsAfterTask.Why.Marked,
                true to AppsAfterTask.Why.Marked,
                false to AppsAfterTask.Why.Playing,
                false to AppsAfterTask.Why.PlaybackUnknown,
                true to AppsAfterTask.Why.Default,
            ),
            fates.map { it.keep to it.why },
        )

        val markedRecheck = AppsAfterTask.recheck(fates[3], playingNow = true)
        assertTrue(markedRecheck.keep)
        val defaultRecheck = AppsAfterTask.recheck(fates[6], playingNow = true)
        assertFalse(defaultRecheck.keep)
        assertEquals(AppsAfterTask.Why.Playing, defaultRecheck.why)
    }

    @Test
    fun appsAfterTaskParsesPlaybackUidsAndFormatsDiagnostics() {
        assertNull(AppsAfterTask.playingUids("no section here"))
        val uids = AppsAfterTask.playingUids(
            """
            PlaybackActivityMonitor
              AudioPlaybackConfiguration id:1 u/pid:10234/555 state:started
              AudioPlaybackConfiguration id:2 u/pid:10235/556 state:paused
              AudioPlaybackConfiguration id:3 u/pid:10236/557 state:started
            """.trimIndent(),
        )
        assertEquals(setOf(10234, 10236), uids)
        assertEquals(
            "kept 2, closed 2 (playing 1, still in front 1)",
            AppsAfterTask.diagnosticsLine(2, listOf("com.a:playing", "com.b:still_in_front"), null),
        )
    }

    @Test
    fun settleBehindTransitionsAndTimeoutsWork() {
        val wait = SettleBehind.plan(
            moved = setOf(1, 2, 3),
            seen = listOf(
                SettleBehind.Seen(1, onMain = true, visible = true),
                SettleBehind.Seen(2, onMain = true, visible = false),
            ),
            elapsedMs = 100L,
            sinceReorderMs = null,
        )
        assertEquals(SettleBehind.Plan.Wait(reorder = setOf(1), gone = setOf(3)), wait)

        val throttled = SettleBehind.plan(
            moved = setOf(1),
            seen = listOf(SettleBehind.Seen(1, onMain = true, visible = true)),
            elapsedMs = 400L,
            sinceReorderMs = 300L,
        )
        assertEquals(SettleBehind.Plan.Wait(reorder = emptySet(), gone = emptySet()), throttled)

        val done = SettleBehind.plan(
            moved = setOf(1, 2),
            seen = listOf(
                SettleBehind.Seen(1, onMain = true, visible = true),
                SettleBehind.Seen(2, onMain = true, visible = false),
            ),
            elapsedMs = SettleBehind.TIMEOUT_MS,
            sinceReorderMs = 0L,
        )
        assertEquals(SettleBehind.Plan.Done(kept = setOf(2), fallback = setOf(1), gone = emptySet()), done)

        val closedOut = SettleBehind.closeOut(
            moved = setOf(1, 2, 3),
            fallback = setOf(1),
            seen = listOf(
                SettleBehind.Seen(1, onMain = true, visible = true),
                SettleBehind.Seen(2, onMain = true, visible = false),
            ),
        )
        assertEquals(SettleBehind.Plan.Done(kept = setOf(2), fallback = setOf(1), gone = setOf(3)), closedOut)
    }

    @Test
    fun coldStartAndAsciiTextAndShareArgs() {
        assertEquals(ColdStart.IN_USE, ColdStart.decide(listOf(0, 5), agentDisplay = 5, visibleOnMain = true))
        assertEquals(ColdStart.WARM, ColdStart.decide(listOf(1, 5), agentDisplay = 5, visibleOnMain = false))
        assertEquals(ColdStart.RESTART, ColdStart.decide(listOf(5), agentDisplay = 5, visibleOnMain = false))

        assertTrue(AsciiTextKeys.supports("Hello, AAU!"))
        assertFalse(AsciiTextKeys.supports(""))
        assertFalse(AsciiTextKeys.supports("hello\n"))
        assertFalse(AsciiTextKeys.supports("中文"))

        assertEquals(
            listOf("am", "start", "--display", "7", "-a", Intent.ACTION_SEND, "-t", "text/plain", "--es", Intent.EXTRA_TEXT, "hi", "-p", "com.pkg"),
            ShareIntent.amArgs(7, "com.pkg", "hi", null),
        )
        assertEquals(
            listOf("am", "start", "--display", "7", "-a", Intent.ACTION_SEND, "-t", "text/plain", "--es", Intent.EXTRA_TEXT, "hi", "-n", "com.pkg/.Share"),
            ShareIntent.amArgs(7, "com.pkg", "hi", "com.pkg/.Share"),
        )
    }

    @Test
    fun coalescedScanDeduplicatesAndCancelsOnClose() {
        var queued: Runnable? = null
        var cancelled = 0
        var scans = 0
        val coalesced = CoalescedScan(
            schedule = { queued = it },
            cancel = { if (queued === it) { queued = null; cancelled++ } },
            scan = { scans++ },
        )
        coalesced.request()
        coalesced.request()
        assertNotNull(queued)
        queued!!.run()
        assertEquals(1, scans)

        coalesced.request()
        coalesced.close()
        assertEquals(1, cancelled)
        coalesced.request()
        assertNull(queued)
    }

    @Test
    fun shellClipAndOrientationAndAwakeAndLedger() {
        assertEquals(ShellClip.Read.Has, ShellClip.read(clipPresent = true, hasPrimaryClip = false, descriptionPresent = false))
        assertEquals(ShellClip.Read.Unreadable, ShellClip.read(clipPresent = false, hasPrimaryClip = false, descriptionPresent = true))
        assertEquals(ShellClip.Read.Empty, ShellClip.read(clipPresent = false, hasPrimaryClip = false, descriptionPresent = false))

        assertEquals(ShellClip.Restore.Clear, ShellClip.restore(priorEmpty = true, now = ShellClip.Now.Ours))
        assertEquals(ShellClip.Restore.PutBack, ShellClip.restore(priorEmpty = false, now = ShellClip.Now.Ours))
        assertEquals(ShellClip.Restore.Leave, ShellClip.restore(priorEmpty = false, now = ShellClip.Now.Other))

        assertEquals(1, DisplayOrientation.rotation(1080, 1920, 0, 1920, 1080))
        assertNull(DisplayOrientation.rotation(1080, 1920, 1, 1920, 1080))
        assertEquals(0, DisplayOrientation.rotation(1080, 1920, 1, 0, 0, ActivityInfo.SCREEN_ORIENTATION_PORTRAIT))

        assertTrue(DisplayAwake.needed(flags = DisplayConfig.FLAG_OWN_DISPLAY_GROUP, ownGroupFlag = DisplayConfig.FLAG_OWN_DISPLAY_GROUP, groupId = 2))
        assertFalse(DisplayAwake.needed(flags = DisplayConfig.FLAG_OWN_DISPLAY_GROUP, ownGroupFlag = DisplayConfig.FLAG_OWN_DISPLAY_GROUP, groupId = 0))

        var cancels = 0
        val awake = DisplayAwake(poke = { false }) { r ->
            r.run()
            val stop: () -> Unit = { cancels++ }
            stop
        }
        awake.start(3)
        assertEquals(1, cancels)

        val ledgerFile = File(tmp.root, "mute.ledger")
        val ledger = AudioMuteLedger(ledgerFile)
        val key = AppAudioKey.of("com.music", 10)
        ledger.put(key, "default")
        assertTrue(ledgerFile.isFile)
        val reloaded = AudioMuteLedger(ledgerFile)
        assertEquals("default", reloaded[key])
        assertTrue(reloaded.restoreAll { k, mode -> k == "com.music@10" && mode == "allow" })
        assertFalse(ledgerFile.isFile)
    }

    @Test
    fun mainScreenLogAndShellPoliciesAndEngineHelpers() {
        val log = MainScreenLog()
        log.scan(
            listOf(
                MainScreenLog.Task(1, 0, "com.home", 0, "com.home/.Main"),
                MainScreenLog.Task(2, 5, "com.agent", 0, "com.agent/.Page"),
            ),
            now = 1000L,
            record = false,
        )
        assertEquals(1, log.topTaskId)
        log.scan(
            listOf(
                MainScreenLog.Task(2, 0, "com.agent", 0, "com.agent/.Page"),
            ),
            now = 1200L,
            record = true,
        )
        val arrivals = log.since(1000L)
        assertEquals(1, arrivals.size)
        assertEquals(5, arrivals.single().from)
        assertFalse(arrivals.single().sameTask)

        assertEquals(66, ShellPressKeys.resolve("KEYCODE_ENTER"))
        assertNull(ShellPressKeys.resolve("KEYCODE_POWER"))
        assertNull(ShellLinkPolicy.check("android.settings.WIFI_SETTINGS", null, null))
        assertNotNull(ShellLinkPolicy.check(null, "javascript:alert(1)", null))
        assertEquals(ShellLinks.START_INVALID_LINK, ShellLinks.refuse(null, "file:///etc/hosts", null))
        assertTrue(ShellLinks.inUse(emptyList(), emptySet()))

        val dumped = ShellAppCopies.parseDumpsys(
            """
            UserInfo{0:Owner:13} parentId=-1
              Flags: 19 (PRIMARY|ADMIN)
            UserInfo{999:Clone:1000} parentId=0
              Flags: 4096 (CLONE)
            """.trimIndent(),
        )
        assertEquals(listOf("CLONE"), dumped[999]?.flagNames)
        assertEquals(0, dumped[999]?.parentId)
        val usable = ShellAppCopies.usable(
            current = 0,
            users = listOf(
                ShellAppCopies.User(0, 0, "android.os.usertype.full.SYSTEM", 0, running = true),
                ShellAppCopies.User(999, 0, "android.os.usertype.profile.CLONE", 0, running = true, flagNames = dumped[999]?.flagNames, parentId = 0),
                ShellAppCopies.User(15, 0, "android.os.usertype.profile.PRIVATE", 0, running = true),
            ),
        )
        assertEquals(listOf(999), usable)

        assertEquals(12345, ShellDevtoolsSocket.pidOf("webview_devtools_remote_12345"))
        assertNull(ShellDevtoolsSocket.pidOf("webview_devtools_remote_0"))
        assertEquals(10123, ShellDevtoolsSocket.procUid("Name:\tapp\nUid:\t10123\t10123\n"))

        val f34 = AgentShellEngine.displayFlags(Build.VERSION_CODES.UPSIDE_DOWN_CAKE, trusted = true)
        assertTrue(f34 and DisplayConfig.FLAG_TRUSTED != 0)
        assertTrue(f34 and DisplayConfig.FLAG_OWN_FOCUS != 0)
        assertTrue(AgentShellEngine.retryWithoutTrust(SecurityException("denied")))
        assertFalse(AgentShellEngine.retryWithoutTrust(IllegalStateException("other")))
        assertEquals(AgentShellEngine.INJECT_MODE_WAIT_FOR_FINISH, AgentShellEngine.injectMode(key = false, waitForFinish = true))
        assertTrue(AgentShellEngine.sameCopy(listOf("com.app"), null, "com.app", 0))
        assertFalse(AgentShellEngine.sameCopy(listOf("com.app"), 10, "com.app", 0))
        assertEquals("allow", AgentShellEngine.parsePlayAudioMode("Uid mode: PLAY_AUDIO: allow"))
        assertEquals("default", AgentShellEngine.parsePlayAudioMode("No mode set"))
    }
}
