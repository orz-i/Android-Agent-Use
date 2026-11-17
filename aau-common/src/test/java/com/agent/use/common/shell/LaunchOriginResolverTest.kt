package com.agent.use.common.shell

import com.agent.use.common.LaunchOrigin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LaunchOriginResolverTest {

    @Test
    fun parsePrefersTopActivityRecordOverRootActivityRecord() {
        val dump = """
            DISPLAY MANAGER ACTIVITIES (dumpsys activity activities)
              Display #0 (activities from top to bottom):
                * Task{a1b2c3d #42 type=standard A=10123:com.browser.app U=0 visible=true}
                  * Hist  #1: ActivityRecord{top111 u0 com.browser.app/.PaymentRedirectActivity t42}
                    launchedFromUid=10222 launchedFromPackage=com.agent.mall userId=0
                  * Hist  #0: ActivityRecord{root000 u0 com.browser.app/.EntryActivity t42}
                    launchedFromUid=10088 launchedFromPackage=com.launcher.app userId=0
                * Task{e4f5a6b #99 type=standard A=10999:com.other.app U=0 visible=false}
                  * Hist  #0: ActivityRecord{other0 u0 com.other.app/.Main t99}
                    launchedFromUid=10001 launchedFromPackage=com.wrong.caller userId=0
        """.trimIndent()

        val origin = LaunchOriginResolver.parse(dump, taskId = 42)
        assertTrue(origin.isKnown)
        assertEquals(10222, origin.uid)
        assertEquals("com.agent.mall", origin.packageName)
        assertEquals(LaunchOrigin.CONFIDENCE_HIGH, origin.confidence)
    }

    @Test
    fun parseFallsBackToRootActivityRecordWhenTopLacksLaunchedFrom() {
        val dump = """
            Display #0:
              * Task{abcd123 #55 type=standard A=0:com.target.app}
                * Hist  #1: ActivityRecord{r1 u0 com.target.app/.SecondActivity t55}
                  intent={act=android.intent.action.VIEW}
                * Hist  #0: ActivityRecord{r0 u0 com.target.app/.FirstActivity t55}
                  mLaunchedFromUid=99910333 mLaunchedFromPackage=com.clone.caller
        """.trimIndent()

        val origin = LaunchOriginResolver.parse(dump, taskId = 55)
        assertTrue(origin.isKnown)
        assertEquals(99910333, origin.uid)
        assertEquals("com.clone.caller", origin.packageName)
        assertEquals(LaunchOrigin.CONFIDENCE_MEDIUM, origin.confidence)
    }

    @Test
    fun parseColorOs14ActivitiesAndNestedSubTaskAndResolverActivity() {
        // 真实设备样本：OnePlus 8T KB2000, Android 14, ColorOS 14.0.0
        val dump = """
            Display #0 (activities from top to bottom):
              * Task{f0ea6ad #49 type=standard I=com.oplus.wirelesssettings/com.android.settings.SettingsActivity U=0 visible=true visibleRequested=false mode=fullscreen translucent=false sz=1}
                mLastPausedActivity: ActivityRecord{4d44c1e u0 com.oplus.wirelesssettings/com.android.settings.SettingsActivity t49}
                * Hist  #0: ActivityRecord{4d44c1e u0 com.oplus.wirelesssettings/com.android.settings.SettingsActivity t49}
                  packageName=com.oplus.wirelesssettings processName=com.oplus.wirelesssettings
                  launchedFromUid=2000 launchedFromPackage=com.android.shell launchedFromFeature=null userId=0
                  Intent { act=android.settings.WIFI_SETTINGS flg=0x10800000 cmp=com.oplus.wirelesssettings/com.android.settings.SettingsActivity mCallingUid=2000 }
                  rootOfTask=true task=Task{f0ea6ad #49 type=standard I=com.oplus.wirelesssettings/com.android.settings.SettingsActivity}
              * Task{7c2f60f #47 type=standard A=1000:com.android.settings.root U=0 visible=false visibleRequested=false mode=fullscreen translucent=true sz=1}
                * Hist  #0: ActivityRecord{903a8ed u0 com.android.settings/com.oplus.settings.feature.homepage.OplusSettingsHomepageActivity t47}
                  intent={cmp=com.android.settings/.Settings}
                * Task{a891ad5 #2 type=home I=com.android.launcher/.Launcher U=0 rootTaskId=1 visible=false visibleRequested=false mode=fullscreen translucent=true sz=1}
                  * Hist  #0: ActivityRecord{9217feb u0 com.android.launcher/.Launcher t2}
                    packageName=com.android.launcher processName=com.android.launcher
                    launchedFromUid=0 launchedFromPackage=null launchedFromFeature=null userId=0
              * Task{caa6231 #50 type=standard I=android/com.android.internal.app.ResolverActivity U=0 visible=false visibleRequested=false mode=fullscreen translucent=true sz=1}
                * Hist  #0: ActivityRecord{c7159bb u0 android/com.android.internal.app.ResolverActivity t50 f}}
                  packageName=android processName=system:ui
                  launchedFromUid=2000 launchedFromPackage=com.android.shell launchedFromFeature=null userId=0
                  Intent { act=android.intent.action.SEND typ=text/plain flg=0x10800000 cmp=android/com.android.internal.app.ResolverActivity (has extras) mCallingUid=2000 }
        """.trimIndent()

        val settings = LaunchOriginResolver.parse(dump, taskId = 49)
        assertEquals(2000, settings.uid)
        assertEquals("com.android.shell", settings.packageName)
        assertEquals(LaunchOrigin.CONFIDENCE_HIGH, settings.confidence)

        val resolver = LaunchOriginResolver.parse(dump, taskId = 50)
        assertEquals(2000, resolver.uid)
        assertEquals("com.android.shell", resolver.packageName)
        assertEquals(LaunchOrigin.CONFIDENCE_HIGH, resolver.confidence)

        // Task #47 不得串读其下方嵌套的 #2 Launcher (launchedFromUid=0)
        val parentWithoutOrigin = LaunchOriginResolver.parse(dump, taskId = 47)
        assertFalse(parentWithoutOrigin.isKnown)

        // Task #2 自身可被正确解析 (uid=0, pkg=null -> root)
        val launcher = LaunchOriginResolver.parse(dump, taskId = 2)
        assertTrue(launcher.isKnown)
        assertEquals(0, launcher.uid)
        assertNull(launcher.packageName)
        assertEquals(LaunchOrigin.CONFIDENCE_HIGH, launcher.confidence)
    }

    @Test
    fun parseStarterIsolatesLastStarterFromHomeStartRecordAndRealColorOsDump() {
        val realColorOsStarter = """
            ACTIVITY MANAGER STARTER (dumpsys activity starter)
            mLastHomeActivityStartResult=0
            mLastHomeActivityStartRecord:
              packageName=com.android.launcher processName=com.android.launcher
              launchedFromUid=0 launchedFromPackage=null launchedFromFeature=null userId=0
            mLastStarter:
              mCurrentUser=0
              mLastStartReason=startActivityAndWait
              mLastStartActivityTimeMs=2026年11月15日 11:44:06
              mLastStartActivityResult=0
              mStartActivity:
                packageName=com.oplus.wirelesssettings processName=com.oplus.wirelesssettings
                launchedFromUid=10288 launchedFromPackage=com.agent.mall launchedFromFeature=null userId=0
                Intent { act=android.settings.WIFI_SETTINGS flg=0x10800000 cmp=com.oplus.wirelesssettings/com.android.settings.SettingsActivity mCallingUid=10288 }
                rootOfTask=true task=Task{f0ea6ad #49 type=standard I=com.oplus.wirelesssettings/com.android.settings.SettingsActivity}
              mIntent=Intent { act=android.settings.WIFI_SETTINGS flg=0x10800000 cmp=com.oplus.wirelesssettings/com.android.settings.SettingsActivity mCallingUid=10288 }
              mLaunchMode=LAUNCH_MULTIPLE  mLaunchFlags=0x10800000 mDoResume=true mAddingToTask=true mInTaskFragment=null
        """.trimIndent()

        // 确保绝不会被前面的 mLastHomeActivityStartRecord (launchedFromUid=0) 污染
        val origin49 = LaunchOriginResolver.parseStarter(realColorOsStarter, taskId = 49)
        assertTrue(origin49.isKnown)
        assertEquals(10288, origin49.uid)
        assertEquals("com.agent.mall", origin49.packageName)
        assertEquals(LaunchOrigin.CONFIDENCE_MEDIUM, origin49.confidence)

        // 不匹配的 taskId 返回 UNKNOWN
        assertFalse(LaunchOriginResolver.parseStarter(realColorOsStarter, taskId = 88).isKnown)

        // 仅含 mCallingUid 时作为低置信度兜底
        val callingOnlyStarter = """
            mLastStarter:
              mStartActivity:
                ActivityRecord{a2 u0 com.shop.app/.Detail t77}
                Intent { mCallingUid=10444 }
              callingPackage=com.caller.agent
        """.trimIndent()
        val origin77 = LaunchOriginResolver.parse("", callingOnlyStarter, taskId = 77)
        assertEquals(10444, origin77.uid)
        assertEquals("com.caller.agent", origin77.packageName)
        assertEquals(LaunchOrigin.CONFIDENCE_LOW, origin77.confidence)
    }

    @Test
    fun parseReturnsUnknownWhenMissingOrInvalid() {
        assertFalse(LaunchOriginResolver.parse("", 42).isKnown)
        assertEquals(LaunchOrigin.UNKNOWN_UID, LaunchOriginResolver.parse("", 42).uid)
        assertNull(LaunchOriginResolver.parse("", 42).packageName)
        assertEquals(LaunchOrigin.CONFIDENCE_UNKNOWN, LaunchOriginResolver.parse("", 42).confidence)

        val nullOriginDump = """
            * Task{abc #12 type=standard}
              * Hist  #0: ActivityRecord{r0 u0 com.foo/.Main t12}
                launchedFromUid=-1 launchedFromPackage=null
        """.trimIndent()
        val parsed = LaunchOriginResolver.parse(nullOriginDump, 12)
        assertFalse(parsed.isKnown)
        assertEquals(LaunchOrigin.unknown(), parsed)
        assertFalse(LaunchOriginResolver.parse(nullOriginDump, -1).isKnown)
    }

    @Test
    fun resolveUsesFullDumpsWithoutPackageFilterAndFallsBackToStarter() {
        val commands = ArrayList<List<String>>()
        val fromActivities = LaunchOriginResolver.resolve(taskId = 10, packageName = "com.app") { cmd ->
            commands += cmd.toList()
            0 to """
                * Task{t10 #10 type=standard}
                  * Hist  #0: ActivityRecord{r0 u0 com.app/.Main t10}
                    launchedFromUid=10111 launchedFromPackage=com.fast.origin
            """.trimIndent()
        }
        assertEquals(10111, fromActivities.uid)
        assertEquals("com.fast.origin", fromActivities.packageName)
        // 禁止传 -p 参数，直接执行全量 dumpsys activity activities
        assertEquals(listOf(listOf("dumpsys", "activity", "activities")), commands)

        commands.clear()
        val fromStarter = LaunchOriginResolver.resolve(taskId = 11, packageName = "com.app") { cmd ->
            commands += cmd.toList()
            when (cmd.last()) {
                "activities" -> 0 to "No matching task"
                "starter" -> 0 to """
                    mLastStarter:
                      mStartActivity:
                        launchedFromUid=10222 launchedFromPackage=com.starter.origin
                        task=Task{t11 #11 type=standard}
                """.trimIndent()
                else -> -1 to ""
            }
        }
        assertEquals(10222, fromStarter.uid)
        assertEquals("com.starter.origin", fromStarter.packageName)
        assertEquals(LaunchOrigin.CONFIDENCE_MEDIUM, fromStarter.confidence)
        assertEquals(
            listOf(
                listOf("dumpsys", "activity", "activities"),
                listOf("dumpsys", "activity", "starter"),
            ),
            commands,
        )
    }

    @Test
    fun parseExtractsColorOsSystemMediatedJumpConfirmOriginOnPlk110() {
        val colorOsActivitiesDump = """
            Display #0 (activities from top to bottom):
              * Task{8f537e3 #48921 type=standard A=1000:.StartConfirmDialog}
                * Hist  #0: ActivityRecord{abc123 u0 com.oplus.securitypermission/com.oplusos.securitypermission.permission.ui.AppStartConfirmDialogActivity t48921}
                  Intent { act=oplus.app.action.CHECK_ALLOW_START_ACTIVITY flg=0x10800000 xflg=0x4 pkg=com.oplus.securitypermission cmp=com.oplus.securitypermission/com.oplusos.securitypermission.permission.ui.AppStartConfirmDialogActivity (has extras) mCallingUid=1000 }
                  launchedFromUid=1000 launchedFromPackage=android launchedFromFeature=null userId=0
            Display #5 (activities from top to bottom):
              * Task{602391c #48920 type=standard A=10410:com.tencent.weread}
                * Hist  #0: ActivityRecord{def456 u0 com.tencent.weread/.WeReadFragmentActivity t48920}
                  launchedFromUid=10614 launchedFromPackage=com.wangzan101.mika userId=0
        """.trimIndent()

        val origin48921 = LaunchOriginResolver.parse(colorOsActivitiesDump, taskId = 48921)
        assertEquals(1000, origin48921.uid)
        assertEquals("android", origin48921.packageName)
        assertEquals(LaunchOrigin.CONFIDENCE_HIGH, origin48921.confidence)
    }

    @Test
    fun resolveBypassesSelfOriginAndLauncherRootViaActivityTaskManagerLogcat() {
        val wechatTaskWithSelfTopAndLauncherRoot = """
            Display #0 (activities from top to bottom):
              * Task{bdeb737 #49336 type=standard A=10433:com.tencent.mm}
                * Hist  #1: ActivityRecord{82496689 u0 com.tencent.mm/.plugin.base.stub.WXBizEntryActivity t49336}
                  launchedFromUid=10433 launchedFromPackage=com.tencent.mm userId=0
                * Hist  #0: ActivityRecord{198306257 u0 com.tencent.mm/.ui.LauncherUI t49336}
                  launchedFromUid=10233 launchedFromPackage=com.android.launcher userId=0
        """.trimIndent()

        // 传入 targetPackage=com.tencent.mm 时，识别到自启动与历史桌面遮蔽并追查近期系统日志
        val resolvedFromStartLog = LaunchOriginResolver.resolve(
            taskId = 49336,
            packageName = "com.tencent.mm",
            nowEpochMs = 1_794_881_604_850L,
        ) { cmd ->
            when {
                cmd.contains("activities") -> 0 to wechatTaskWithSelfTopAndLauncherRoot
                cmd.contains("starter") -> 0 to "mLastStarter:\n  task=Task{other #999}"
                cmd.firstOrNull() == "logcat" -> 0 to """
                             1794881604.210  9197  9666 I ActivityTaskManager: START u0 {dat=weixin://dl/... flg=0x10000000 cmp=com.tencent.mm/.plugin.base.stub.WXBizEntryActivity} with LAUNCH_SINGLE_TOP from uid 10433 (com.tencent.mm) result code=0
                             1794881604.215  9197  9296 I ActivityTaskManager: START u0 {act=android.intent.action.MAIN flg=0x10000000 pkg=com.tencent.mm cmp=com.tencent.mm/.ui.LauncherUI} with LAUNCH_SINGLE_TOP from uid 10434 (com.qidian.QDReader) (realCallingUid=1000) result code=3
                """.trimIndent()
                else -> -1 to ""
            }
        }
        assertEquals(10434, resolvedFromStartLog.uid)
        assertEquals("com.qidian.QDReader", resolvedFromStartLog.packageName)
        assertEquals(LaunchOrigin.CONFIDENCE_HIGH, resolvedFromStartLog.confidence)

        // 当 WXBizEntryActivity 已销毁只剩 LauncherUI（launchedFromPackage=com.android.launcher）时，也能从 BAL 日志反查真实发起方
        val launcherOnlyRootDump = """
            Display #0 (activities from top to bottom):
              * Task{bdeb737 #49336 type=standard A=10433:com.tencent.mm}
                * Hist  #0: ActivityRecord{198306257 u0 com.tencent.mm/.ui.LauncherUI t49336}
                  launchedFromUid=10233 launchedFromPackage=com.android.launcher userId=0
        """.trimIndent()
        val resolvedFromBalLog = LaunchOriginResolver.resolve(
            taskId = 49336,
            packageName = "com.tencent.mm",
            nowEpochMs = 1_794_881_604_850L,
        ) { cmd ->
            when {
                cmd.contains("activities") -> 0 to launcherOnlyRootDump
                cmd.contains("starter") -> 0 to ""
                cmd.firstOrNull() == "logcat" -> 0 to """
                             1794881604.213  9197  9296 E ActivityTaskManager: With Android 15 BAL hardening this activity start may be blocked ![callingPackage: com.qidian.QDReader; callingPackageTargetSdk: 30; callingUid: 10434; callingPid: -1; intent: Intent { pkg=com.tencent.mm cmp=com.tencent.mm/.ui.LauncherUI }]
                """.trimIndent()
                else -> -1 to ""
            }
        }
        assertEquals(10434, resolvedFromBalLog.uid)
        assertEquals("com.qidian.QDReader", resolvedFromBalLog.packageName)
        assertEquals(LaunchOrigin.CONFIDENCE_HIGH, resolvedFromBalLog.confidence)
    }
}
