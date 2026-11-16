package com.agent.use.common.shell

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class JumpTargetResolverTest {

    private val ctx = JumpTargetResolver.TargetLookupContext(
        taskId = 49061,
        interstitialPackage = "com.oplus.securitypermission",
        initiatorPackage = "com.tencent.weread",
        initiatorUid = 10410,
        windowMs = 4_000L,
    )

    @Test
    fun resolvePrefersBaseIntentBeforeDumpsAndLogcat() {
        val target = JumpTargetResolver.parseFromSources(
            ctx = ctx,
            baseIntent = JumpTargetResolver.IntentSummary(
                packageName = "com.oplus.securitypermission",
                componentPackage = "com.oplus.securitypermission",
                dataUri = "weixin://dl/jumpWxa/?appid=wx123",
            ),
            resolveSchemeUri = { uri -> if (uri.startsWith("weixin://")) "com.tencent.mm" else null },
        )
        assertEquals("com.tencent.mm", target)
    }

    @Test
    fun resolveReadsFreshActivityTaskManagerStartLogMatchingInitiator() {
        val logcat = """
            1794753450.000  9197 10111 I ActivityTaskManager: START u0 {act=android.intent.action.VIEW cmp=com.taobao.taobao/.MainActivity} with LAUNCH_MULTIPLE from uid 10999 (com.unrelated.app) result code=0
            1794753455.900  9197 10111 I ActivityTaskManager: START u0 {act=android.intent.action.VIEW dat=weixin://dl/jumpWxa/?appid=wxab9b71ad2b90ff34 cmp=com.tencent.mm/.plugin.base.stub.WXBizEntryActivity flg=0x10000000} with LAUNCH_MULTIPLE from uid 10410 (com.tencent.weread) result code=0
            1794753456.100  9197 10111 I ActivityTaskManager: START u0 {act=oplus.app.action.CHECK_ALLOW_START_ACTIVITY cmp=com.oplus.securitypermission/com.oplusos.securitypermission.permission.ui.AppStartConfirmDialogActivity (has extras)} with LAUNCH_MULTIPLE from uid 1000 (android) result code=0
        """.trimIndent()

        val resolved = JumpTargetResolver.parseFromSources(
            ctx = ctx,
            logcatDump = logcat,
            nowEpochMs = 1794753456_460L,
        )
        assertEquals("com.tencent.mm", resolved)

        // 超过 4s 时间窗的陈旧日志必须忽略，不能误抓历史跳转
        val stale = JumpTargetResolver.parseFromSources(
            ctx = ctx,
            logcatDump = logcat,
            nowEpochMs = 1794753462_000L,
        )
        assertNull(stale)
    }

    @Test
    fun resolveIgnoresUnrelatedPendingIntentAndReadsInitiatorOrInterstitialPendingIntent() {
        val intentsDump = """
            ACTIVITY MANAGER PENDING INTENTS (dumpsys activity intents)
              * com.taobao.taobao: 1 items
                #0: PendingIntentRecord{aaaa com.taobao.taobao startActivity}
                  uid=10427 packageName=com.taobao.taobao featureId=null type=startActivity flags=0x4000000
                  requestIntent=cmp=com.taobao.taobao/.TaoDetailActivity
              * com.oplus.securitypermission: 1 items
                #0: PendingIntentRecord{bbbb com.oplus.securitypermission startActivity}
                  uid=1000 packageName=com.oplus.securitypermission featureId=null type=startActivity flags=0x4000000
                  requestIntent=dat=weixin://dl/jumpWxa/?appid=wx123 cmp=com.tencent.mm/.plugin.base.stub.WXBizEntryActivity (has extras)
        """.trimIndent()

        assertEquals(
            "com.tencent.mm",
            JumpTargetResolver.parseFromSources(ctx = ctx, intentsDump = intentsDump),
        )

        // 若没有 interstitial/initiator 所属 PendingIntent，不得误用其它 App（如淘宝）的历史 PendingIntent
        val onlyTargetAppOwned = """
              * com.taobao.taobao: 1 items
                #0: PendingIntentRecord{aaaa com.taobao.taobao startActivity}
                  uid=10427 packageName=com.taobao.taobao featureId=null type=startActivity flags=0x4000000
                  requestIntent=cmp=com.taobao.taobao/.TaoDetailActivity
        """.trimIndent()
        assertNull(JumpTargetResolver.parseFromSources(ctx = ctx, intentsDump = onlyTargetAppOwned))
    }

    @Test
    fun resolveIgnoresWebHttpSchemesToAvoidGuessingBrowserOrLinkHandler() {
        val activitiesDump = """
            Display #0 (activities from top to bottom):
              * Task{8f537e3 #49061 type=standard A=1000:.StartConfirmDialog}
                * Hist  #0: ActivityRecord{abc123 u0 com.oplus.securitypermission/.AppStartConfirmDialogActivity t49061}
                  Intent { act=android.intent.action.VIEW dat=https://weread.qq.com/web/123 cmp=com.oplus.securitypermission/.AppStartConfirmDialogActivity }
                  launchedFromUid=10410 launchedFromPackage=com.tencent.weread userId=0
        """.trimIndent()

        var schemeLookups = 0
        val resolved = JumpTargetResolver.parseFromSources(
            ctx = ctx,
            activitiesDump = activitiesDump,
            resolveSchemeUri = { schemeLookups++; "com.tencent.mm" },
        )
        assertNull(resolved)
        assertEquals(0, schemeLookups)
    }
}
