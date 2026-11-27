package com.agent.use.flow

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 脚本解释器：用一条和起点福利中心同形的脚本跑完整两轮。
 *
 * 假宿主按「屏上现在有什么」回答，`tap` 改屏幕状态——和真机上的因果一样：
 * 点「去完成」才出广告，广告里才有 CTA 和 ✕。所以这组测试挡的是**顺序**错误
 * （锚点没先查、✕ 没按名字、退出没回前台），不是像素。
 */
class FlowRunnerTest {

    private class FakeHost : FlowHost {
        var screen = "welfare"
        var claims = 0
        val taps = mutableListOf<String>()

        override suspend fun find(selector: FlowSelector): List<FlowHit> {
            val words = when (screen) {
                "welfare" -> listOf("激励任务", "去完成", "惊喜礼包", "领取", "已领取")
                "ad" -> listOf("去微信立即玩小游戏", "点击退出关闭视频")
                "claim" -> listOf("恭喜获得奖励", "知道了")
                "dialog" -> listOf("打开", "取消")
                "blank" -> emptyList()
                else -> emptyList()
            }
            val key = selector.texts.firstOrNull { t -> words.any { it.contains(t, ignoreCase = true) } }
                ?: return emptyList()
            return words.filter { it.contains(key, ignoreCase = true) }.mapIndexed { i, w ->
                FlowHit(
                    name = w,
                    ref = "@$w",
                    snapshotId = "s1",
                    bounds = listOf(0, 100 * i, 100, 100 * i + 50),
                    center = 500 to 100 * i,
                )
            }
        }

        override suspend fun tap(hit: FlowHit): Boolean {
            taps += hit.name
            when {
                hit.name == "去完成" -> screen = "ad"
                hit.name.contains("立即玩") -> screen = "dialog"
                hit.name == "取消" -> screen = "ad"
                hit.name.contains("退出关闭") || hit.name.contains("关闭视频") -> screen = "claim"
                hit.name == "知道了" -> { screen = "welfare"; claims++ }
            }
            return true
        }

        override suspend fun tapAt(x: Int, y: Int): Boolean {
            taps += "$x,$y"
            return true
        }

        override suspend fun back(): Boolean {
            if (screen == "wechat") screen = "ad"
            return true
        }

        override suspend fun foreground(): String? = "com.qidian.QDReader"
    }

    private val json = """
    {
      "apiVersion": 1,
      "packages": ["com.qidian.QDReader"],
      "flows": [{
        "id": "reward-video",
        "params": {
          "taskText": {"type": "string", "default": "惊喜礼包"},
          "rounds": {"type": "int", "default": "2"}
        },
        "steps": [
          {"op": "wait", "query": {"text": "激励任务"}, "timeoutMs": 900},
          {"op": "repeat", "times": "${'$'}{rounds}", "as": "round", "steps": [
            {"op": "tap", "query": {"text": "去完成", "near": "激励任务", "pick": "nearest"}},
            {"op": "wait", "query": {"text": "激励任务"}, "gone": true, "timeoutMs": 900, "stop": "ad_not_shown"},
            {"op": "sleep", "ms": 5},
            {"op": "tap", "query": {"text": "去微信立即玩", "source": "text", "pick": "maxY"}, "optional": true},
            {"op": "if", "query": {"text": "打开"}, "then": [
              {"op": "tap", "query": {"text": "取消"}, "optional": true}
            ]},
            {"op": "returnTo", "package": "com.qidian.QDReader", "max": 3},
            {"op": "tap", "query": {"textAny": ["退出关闭", "关闭视频"]}, "optional": true},
            {"op": "tap", "query": {"text": "知道了"}, "optional": true}
          ]},
          {"op": "stop", "reason": "round_limit"}
        ]
      }]
    }
    """.trimIndent()

    @Test
    fun runsTwoRoundsAndClosesByAccessibilityName() = runTest {
        val parsed = AppFlowSpec.parsePack(json, "builtin.qidian")
        assertTrue(parsed.errors.toString(), parsed.errors.isEmpty())
        val flow = parsed.flows.single()
        val host = FakeHost()

        val result = FlowRunner(host, pollMs = 5).run(flow)

        assertTrue(result.ok)
        assertEquals("round_limit", result.stopped)
        assertEquals(2, host.claims)
        assertEquals(listOf("去完成", "去微信立即玩小游戏", "取消", "点击退出关闭视频", "知道了"), host.taps.take(5))
        // 第二轮又走了一遍
        assertEquals(2, host.taps.count { it == "去完成" })
        assertEquals(2, host.taps.count { it == "点击退出关闭视频" })
        assertTrue(result.trace.any { it.op == "returnto" })
    }

    @Test
    fun stopsWithTheReasonTheFlowDeclaresWhenNoAdShows() = runTest {
        val parsed = AppFlowSpec.parsePack(json, "builtin.qidian")
        // 点了「去完成」页面却不动：广告一直没盖上来
        val host = object : FlowHost by FakeHost() {
            override suspend fun tap(hit: FlowHit): Boolean = true
        }
        val result = FlowRunner(host, pollMs = 5).run(parsed.flows.single())
        assertEquals("ad_not_shown", result.stopped)
        assertTrue(result.ok)
    }

    @Test
    fun excludesGreyClaimButtons() = runTest {
        // 「领取」也包含在「已领取」里：不过滤就会点灰按钮，点完页面不动，还当成领到了
        val claim = """{"apiVersion":1,"packages":["a.b"],"flows":[{"id":"claim","steps":[
            {"op":"tap","query":{"text":"领取","exclude":["已领"]}}]}]}"""
        val parsed = AppFlowSpec.parsePack(claim, "builtin.qidian")
        val host = FakeHost()
        val result = FlowRunner(host, pollMs = 5).run(parsed.flows.single())
        assertTrue(result.ok)
        assertEquals(listOf("领取"), host.taps)
    }

    @Test
    fun rejectsUnknownOpInsteadOfSkippingIt() {
        val bad = """{"apiVersion":1,"packages":["a.b"],"flows":[{"id":"x","steps":[{"op":"teleport"}]}]}"""
        val parsed = AppFlowSpec.parsePack(bad, "builtin.bad")
        assertTrue(parsed.flows.isEmpty())
        assertTrue(parsed.errors.single().contains("unknown_op:teleport"))
    }

    @Test
    fun missingVariableFailsInsteadOfTappingBlank() = runTest {
        val missing = """{"apiVersion":1,"packages":["a.b"],"flows":[{"id":"x","steps":[
            {"op":"tap","query":{"text":"${'$'}{nope}"}}]}]}"""
        val parsed = AppFlowSpec.parsePack(missing, "builtin.bad")
        val result = FlowRunner(FakeHost(), pollMs = 5).run(parsed.flows.single())
        assertTrue(!result.ok)
        assertTrue(result.stopped.startsWith("error:missing_var"))
    }
}
