package com.agent.use.common.capture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

/**
 * 长截图拼接的算法级测试。
 *
 * 合成帧用「内容编号」表示：编号相同的行就是同一块画面。这样可以精确构造
 * 「滚动了 N 行」「整屏换掉」「固定标题栏」等场景，而不必依赖真机截图。
 *
 * 关键的一条是 [noisy frames still match]：真机实测一次滚动的两帧只有约 97.8% 的行
 * 逐像素相同，其余因抗锯齿/亚像素位移差一两个色阶。第一版用 KMP 精确匹配就是在
 * 这里归零的，所以必须把噪声作为默认条件写进测试。
 */
class LongScreenshotCaptureTest {

    // ---------- 合成工具 ----------

    /**
     * 把内容编号扩散成 8 段亮度。
     *
     * 用 splitmix64 而不是线性公式或 LCG：线性映射会让无关位移只产生固定的小差值；
     * LCG 更糟——两个只差几十的种子经过同样的迭代后，高 8 位仍然相关，于是「差 20 的行」
     * 反而比「差 4 的行」更像，直接把粗扫引到错误位置。splitmix64 的雪崩性保证
     * 不同编号的输出互相独立，测试才测的是算法而不是生成器的漏洞。
     */
    private fun packRow(id: Int): Long {
        var packed = 0L
        var z = id.toLong() * -7046029254386353131L
        for (seg in 0 until RowSignature.SEGMENTS) {
            z += -7046029254386353131L
            var t = z
            t = (t xor (t ushr 30)) * -4658895280553007687L
            t = (t xor (t ushr 27)) * -7723592293110705685L
            t = t xor (t ushr 31)
            packed = packed or ((t and 0xFF) shl (seg * 8))
        }
        return packed
    }

    private fun textureOf(row: Long): Int {
        var min = 255
        var max = 0
        for (seg in 0 until RowSignature.SEGMENTS) {
            val v = ((row ushr (seg * 8)) and 0xFF).toInt()
            if (v < min) min = v
            if (v > max) max = v
        }
        return max - min
    }

    private fun makeFrame(ids: IntRange, texture: Int = 80): FrameSignature {
        val count = ids.count()
        val rows = LongArray(count) { packRow(ids.first + it) }
        val tex = IntArray(count) { maxOf(textureOf(rows[it]), texture) }
        return FrameSignature(rows, tex)
    }

    /** 给每一段加 ±delta 的随机扰动，模拟真机上的色阶抖动。 */
    private fun FrameSignature.noisy(delta: Int, seed: Int = 42): FrameSignature {
        val random = Random(seed)
        val out = LongArray(rows.size)
        for (i in rows.indices) {
            var packed = 0L
            for (seg in 0 until RowSignature.SEGMENTS) {
                val value = ((rows[i] ushr (seg * 8)) and 0xFF).toInt()
                val jitter = random.nextInt(-delta, delta + 1)
                val noisy = (value + jitter).coerceIn(0, 255)
                packed = packed or (noisy.toLong() shl (seg * 8))
            }
            out[i] = packed
        }
        return FrameSignature(out, texture.copyOf())
    }

    private fun FrameSignature.duplicate() = FrameSignature(rows.copyOf(), texture.copyOf())

    // ---------- 正常滚动 ----------

    @Test
    fun `normal scroll finds exact overlap and new rows`() {
        val prev = makeFrame(0 until 200)
        // 向上滚动 60 行：新帧第 i 行 = 旧帧第 i + 60 行
        val next = makeFrame(60 until 260)

        val match = OverlapFinder.match(prev, next, minOverlap = 16, minNewRows = 8)

        assertTrue("found=${match.found} newRows=${match.newRows} score=${match.score}", match.found)
        assertEquals("delta, score=${match.score}", 60, match.newRows)
        assertEquals(140, match.overlapRows)
        // skipRows = 顶栏 + 重叠行数 = 0 + 140
        assertEquals(140, match.skipRows)
        assertTrue(match.scrolled)
    }

    @Test
    fun `noisy frames still match`() {
        val prev = makeFrame(0 until 200)
        val next = makeFrame(60 until 260).noisy(delta = 3)

        val match = OverlapFinder.match(prev, next, minOverlap = 16, minNewRows = 8)

        assertTrue("带 ±3 抖动: found=${match.found} newRows=${match.newRows} score=${match.score}", match.found)
        assertEquals("noisy delta, score=${match.score}", 60, match.newRows)
    }

    @Test
    fun `heavy noise is rejected instead of mis-stitched`() {
        val prev = makeFrame(0 until 200)
        // ±70 的抖动基本抹掉了内容差异，不该被当成可信重叠
        val next = makeFrame(60 until 260).noisy(delta = 70)

        val match = OverlapFinder.match(prev, next, minOverlap = 16, minNewRows = 8)
        assertFalse("噪声过大时应返回未找到，宁可少拼也不错拼", match.found)
    }

    // ---------- 终止条件 ----------

    @Test
    fun `identical frames mean reached end`() {
        val prev = makeFrame(0 until 200)
        val next = makeFrame(0 until 200)

        val match = OverlapFinder.match(prev, next, minOverlap = 16, minNewRows = 8)
        assertTrue(match.found)
        assertEquals(0, match.newRows)
        assertFalse("没有新内容就不算有效滚动", match.scrolled)
    }

    @Test
    fun `completely different screens report no overlap`() {
        val prev = makeFrame(0 until 200)
        val next = makeFrame(1000 until 1200)

        val match = OverlapFinder.match(prev, next, minOverlap = 16, minNewRows = 8)
        assertFalse(match.found)
    }

    @Test
    fun `overlap below threshold is rejected`() {
        val prev = makeFrame(0 until 200)
        val next = makeFrame(190 until 390) // 只剩 10 行重叠

        val match = OverlapFinder.match(prev, next, minOverlap = 40, minNewRows = 8)
        assertFalse("重叠行数低于阈值应判定为无重叠", match.found)
    }

    // ---------- 固定区 ----------

    @Test
    fun `sticky header is excluded from matching`() {
        // 两帧顶部 10 行是同一个标题栏，内容各滚各的
        val header = makeFrame(0 until 10)
        val prevBody = makeFrame(1000 until 1190)
        val nextBody = makeFrame(1060 until 1250)

        fun assemble(body: FrameSignature) =
            FrameSignature(header.rows + body.rows, header.texture + body.texture)

        val prev = assemble(prevBody)
        val next = assemble(nextBody)

        // 投票法对少量固定行免疫：标题栏只占 10/200，锚点仍被内容区主导，delta 依旧正确。
        // 这正是从「整段平均分」换成「锚点投票」换来的鲁棒性。
        val plain = OverlapFinder.match(prev, next, minOverlap = 16, minNewRows = 8)
        assertTrue("plain: found=${plain.found} newRows=${plain.newRows}", plain.found)
        assertEquals("plain delta", 60, plain.newRows)

        // 显式排除标题栏后结果一致，skipRows 仍是「标题栏 + 重叠」
        val withHeader = OverlapFinder.match(prev, next, minOverlap = 16, minNewRows = 8, topInset = 10)
        assertTrue("header: found=${withHeader.found} newRows=${withHeader.newRows} score=${withHeader.score}", withHeader.found)
        assertEquals("header delta, score=${withHeader.score}", 60, withHeader.newRows)
        assertEquals(10 + 130, withHeader.skipRows)
    }

    @Test
    fun `bottom inset is excluded from matching`() {
        val prevContent = makeFrame(0 until 190)
        val nextContent = makeFrame(50 until 240)
        // 底部 10 行是固定导航栏
        val bar = makeFrame(7000 until 7010)

        fun assemble(body: FrameSignature) =
            FrameSignature(body.rows + bar.rows, body.texture + bar.texture)

        val match = OverlapFinder.match(
            assemble(prevContent), assemble(nextContent),
            minOverlap = 16, minNewRows = 8, bottomInset = 10,
        )
        assertTrue("bottom: found=${match.found} newRows=${match.newRows} score=${match.score}", match.found)
        assertEquals("bottom delta, score=${match.score}", 50, match.newRows)
    }

    // ---------- 边界 ----------

    @Test
    fun `zz debug scores`() {
        val prev = makeFrame(0 until 200)
        val next = makeFrame(60 until 260)
        for (d in listOf(0, 8, 40, 56, 60, 64, 96, 140, 184)) {
            println("DEBUG d=$d score=${OverlapFinder.scoreAt(prev, next, d, 0, 200, 1)}")
        }
        println("DEBUG match=" + OverlapFinder.match(prev, next, 16, 8))
        println("DEBUG tex0=${prev.texture[0]} tex100=${prev.texture[100]}")
        println("DEBUG rowEq=${prev.rows[60] == next.rows[0]} dist=${RowSignature.rowDistance(prev.rows[60], next.rows[0])}")
    }

    @Test
    fun `solid color page is not matched`() {
        val flat = FrameSignature(LongArray(200) { 0x4040404040404040L }, IntArray(200) { 0 })

        val match = OverlapFinder.match(flat, flat, minOverlap = 16, minNewRows = 8)
        assertFalse("纯色页面没有匹配依据", match.found)
    }

    @Test
    fun `empty signatures are rejected`() {
        val empty = FrameSignature(LongArray(0), IntArray(0))
        assertFalse(OverlapFinder.match(empty, empty, 8, 4).found)
    }

    @Test
    fun `mismatched heights are rejected`() {
        val a = makeFrame(0 until 100)
        val b = makeFrame(0 until 120)
        assertFalse(OverlapFinder.match(a, b, 8, 4).found)
    }

    // ---------- 选项裁剪 ----------

    @Test
    fun `inset ratio is capped to a quarter of the frame`() {
        val options = LongScreenshotOptions(topInsetRatio = 0.30f)
        assertEquals(250, options.topInsetOf(1_000))
    }

    @Test
    fun `similarity tolerates small jitter but not real change`() {
        val base = makeFrame(0 until 100)
        assertTrue(base.similarTo(base.duplicate()))
        assertTrue(base.noisy(delta = 2).similarTo(base))
        assertFalse("内容整体换掉必须判为不同", base.similarTo(makeFrame(500 until 600)))
    }
}
