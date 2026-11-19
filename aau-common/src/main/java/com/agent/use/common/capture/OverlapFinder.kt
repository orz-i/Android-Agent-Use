package com.agent.use.common.capture

import kotlin.math.abs

/**
 * 帧间重叠求解器。
 *
 * 问题定义：页面向上滚动 `delta` 行后，新帧的第 `i` 行就是上一帧的第 `i + delta` 行，
 * 于是「重叠行数」= 内容高度 − delta，也就是**上一帧后缀**与**新帧前缀**的公共长度。
 *
 * ## 为什么不是「逐 delta 求平均分」
 *
 * 第一版用 KMP 精确匹配，真机实测直接归零：一次滚动的两帧只有约 97.8% 的行逐像素相同，
 * 剩下 2.2% 因为抗锯齿、亚像素位移、OLED 调光差一两个色阶，精确匹配要求 100% 连续相等。
 *
 * 第二版改成「粗扫 + 局部精修」的容差匹配，仍然失败——因为真实位移不落在粗扫步长上时，
 * 相邻两个候选点的分数都是噪声级，谷底只有一两行宽，粗扫根本看不见它。
 *
 * 现在这一版换成**锚点投票**，思路和长截图真正的做法一致：
 *
 * 1. 从新帧里挑若干**高纹理行**当锚点（纯色行不携带信息，不能当锚点）；
 * 2. 每个锚点在上一帧里找「几乎是同一行」的位置（距离小于 [SAME_ROW_DISTANCE]）；
 * 3. 每一对「锚点位置 i ↔ 命中位置 j」给 `delta = j - i` 投一票；
 * 4. 票数最高的若干 delta 再用整段加权距离复核，选最优。
 *
 * 单行即可定位，不依赖连续匹配，因此对噪声、对局部内容变化（点赞数、时间戳）都更稳。
 */
object OverlapFinder {

    /** 参与投票的锚点数量上限。 */
    private const val ANCHOR_COUNT = 24

    /** 锚点之间的最小行距，避免全部挤在同一块内容里。 */
    private const val ANCHOR_MIN_GAP = 12

    /** 认定「同一行」的最大段距离（8 段平均差 3）。 */
    private const val SAME_ROW_DISTANCE = 24

    /** 投票后进入复核的候选数量。 */
    private const val CANDIDATE_COUNT = 4

    /** 匹配评分的接受阈值（千分比）：平均每段偏差 6% 以内认为同一块画面。 */
    const val DEFAULT_THRESHOLD = 60

    /** 整帧平均纹理低于此值时认为页面是纯色，不做匹配。 */
    private const val MIN_TEXTURE = 6

    /**
     * 匹配结果。
     *
     * @property skipRows 新帧顶部应当跳过的行数（= 顶栏高度 + 重叠行数）；找不到重叠时为 -1
     * @property newRows 新帧真正带来的新内容行数（= delta）
     * @property overlapRows 判定出的重叠行数
     * @property scrolled 是否算「有效滚动」（新内容行数达到阈值）
     * @property score 匹配评分（0..1000，越小越可信）
     * @property votes 支持该 delta 的锚点数（诊断用）
     */
    data class Match(
        val skipRows: Int,
        val newRows: Int,
        val overlapRows: Int,
        val scrolled: Boolean,
        val score: Int = -1,
        val votes: Int = 0,
    ) {
        val found: Boolean get() = skipRows >= 0

        companion object {
            /** 未找到可用重叠。 */
            @JvmStatic
            val NONE = Match(skipRows = -1, newRows = 0, overlapRows = 0, scrolled = false)
        }
    }

    /**
     * 在相邻两帧的特征上求重叠。
     *
     * @param prev 上一帧特征
     * @param next 当前帧特征
     * @param minOverlap 最小可信重叠行数
     * @param minNewRows 最小有效新增行数
     * @param topInset 顶部固定区行数
     * @param bottomInset 底部固定区行数
     * @param threshold 评分接受阈值
     */
    @JvmStatic
    @JvmOverloads
    fun match(
        prev: FrameSignature,
        next: FrameSignature,
        minOverlap: Int,
        minNewRows: Int,
        topInset: Int = 0,
        bottomInset: Int = 0,
        threshold: Int = DEFAULT_THRESHOLD,
    ): Match {
        if (prev.height == 0 || next.height != prev.height) return Match.NONE

        val frameHeight = prev.height
        val top = topInset.coerceIn(0, frameHeight / 2)
        val bottom = bottomInset.coerceIn(0, frameHeight / 2)
        val contentHeight = frameHeight - top - bottom
        if (contentHeight <= 0) return Match.NONE

        var textureSum = 0L
        for (i in top until top + contentHeight) textureSum += next.texture[i]
        if (textureSum / contentHeight < MIN_TEXTURE) return Match.NONE

        val maxDelta = contentHeight - minOverlap
        if (maxDelta <= 0) return Match.NONE

        val candidates = voteDeltas(prev, next, top, contentHeight, maxDelta)
        if (candidates.isEmpty()) return Match.NONE

        var bestDelta = -1
        var bestScore = Int.MAX_VALUE
        var bestVotes = 0
        for ((delta, votes) in candidates) {
            val score = scoreAt(prev, next, delta, top, contentHeight, 1)
            if (score < bestScore) {
                bestScore = score
                bestDelta = delta
                bestVotes = votes
            }
        }
        if (bestDelta < 0 || bestScore > threshold) return Match.NONE

        val overlap = contentHeight - bestDelta
        if (overlap <= 0 || overlap < minOverlap) return Match.NONE

        return Match(
            skipRows = top + overlap,
            newRows = bestDelta,
            overlapRows = overlap,
            scrolled = bestDelta >= minNewRows,
            score = bestScore,
            votes = bestVotes,
        )
    }

    /** 带 [LongScreenshotOptions] 的便捷重载：按帧高换算顶部/底部固定区。 */
    @JvmStatic
    fun match(
        prev: FrameSignature,
        next: FrameSignature,
        options: LongScreenshotOptions,
        frameHeight: Int,
    ): Match = match(
        prev = prev,
        next = next,
        minOverlap = options.minOverlapPx,
        minNewRows = options.minNewRowsPx,
        topInset = options.topInsetOf(frameHeight),
        bottomInset = options.bottomInsetOf(frameHeight),
    )

    /**
     * 锚点投票：返回按票数降序的 (delta, votes) 候选。
     *
     * 锚点只取**高纹理行**。纯色行在整帧里可能重复成百上千次，拿它投票只会淹没真实信号，
     * 这也是「先加权、再投票」两重保险的原因。
     */
    internal fun voteDeltas(
        prev: FrameSignature,
        next: FrameSignature,
        top: Int,
        contentHeight: Int,
        maxDelta: Int,
    ): List<Pair<Int, Int>> {
        val anchors = pickAnchors(next, top, contentHeight)
        if (anchors.isEmpty()) return emptyList()

        val votes = HashMap<Int, Int>(64)
        for (anchorRow in anchors) {
            val target = next.rows[anchorRow]
            for (j in top until top + contentHeight) {
                if (RowSignature.rowDistance(prev.rows[j], target) > SAME_ROW_DISTANCE) continue
                val delta = j - anchorRow
                if (delta < 0 || delta > maxDelta) continue
                votes[delta] = (votes[delta] ?: 0) + 1
            }
        }
        if (votes.isEmpty()) return emptyList()
        return votes.entries
            .sortedByDescending { it.value }
            .take(CANDIDATE_COUNT)
            .map { it.key to it.value }
    }

    /** 挑出纹理最高的若干行作为锚点，彼此至少间隔 [ANCHOR_MIN_GAP]。 */
    private fun pickAnchors(next: FrameSignature, top: Int, contentHeight: Int): IntArray {
        val scored = ArrayList<Int>(contentHeight)
        for (i in top until top + contentHeight) scored.add(i)
        scored.sortByDescending { next.texture[it] }

        val chosen = ArrayList<Int>(ANCHOR_COUNT)
        for (row in scored) {
            if (chosen.size >= ANCHOR_COUNT) break
            if (next.texture[row] < MIN_TEXTURE) break
            if (chosen.any { abs(it - row) < ANCHOR_MIN_GAP }) continue
            chosen.add(row)
        }
        return chosen.toIntArray()
    }

    /**
     * 计算候选位移 [delta] 下的归一化加权距离。
     *
     * `prev[top + delta + i]` 对齐 `next[top + i]`，比较 `contentHeight - delta` 行。
     *
     * @return 0..1000；无有效比较行时返回 [Int.MAX_VALUE]
     */
    internal fun scoreAt(
        prev: FrameSignature,
        next: FrameSignature,
        delta: Int,
        top: Int,
        contentHeight: Int,
        rowStep: Int,
    ): Int {
        val overlap = contentHeight - delta
        if (overlap <= 0) return Int.MAX_VALUE

        var sum = 0L
        var weight = 0L
        var i = 0
        while (i < overlap) {
            val w = 1 + next.texture[top + i]
            val distance = RowSignature.rowDistance(
                prev.rows[top + delta + i],
                next.rows[top + i],
            )
            sum += distance.toLong() * w
            weight += RowSignature.MAX_ROW_DISTANCE.toLong() * w
            i += rowStep
        }
        if (weight <= 0L) return Int.MAX_VALUE
        return (sum * 1000L / weight).toInt()
    }

    /** 位移对应的重叠行数（负值表示无重叠）。 */
    @JvmStatic
    fun overlapForDelta(contentHeight: Int, delta: Int): Int =
        if (delta in 0 until contentHeight) contentHeight - delta else -abs(contentHeight - delta)
}
