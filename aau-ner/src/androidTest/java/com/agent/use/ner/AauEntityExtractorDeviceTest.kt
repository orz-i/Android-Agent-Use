package com.agent.use.ner

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs the real model. Needs the assets from `tools/import_ner_assets.py`, which are not
 * committed, so a checkout without them skips instead of failing.
 */
@RunWith(AndroidJUnit4::class)
class AauEntityExtractorDeviceTest {

    private val assets get() = InstrumentationRegistry.getInstrumentation().targetContext.assets

    @Before
    fun requireModel() {
        assumeTrue(AauEntityExtractor.supported)
        val present = runCatching { assets.open("aau_ner_v1.tflite").close() }.isSuccess
        assumeTrue("Run aau-ner/tools/import_ner_assets.py to provision the NER assets", present)
    }

    private fun extract(text: String): List<EntitySpan> =
        AauEntityExtractor(assets).use { it.extract(text) }

    @Test
    fun extractsAddressAndNameFromASentence() {
        val text = "明天下午三点去北京朝阳区望京SOHO找张三"
        val spans = extract(text)
        assertTrue("address in $spans", spans.any { it.type == EntityType.Address && it.text == "北京朝阳区望京SOHO" })
        assertTrue("person in $spans", spans.any { it.type == EntityType.Person && it.text == "张三" })
        spans.forEach { assertEquals(it.text, text.substring(it.start, it.end)) }
    }

    @Test
    fun extractsExpressNumberAndPhone() {
        val spans = extract("我的快递单号SF1234567890，电话13800138000")
        assertTrue("express in $spans", spans.any { it.type == EntityType.ExpressNumber && it.text == "SF1234567890" })
        assertTrue("phone in $spans", spans.any { it.type == EntityType.Phone && it.text == "13800138000" })
    }

    @Test
    fun extractsAddressAfterALabel() {
        val spans = extract("订单号 1234567890123 收货地址 上海市浦东新区世纪大道100号")
        assertTrue("address in $spans", spans.any { it.type == EntityType.Address && it.text == "上海市浦东新区世纪大道100号" })
    }

    @Test
    fun keepsOffsetsAlignedOnTextLongerThanOneWindow() {
        val filler = "这是一段没有实体的说明文字。".repeat(40) // 560 characters: two windows
        val text = filler + "收货人 张三 13800138000 地址 上海市浦东新区世纪大道100号"
        val spans = extract(text)
        assertTrue("person in $spans", spans.any { it.type == EntityType.Person && it.text == "张三" })
        assertTrue("address in $spans", spans.any { it.type == EntityType.Address && it.text == "上海市浦东新区世纪大道100号" })
        spans.forEach { assertEquals(it.text, text.substring(it.start, it.end)) }
        assertTrue("the entity sits past the first window", spans.all { it.start >= AauEntityExtractor.MAX_CHARS })
    }

    @Test
    fun repeatedCallsOnOneInterpreterAgree() {
        // The graph keeps its weights in variable tensors; if the runtime carried state
        // between invocations the second call would drift.
        val text = "明天下午三点去北京朝阳区望京SOHO找张三"
        AauEntityExtractor(assets).use { extractor ->
            val first = extractor.extract(text)
            assertTrue("expected spans, got $first", first.isNotEmpty())
            repeat(3) { assertEquals(first, extractor.extract(text)) }
        }
    }

    @Test
    fun oneWindowStaysWellUnderASecond() {
        val text = "明天下午三点去北京朝阳区望京SOHO找张三"
        AauEntityExtractor(assets).use { extractor ->
            repeat(2) { extractor.extract(text) } // warm up
            val started = System.nanoTime()
            repeat(5) { extractor.extract(text) }
            val millis = (System.nanoTime() - started) / 5 / 1_000_000
            Log.i("AauEntityExtractor", "one window: $millis ms")
            assertTrue("one window took $millis ms", millis < 1_000)
        }
    }
}
