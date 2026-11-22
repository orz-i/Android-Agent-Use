package com.agent.use.server

import com.agent.use.ner.AauEntityExtractor
import java.io.File

/**
 * 在裸 `app_process` 进程里把 NER 从头跑一遍：加载 LiteRT、读磁盘上的模型、抽两个句子。
 *
 * ```
 * adb push aau_ner_v1.* /data/local/tmp/ner/
 * adb push libLiteRt.so /data/local/tmp/ner/
 * adb shell "CLASSPATH=/data/local/tmp/aau-server.jar app_process /system/bin \
 *   com.agent.use.server.NerSelfCheck /data/local/tmp/ner"
 * ```
 *
 * 输出每一句的实体与耗时；库或资产缺了就说明缺哪一样，不抛。
 */
object NerSelfCheck {
    @JvmStatic
    fun main(args: Array<String>) {
        val dir = File(if (args.isNotEmpty()) args[0] else "/data/local/tmp/ner")
        val loaded = NativeLibraries.loadLiteRt()
        println("dir=${dir.absolutePath} liteRt=$loaded abiSupported=${AauEntityExtractor.supported}")
        if (!loaded) return

        val model = File(dir, "aau_ner_v1.tflite")
        val vocabulary = File(dir, "aau_ner_v1.vocab")
        val labels = File(dir, "aau_ner_v1.labels")
        if (!model.isFile || !vocabulary.isFile || !labels.isFile) {
            println("missing ${listOf(model, vocabulary, labels).filterNot { it.isFile }}")
            return
        }

        try {
            AauEntityExtractor.fromFiles(model, vocabulary, labels).use { extractor ->
                for (text in SENTENCES) {
                    val started = System.nanoTime()
                    val spans = extractor.extract(text)
                    val millis = (System.nanoTime() - started) / 1_000_000
                    println("$millis ms  $text")
                    spans.forEach { println("    ${it.type} [${it.start},${it.end}) ${it.text}") }
                }
            }
        } catch (t: Throwable) {
            println("FAILED ${t.javaClass.name}: ${t.message}")
            t.printStackTrace(System.out)
        }
    }

    private val SENTENCES = listOf(
        "明天下午三点去北京朝阳区望京SOHO找张三",
        "我的快递单号SF1234567890，电话13800138000",
    )
}
