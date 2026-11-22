package com.agent.use.ner

import android.content.res.AssetManager
import java.io.Closeable
import java.io.File
import kotlin.math.min

internal const val MODEL = "aau_ner_v1"
internal const val VOCAB = "aau_ner_v1.vocab"
internal const val LABELS = "aau_ner_v1.labels"

/**
 * Character-level named entity recognition over already-extracted screen text.
 *
 * The model is a bidirectional LSTM: 512 character ids in, one label id per character out.
 * It runs on CPU, needs no network, and returns character offsets into the caller's string,
 * so it composes with accessibility node text or OCR output. Call off the main thread;
 * one call takes tens of milliseconds. The caller owns the text and decides what to do with it.
 *
 * The model emits label ids only (the argmax is part of the graph), so spans carry no
 * probability. Text longer than [MAX_CHARS] is split into windows at whitespace.
 */
class AauEntityExtractor internal constructor(
    private val vocabulary: Vocabulary,
    private val labels: Labels,
    private val model: TokenTagger,
) : Closeable {
    constructor(assets: AssetManager) : this(
        Vocabulary.fromAssets(assets, VOCAB),
        Labels.fromAssets(assets, LABELS),
        createModel(assets),
    )

    private var closed = false

    /** Returns the spans in text order. Empty when nothing is recognised. */
    @Synchronized
    fun extract(text: String): List<EntitySpan> {
        check(!closed)
        if (text.isEmpty()) return emptyList()
        val spans = ArrayList<EntitySpan>()
        val tokens = IntArray(MAX_CHARS)
        for (window in windows(text, MAX_CHARS)) {
            tokens.fill(PAD)
            for (i in window) {
                val c = text[i]
                tokens[i - window.first] = if (c.isWhitespace()) vocabulary.space else vocabulary.idOf(c)
            }
            val length = window.last + 1 - window.first
            val tags = model.classify(tokens)
            check(tags.size >= length) { "NER model returned ${tags.size} labels for $length characters" }
            decode(tags, labels, window.first, length, text, spans)
        }
        return spans
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        model.close()
    }

    companion object {
        /** Model input width, also the window size used for longer text. */
        const val MAX_CHARS = 512

        /** False when the ABI has no LiteRT runtime, which is the only backend for this graph. */
        val supported: Boolean get() = CpuTextModel.isSupported()

        /**
         * 从磁盘装载，给没有本 APK assets 的进程用（`app_process` 守护进程）。
         * 三个文件分别是模型、词表、标签表；路径和资产名无关，部署脚本放哪就从哪读。
         */
        fun fromFiles(model: File, vocabulary: File, labels: File): AauEntityExtractor = AauEntityExtractor(
            Vocabulary.ofFile(vocabulary),
            Labels.ofFile(labels),
            CpuTextModel.fromFile(model),
        )

        private fun createModel(assets: AssetManager): TokenTagger {
            require(CpuTextModel.isSupported()) {
                "NER needs the LiteRT runtime, which is not packaged for this ABI"
            }
            return CpuTextModel(assets, MODEL)
        }
    }
}

internal const val PAD = 0

/** Runs one 512-wide window of character ids and returns one label id per position. */
internal fun interface TokenTagger : Closeable {
    fun classify(tokens: IntArray): IntArray

    override fun close() = Unit
}

/**
 * The model's character table: one BMP code point per id, plus the named tokens.
 * Ids come from the asset, never from this file, so a model refresh only needs a re-import.
 */
internal class Vocabulary private constructor(lines: List<String>) {
    private val packed: LongArray

    /** Id of `[UNK]`, used for anything the table does not cover. */
    val unknown: Int

    /** Id of `[SPACE]`. The table has no literal space, only this token. */
    val space: Int

    init {
        val points = ArrayList<Int>(lines.size)
        val ids = ArrayList<Int>(lines.size)
        val names = HashMap<String, Int>(4)
        for (line in lines) {
            val cut = line.lastIndexOfAny(DELIMITERS)
            if (cut <= 0) continue
            val token = line.substring(0, cut).trim()
            val id = line.substring(cut + 1).trim().toIntOrNull() ?: continue
            if (token.length == 1) {
                points += token[0].code
                ids += id
            } else if (token.length > 1 && token[0] == '[' && token.last() == ']') {
                names[token] = id
            }
        }
        require(points.isNotEmpty()) { "Empty character table" }
        packed = LongArray(points.size) { (points[it].toLong() shl 32) or ids[it].toLong() }
        packed.sort()
        unknown = names["[UNK]"] ?: error("Character table has no [UNK] token")
        space = names["[SPACE]"] ?: error("Character table has no [SPACE] token")
    }

    /** Binary search over (code point, id) pairs packed into one long each. */
    fun idOf(c: Char): Int {
        val key = c.code
        var low = 0
        var high = packed.size - 1
        while (low <= high) {
            val mid = (low + high) ushr 1
            val entry = packed[mid]
            val point = (entry ushr 32).toInt()
            when {
                point < key -> low = mid + 1
                point > key -> high = mid - 1
                else -> return (entry and 0xFFFFFFFFL).toInt()
            }
        }
        return unknown
    }

    companion object {
        private val DELIMITERS = charArrayOf('\t', ' ')

        fun fromAssets(assets: AssetManager, name: String): Vocabulary =
            Vocabulary(assets.open(name).bufferedReader().use { it.readLines() })

        fun ofFile(file: File): Vocabulary = Vocabulary(file.bufferedReader().use { it.readLines() })

        internal fun of(vararg lines: String) = Vocabulary(lines.toList())
    }
}

/**
 * Maps label ids to the BIOES tag and the entity class. Unknown names become [EntityType.Other]
 * rather than failing: a stale mapping should degrade, not break screen reading.
 */
internal class Labels private constructor(lines: List<String>) {
    private val prefixes: CharArray
    private val types: Array<EntityType?>

    init {
        val entries = lines.mapNotNull { line ->
            val cut = line.lastIndexOfAny(DELIMITERS)
            if (cut <= 0) return@mapNotNull null
            val name = line.substring(0, cut).trim()
            val id = line.substring(cut + 1).trim().toIntOrNull() ?: return@mapNotNull null
            id to name
        }
        require(entries.isNotEmpty()) { "Empty label table" }
        val size = entries.maxOf { it.first } + 1
        prefixes = CharArray(size) { 'O' }
        types = arrayOfNulls(size)
        for ((id, name) in entries) {
            if (id <= 0 || name.length < 3 || name[1] != '-') continue // [PAD] and "O" stay as 'O'
            val prefix = name[0]
            if (prefix !in "BIES") continue
            prefixes[id] = prefix
            types[id] = typeOf(name.substring(2))
        }
    }

    fun prefixOf(id: Int): Char = if (id in prefixes.indices) prefixes[id] else 'O'

    fun typeOf(id: Int): EntityType? = if (id in types.indices) types[id] else null

    companion object {
        private val DELIMITERS = charArrayOf('\t', ' ')

        fun fromAssets(assets: AssetManager, name: String): Labels =
            Labels(assets.open(name).bufferedReader().use { it.readLines() })

        fun ofFile(file: File): Labels = Labels(file.bufferedReader().use { it.readLines() })

        internal fun of(vararg lines: String) = Labels(lines.toList())

        private fun typeOf(suffix: String): EntityType = when (suffix) {
            "NAME" -> EntityType.Person
            "PHONE" -> EntityType.Phone
            "STANDARD_ADDRESS" -> EntityType.Address
            "ORAL_STANDARD_ADDRESS" -> EntityType.OralAddress
            "ORAL_WIDE_ADDRESS" -> EntityType.OralWideAddress
            "ADMINISTRATIVE_DIVISION" -> EntityType.AdministrativeDivision
            "COMPANY" -> EntityType.Company
            "OTHER_ORGANIZATION" -> EntityType.Organization
            "GOVERNMENT_ORGANIZATION" -> EntityType.Government
            "SCHOOL" -> EntityType.School
            "HEALTHCARE" -> EntityType.Healthcare
            "RESTAURANT" -> EntityType.Restaurant
            "HOTEL" -> EntityType.Hotel
            "SUPERMARKET" -> EntityType.Supermarket
            "ENTERTAINMENT" -> EntityType.Entertainment
            "SPOT" -> EntityType.Spot
            "OFFICE_BUILDING" -> EntityType.OfficeBuilding
            "BANK_NAME" -> EntityType.Bank
            "BANK_ID" -> EntityType.BankCard
            "EXPRESS_NUMBER" -> EntityType.ExpressNumber
            "FLIGHT_NUMBER" -> EntityType.FlightNumber
            "TRAIN_NUMBER" -> EntityType.TrainNumber
            "SUBWAY_STATION" -> EntityType.SubwayStation
            "BUS_STATION" -> EntityType.BusStation
            "AIRPORT_TRAIN" -> EntityType.AirportTrain
            "OIL_ELECTRIC" -> EntityType.OilElectric
            "OTHER_ADDRESS" -> EntityType.OtherAddress
            else -> EntityType.Other
        }
    }
}

/**
 * Splits text into model-sized windows, preferring a whitespace break in the last quarter
 * so that a sentence boundary, not an entity, tends to land on the cut.
 */
internal fun windows(text: CharSequence, max: Int): List<IntRange> {
    require(max > 0)
    if (text.isEmpty()) return emptyList()
    val result = ArrayList<IntRange>(text.length / max + 1)
    var start = 0
    while (start < text.length) {
        var end = min(start + max, text.length)
        if (end < text.length) {
            val floor = start + max * 3 / 4
            for (i in end - 1 downTo floor) {
                if (text[i].isWhitespace()) {
                    end = i + 1
                    break
                }
            }
        }
        result += start until end
        start = end
    }
    return result
}

/**
 * Turns per-character BIOES ids into spans. A tag that starts mid-entity (I or E without B)
 * opens a new span instead of dropping characters, because OCR and accessibility text rarely
 * agree on where a line starts.
 */
internal fun decode(
    tags: IntArray,
    labels: Labels,
    offset: Int,
    length: Int,
    text: String,
    into: MutableList<EntitySpan>,
) {
    var start = -1
    var current: EntityType? = null

    fun emit(from: Int, to: Int, type: EntityType) {
        if (to > from) into += EntitySpan(type, offset + from, offset + to, text.substring(offset + from, offset + to))
    }

    fun flush(endExclusive: Int) {
        val type = current
        if (start >= 0 && type != null) emit(start, endExclusive, type)
        start = -1
        current = null
    }

    for (i in 0 until length) {
        val id = tags[i]
        val type = labels.typeOf(id)
        when (labels.prefixOf(id)) {
            'S' -> {
                flush(i)
                if (type != null) emit(i, i + 1, type)
            }
            'B' -> {
                flush(i)
                if (type != null) {
                    start = i
                    current = type
                }
            }
            'I' -> if (type != null && type != current) {
                flush(i)
                start = i
                current = type
            }
            'E' -> if (type != null) {
                if (type != current) {
                    flush(i)
                    emit(i, i + 1, type)
                } else {
                    flush(i + 1)
                }
            }
            else -> flush(i)
        }
    }
    flush(length)
}
