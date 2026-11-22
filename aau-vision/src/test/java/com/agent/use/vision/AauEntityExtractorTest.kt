package com.agent.use.vision

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AauEntityExtractorTest {

    private val labels = Labels.of(
        "O 0",
        "B-NAME 1",
        "I-NAME 2",
        "E-NAME 3",
        "S-NAME 4",
        "B-PHONE 5",
        "E-PHONE 6",
    )

    private fun spans(tags: IntArray, text: String): List<EntitySpan> {
        val out = ArrayList<EntitySpan>()
        decode(tags, labels, 0, tags.size, text, out)
        return out
    }

    @Test
    fun decodeJoinsBeginInsideEndIntoOneSpan() {
        val decoded = spans(intArrayOf(0, 1, 2, 3, 0, 0), "x张三丰yz")
        assertEquals(listOf(EntitySpan(EntityType.Person, 1, 4, "张三丰")), decoded)
    }

    @Test
    fun decodeAcceptsSingleCharacterEntity() {
        val decoded = spans(intArrayOf(4, 0), "张y")
        assertEquals(listOf(EntitySpan(EntityType.Person, 0, 1, "张")), decoded)
    }

    @Test
    fun decodeOpensSpanWhenInsideOrEndArrivesWithoutBegin() {
        assertEquals(listOf(EntitySpan(EntityType.Person, 0, 2, "张三")), spans(intArrayOf(2, 3), "张三"))
        assertEquals(listOf(EntitySpan(EntityType.Person, 0, 1, "张")), spans(intArrayOf(3), "张"))
        assertEquals(listOf(EntitySpan(EntityType.Person, 0, 2, "张三")), spans(intArrayOf(2, 2), "张三"))
    }

    @Test
    fun decodeKeepsAdjacentEntitiesOfOneTypeApart() {
        val decoded = spans(intArrayOf(1, 3, 1, 3), "张三李四")
        assertEquals(
            listOf(
                EntitySpan(EntityType.Person, 0, 2, "张三"),
                EntitySpan(EntityType.Person, 2, 4, "李四"),
            ),
            decoded,
        )
    }

    @Test
    fun decodeSplitsWhenTheTypeChangesMidStream() {
        val decoded = spans(intArrayOf(1, 5, 6), "张123")
        assertEquals(
            listOf(
                EntitySpan(EntityType.Person, 0, 1, "张"),
                EntitySpan(EntityType.Phone, 1, 3, "12"),
            ),
            decoded,
        )
    }

    @Test
    fun decodeIgnoresPaddingAndUnknownIds() {
        assertTrue(spans(intArrayOf(0, 0, 999, -1), "abcd").isEmpty())
    }

    @Test
    fun windowsKeepShortTextWhole() {
        assertEquals(listOf(0 until 10), windows("0123456789", AauEntityExtractor.MAX_CHARS))
        assertTrue(windows("", AauEntityExtractor.MAX_CHARS).isEmpty())
        assertEquals(listOf(0 until AauEntityExtractor.MAX_CHARS), windows("a".repeat(AauEntityExtractor.MAX_CHARS), AauEntityExtractor.MAX_CHARS))
    }

    @Test
    fun windowsCoverEveryCharacterExactlyOnce() {
        val text = "a".repeat(2000)
        val ranges = windows(text, AauEntityExtractor.MAX_CHARS)
        assertEquals(0, ranges.first().first)
        assertEquals(text.length, ranges.last().last + 1)
        ranges.zipWithNext().forEach { (a, b) -> assertEquals(a.last + 1, b.first) }
        assertTrue(ranges.all { it.last - it.first + 1 <= AauEntityExtractor.MAX_CHARS })
    }

    @Test
    fun windowsPreferWhitespaceInTheLastQuarter() {
        val text = "a".repeat(400) + " " + "b".repeat(400)
        val ranges = windows(text, AauEntityExtractor.MAX_CHARS)
        assertEquals(0 until 401, ranges.first())
    }

    @Test
    fun windowsStillAdvanceWithoutWhitespace() {
        val ranges = windows("字".repeat(1500), AauEntityExtractor.MAX_CHARS)
        assertEquals(3, ranges.size)
        assertTrue(ranges.all { it.last - it.first + 1 <= AauEntityExtractor.MAX_CHARS })
    }

    @Test
    fun vocabularyMapsCharactersWhitespaceAndUnknowns() {
        val vocabulary = Vocabulary.of("中 7", "a 42", "[PAD] 0", "[UNK] 9", "[SPACE] 8")
        assertEquals(7, vocabulary.idOf('中'))
        assertEquals(42, vocabulary.idOf('a'))
        assertEquals(9, vocabulary.idOf(' ')) // the table has no literal space; callers use [SPACE]
        assertEquals(9, vocabulary.idOf('\uD83D'))
        assertEquals(8, vocabulary.space)
        assertEquals(9, vocabulary.unknown)
    }

    @Test
    fun labelsSkipPaddingAndUnknownClasses() {
        assertEquals('O', labels.prefixOf(0))
        assertEquals('B', labels.prefixOf(1))
        assertEquals(EntityType.Person, labels.typeOf(1))
        assertEquals('O', labels.prefixOf(99))
        assertEquals(null, labels.typeOf(99))
    }

    @Test
    fun extractEncodesSpacesAndReturnsAbsoluteOffsets() {
        // A stand-in for the model: 张 opens a name, 三 closes it, everything else is O.
        val vocabulary = Vocabulary.of("张 1", "三 2", "联 3", "系 4", "[PAD] 0", "[UNK] 9", "[SPACE] 8")
        var seen = IntArray(0)
        val tagger = TokenTagger { tokens ->
            seen = tokens.copyOf()
            IntArray(tokens.size) { i ->
                when (tokens[i]) {
                    1 -> 1
                    2 -> 3
                    else -> 0
                }
            }
        }
        AauEntityExtractor(vocabulary, labels, tagger).use { extractor ->
            assertEquals(listOf(EntitySpan(EntityType.Person, 3, 5, "张三")), extractor.extract("联系 张三"))
            assertEquals(8, seen[2]) // the space between 联系 and 张三 became [SPACE], not [UNK]
        }
    }

    @Test
    fun extractReportsOffsetsRelativeToTheCallerStringAcrossWindows() {
        val vocabulary = Vocabulary.of("张 1", "三 2", "a 3", "[PAD] 0", "[UNK] 9", "[SPACE] 8")
        val tagger = TokenTagger { tokens ->
            IntArray(tokens.size) { i ->
                when (tokens[i]) {
                    1 -> 1
                    2 -> 3
                    else -> 0
                }
            }
        }
        val text = "a".repeat(600) + "张三"
        AauEntityExtractor(vocabulary, labels, tagger).use { extractor ->
            val spans = extractor.extract(text)
            assertEquals(1, spans.size)
            assertEquals(EntitySpan(EntityType.Person, 600, 602, "张三"), spans.single())
            assertEquals("张三", text.substring(spans.single().start, spans.single().end))
        }
    }

    @Test(expected = IllegalStateException::class)
    fun extractAfterCloseFails() {
        val vocabulary = Vocabulary.of("a 3", "[PAD] 0", "[UNK] 9", "[SPACE] 8")
        val extractor = AauEntityExtractor(vocabulary, labels) { IntArray(it.size) }
        extractor.close()
        extractor.extract("a")
    }
}
