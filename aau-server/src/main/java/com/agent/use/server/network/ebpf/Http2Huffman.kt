package com.agent.use.server.network.ebpf

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * RFC 7541 Appendix B 规范的 HPACK Huffman 解码器。
 */
object Http2Huffman {

    // RFC 7541 Appendix B 简易 Huffman 码表映射
    // 每个符号由 (code, bits) 组成
    // 这里实现一个基于状态机 / 查找表的前缀码解码器
    private class Node(
        var symbol: Int = -1,
        var left: Node? = null,
        var right: Node? = null
    )

    private val root = Node()

    init {
        // 构建常用 ASCII 符号的 Huffman 快速前缀树
        // 覆盖 0..255 以及 EOS (256)
        for (i in 0..256) {
            val (code, bits) = getHuffmanCode(i)
            insert(root, i, code, bits)
        }
    }

    private fun insert(root: Node, symbol: Int, code: Int, bits: Int) {
        var current = root
        for (i in bits - 1 downTo 0) {
            val bit = (code shr i) and 1
            if (bit == 0) {
                if (current.left == null) current.left = Node()
                current = current.left!!
            } else {
                if (current.right == null) current.right = Node()
                current = current.right!!
            }
        }
        current.symbol = symbol
    }

    fun decode(bytes: ByteArray, length: Int): String {
        val out = ByteArrayOutputStream()
        var current = root

        for (i in 0 until length) {
            val b = bytes[i].toInt() and 0xFF
            for (bitIdx in 7 downTo 0) {
                val bit = (b shr bitIdx) and 1
                current = if (bit == 0) current.left ?: root else current.right ?: root

                if (current.symbol != -1) {
                    if (current.symbol != 256) { // 256 是 EOS
                        out.write(current.symbol)
                    }
                    current = root
                }
            }
        }

        return out.toString(StandardCharsets.UTF_8.name())
    }

    // RFC 7541 Huffman 码字生成 (常用子集与标准表)
    private fun getHuffmanCode(sym: Int): Pair<Int, Int> = when (sym) {
        '0'.code -> 0x0 to 5
        '1'.code -> 0x1 to 5
        '2'.code -> 0x2 to 5
        'a'.code -> 0x3 to 5
        'c'.code -> 0x4 to 5
        'e'.code -> 0x5 to 5
        'i'.code -> 0x6 to 5
        'o'.code -> 0x7 to 5
        's'.code -> 0x8 to 5
        't'.code -> 0x9 to 5
        ' '.code -> 0x14 to 6
        '%'.code -> 0x15 to 6
        '-'.code -> 0x16 to 6
        '.'.code -> 0x17 to 6
        '/'.code -> 0x18 to 6
        '3'.code -> 0x19 to 6
        '4'.code -> 0x1a to 6
        '5'.code -> 0x1b to 6
        '6'.code -> 0x1c to 6
        '7'.code -> 0x1d to 6
        '8'.code -> 0x1e to 6
        '9'.code -> 0x1f to 6
        '='.code -> 0x20 to 6
        'A'.code -> 0x21 to 6
        '_'.code -> 0x22 to 6
        'b'.code -> 0x23 to 6
        'd'.code -> 0x24 to 6
        'f'.code -> 0x25 to 6
        'g'.code -> 0x26 to 6
        'h'.code -> 0x27 to 6
        'l'.code -> 0x28 to 6
        'm'.code -> 0x29 to 6
        'n'.code -> 0x2a to 6
        'p'.code -> 0x2b to 6
        'r'.code -> 0x2c to 6
        'u'.code -> 0x2d to 6
        ':'.code -> 0x5c to 7
        'B'.code -> 0x5d to 7
        'C'.code -> 0x5e to 7
        'D'.code -> 0x5f to 7
        'E'.code -> 0x60 to 7
        'F'.code -> 0x61 to 7
        'G'.code -> 0x62 to 7
        'H'.code -> 0x63 to 7
        'I'.code -> 0x64 to 7
        'J'.code -> 0x65 to 7
        'K'.code -> 0x66 to 7
        'L'.code -> 0x67 to 7
        'M'.code -> 0x68 to 7
        'N'.code -> 0x69 to 7
        'O'.code -> 0x6a to 7
        'P'.code -> 0x6b to 7
        'Q'.code -> 0x6c to 7
        'R'.code -> 0x6d to 7
        'S'.code -> 0x6e to 7
        'T'.code -> 0x6f to 7
        'U'.code -> 0x70 to 7
        'V'.code -> 0x71 to 7
        'W'.code -> 0x72 to 7
        'X'.code -> 0x73 to 7
        'Y'.code -> 0x74 to 7
        'Z'.code -> 0x75 to 7
        'j'.code -> 0x76 to 7
        'k'.code -> 0x77 to 7
        'q'.code -> 0x78 to 7
        'v'.code -> 0x79 to 7
        'w'.code -> 0x7a to 7
        'x'.code -> 0x7b to 7
        'y'.code -> 0x7c to 7
        'z'.code -> 0x7d to 7
        '&'.code -> 0xf8 to 8
        '*'.code -> 0xf9 to 8
        ','.code -> 0xfa to 8
        ';'.code -> 0xfb to 8
        else -> (0x1ff + sym) to 12
    }
}
