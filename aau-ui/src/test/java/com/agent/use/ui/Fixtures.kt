package com.agent.use.ui

/** 一屏里常见的三种节点，测试里按名字造一屏用。 */
fun button(ref: String, name: String, y: Int = 500) =
    UiElement(ref, "button", name, 540, y * 24 / 10, listOf(0, y - 40, 999, y + 40), null, true, false, false)

fun label(ref: String, name: String, y: Int = 200) =
    UiElement(ref, "text", name, 540, y * 24 / 10, listOf(0, y - 40, 999, y + 40), null, false, false, false)

fun field(ref: String, name: String, y: Int = 900, hint: Boolean = true) =
    UiElement(ref, "edit", name, 540, y * 24 / 10, listOf(0, y - 40, 999, y + 40), null, true, true, false, hint = hint)
