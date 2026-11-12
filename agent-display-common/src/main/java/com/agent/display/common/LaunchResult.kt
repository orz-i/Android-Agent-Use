package com.agent.display.common

/**
 * 虚拟屏应用启动结果状态。
 *
 * 封装在虚拟屏启动应用、冷启动、链接跳转等操作的完整状态机，
 * 提供对主屏冲突、跨屏冲突、冷启动降级等边界情况的语义化表达。
 */
enum class LaunchResult(val code: Int, val description: String) {
    /** 启动成功 */
    SUCCESS(0, "启动成功"),

    /** 目标应用正在用户主屏可见使用中，为避免打扰用户已中止启动 */
    IN_USE_ON_MAIN(1, "目标应用正在主屏使用，已触发防打扰避让"),

    /** 未找到目标包的可启动入口 Activity */
    NOT_FOUND(2, "未找到目标应用入口"),

    /** 系统调用异常或底层执行失败 */
    ERROR(3, "系统底层执行异常"),

    /** 冷启动跳过：目标应用在其他屏幕上存在未结束的任务，为避免丢失用户现场已自动转为热启动 */
    COLD_IGNORED_WARM_STARTED(4, "冷启动已转为热启动（其他屏幕存在任务）"),

    /** 未找到能够响应指定 Intent 或链接的组件 */
    UNRESOLVED_INTENT(5, "未找到可处理目标链接或 Intent 的组件"),

    /** 链接被安全规则拦截（如非法的内部隐式 Action） */
    INVALID_LINK(6, "链接或动作不安全，已被拦截"),

    /** 目标应用已被其他 Agent 虚拟屏占用 */
    IN_USE_BY_OTHER_DISPLAY(7, "应用已被其他虚拟屏占用"),

    /** 指定的多用户编号（分身/工作资料）不在允许使用的列表中 */
    USER_NOT_ALLOWED(8, "指定用户无权启动目标应用");

    /** 是否代表任务已成功就绪（正常启动或降级热启动） */
    val isSuccess: Boolean
        get() = this == SUCCESS || this == COLD_IGNORED_WARM_STARTED

    /** 是否发生了前台/主屏冲突 */
    val isConflict: Boolean
        get() = this == IN_USE_ON_MAIN || this == IN_USE_BY_OTHER_DISPLAY

    companion object {
        @JvmStatic
        fun fromCode(code: Int): LaunchResult =
            values().firstOrNull { it.code == code } ?: ERROR
    }
}
