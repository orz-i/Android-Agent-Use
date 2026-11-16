package com.agent.use.common;

import android.os.Bundle;

/**
 * 虚拟屏托管与主屏到达事件异步回调接口。
 * 使用 oneway 异步投递，确保服务端任务栈扫描线程不会被客户端处理阻塞。
 */
oneway interface IAgentCustodyListener {
    /**
     * 主屏 (display == 0) 或已托管虚拟屏 (display == D) 出现新任务/前台切换时触发。
     *
     * Bundle 字段：
     * - "task" (Int): 任务 ID
     * - "package" (String): 顶层包名（未知时为空串）
     * - "user" (Int): 任务所属用户 ID（未知为 -1）
     * - "activity" (String?): 顶层 Activity 类名
     * - "display" (Int): 到达所在屏幕 ID
     * - "from" (Int): 此前所在屏幕 ID，-1 表示新任务 (NEW)
     * - "newTask" (Boolean): 是否为本帧新出现的任务
     * - "sameTask" (Boolean): 是否为同一主屏顶部任务内的 Activity 切换
     * - "originUid" (Int): 启动来源 UID（未知为 -1）
     * - "originPackage" (String?): 启动来源包名（未知为 null）
     * - "originConfidence" (Int): 来源置信度 (0=UNKNOWN, 1=LOW, 2=MEDIUM, 3=HIGH)
     * - "managedDisplay" (Int): 来源 UID 归属的托管屏 ID（不在任何托管屏集合内为 -1）
     * - "at" (Long): 事件发生时刻 (SystemClock.uptimeMillis)
     * - "standard" (Boolean, 辅助): 是否为标准任务（非 Home/Recents/PIP）
     * - "uid" (Int, 辅助): 到达任务在所属用户下的完整 UID（未知为 -1）
     */
    void onTaskArrived(in Bundle e);

    /**
     * 已追踪任务从窗口栈消失时触发（如中间页关闭、应用退出）。
     */
    void onTaskVanished(int taskId, int lastDisplayId, long at);
}
