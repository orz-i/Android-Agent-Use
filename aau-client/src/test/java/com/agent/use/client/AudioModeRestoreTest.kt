package com.agent.use.client

import com.agent.use.common.AudioMode
import org.junit.Assert.assertEquals
import org.junit.Test

class AudioModeRestoreTest {

    @Test
    fun testAudioModeRestoreLogic() {
        // null 或 DEFAULT 恢复时必须强制矫正为 ALLOW，防止系统静音脏状态
        assertEquals(AudioMode.ALLOW, AudioMode.calculateRestoreMode(null))
        assertEquals(AudioMode.ALLOW, AudioMode.calculateRestoreMode(AudioMode.DEFAULT))
        assertEquals(AudioMode.ALLOW, AudioMode.calculateRestoreMode(AudioMode.ALLOW))
        assertEquals(AudioMode.IGNORE, AudioMode.calculateRestoreMode(AudioMode.IGNORE))
    }
}
