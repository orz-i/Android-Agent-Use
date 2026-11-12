package com.agent.display.common.network;

import com.agent.display.common.network.NetworkCaptureConfig;
import com.agent.display.common.network.INetworkEventListener;

/**
 * 跨进程原生 CDP 风格网络流量嗅探与抓包控制接口。
 *
 * 运行在 Shell/Root 服务端守护进程或客户端 VpnService 中，
 * 支持 eBPF TLS 挂载与 VpnService 局部 TUN 代理两种捕获机制。
 */
interface INetworkCapture {

    /**
     * 启动网络捕获。
     *
     * @param config 抓包配置（目标包名、UID、抓包模式、大小限制、URL 过滤正则等）
     * @param listener 网络事件监听器（HTTP 请求、响应、数据块和异常事件）
     * @return 启动是否成功
     */
    boolean startCapture(in NetworkCaptureConfig config, in INetworkEventListener listener) = 1;

    /**
     * 停止网络捕获并释放底层资源（清理 eBPF 挂载或释放 TUN 虚拟网卡）。
     */
    void stopCapture() = 2;

    /**
     * 获取指定请求对应的完整 HTTP 响应体数据。
     *
     * @param requestId 请求唯一标识符
     * @return 响应体字节数组，若不存在或尚未接收完毕则返回 null
     */
    byte[] getResponseBody(in String requestId) = 3;

    /**
     * 获取当前生效的底层抓包模式。
     *
     * @return 0: NONE, 1: EBPF, 2: VPN_SERVICE
     */
    int getActiveMode() = 4;
}
