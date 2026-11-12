package com.agent.display.common.network;

import com.agent.display.common.network.HttpRequestEvent;
import com.agent.display.common.network.HttpResponseEvent;

/**
 * 原生网络事件回调监听接口（对应 Chrome DevTools Protocol Network Domain Events）。
 *
 * 底层抓包引擎（eBPF 或 VpnService）在拦截到网络流量时，通过此接口向订阅方投递事件。
 */
interface INetworkEventListener {

    /**
     * 当 HTTP 请求即将发送时触发（对应 CDP Network.requestWillBeSent）。
     *
     * @param request 封装请求行、URL、Method、Headers、POST 数据等
     */
    void onRequestWillBeSent(in HttpRequestEvent request) = 1;

    /**
     * 当 HTTP 响应头接收完成时触发（对应 CDP Network.responseReceived）。
     *
     * @param response 封装状态码、状态描述、响应头、MIME 类型、内容长度等
     */
    void onResponseReceived(in HttpResponseEvent response) = 2;

    /**
     * 当接收到分块流式数据时触发（对应 CDP Network.dataReceived）。
     *
     * @param requestId 对应的请求标识符
     * @param chunk 当前收到的数据块字节
     */
    void onDataChunkReceived(in String requestId, in byte[] chunk) = 3;

    /**
     * 当请求或响应处理发生网络异常、解析错误或链路断开时触发（对应 CDP Network.loadingFailed）。
     *
     * @param requestId 对应的请求标识符
     * @param errorMsg 错误描述信息
     */
    void onErrorOccurred(in String requestId, in String errorMsg) = 4;
}
