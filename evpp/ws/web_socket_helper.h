/** @file ws.h
  * @brief 
  * @author teng.qing
  * @date 2021/5/21
  */

// WebSocket, v1.00 2012-09-13
//
// Description: WebSocket FRC6544 codec, written in C++.
// Homepage: http://katzarsky.github.com/WebSocket
// Author: katzarsky@gmail.com

#ifndef SAFE_EVPP_WEBSOCKET_H_
#define SAFE_EVPP_WEBSOCKET_H_

#include <assert.h>
#include <stdint.h> /* uint8_t */
#include <stdio.h> /* sscanf */
#include <ctype.h> /* isdigit */
#include <stddef.h> /* int */

// std c++
#include <vector>
#include <string>
#include <cstring>

using namespace std;

namespace evpp {
    namespace ws {

        /** @class WebSocketFrameType
          * @brief websocket帧类型
          */
        enum WebSocketFrameType {
            ERROR_FRAME = 0xFF00,       // 帧错误
            INCOMPLETE_FRAME = 0xFE00,  // 不完整的帧

            OPENING_FRAME = 0x3300,     // 握手
            CLOSING_FRAME = 0x3400,

            INCOMPLETE_TEXT_FRAME = 0x01,   // 不完整的文本
            INCOMPLETE_BINARY_FRAME = 0x02, // 不完整的二进制数据

            TEXT_FRAME = 0x81,      // 文本数据
            BINARY_FRAME = 0x82,    // 二进制数据

            PING_FRAME = 0x19,  // ping
            PONG_FRAME = 0x1A   // pong
        };

        /** @class HandshakeInfo
          * @brief 握手信息
          */
        struct HandshakeInfo {
            string resource;      // /sub
            string host;
            string origin;
            string protocol;      // Sec-WebSocket-Protocol
            string key;           // Sec-WebSocket-Key
            string version;       // Sec-WebSocket-Version
            string extensions;    // Sec-WebSocket-Extensions
        };

        /** @class ws
          * @brief
          */
        class WebSocketHelper {
        public:
            WebSocketHelper() = default;

            WebSocketHelper(const WebSocketHelper &) = delete;

            WebSocketHelper &operator=(const WebSocketHelper &) = delete;

        public:
            /**
             * @param input_frame .in. pointer to input frame
             * @param input_len .in. length of input frame
             * @return [WS_INCOMPLETE_FRAME, WS_ERROR_FRAME, WS_OPENING_FRAME]
             */

            /**@fn parseHandshake
              *@brief 获取握手信息
              *@param [in]input_frame: 缓冲区
              *@param [in]input_len: 缓冲区
              *@param [out]info: 握手信息
              *@return
              */
            WebSocketFrameType parseHandshake(const char *input_frame, int input_len, HandshakeInfo &info);

            /** @fn answerHandshake
              * @brief 获取握手响应数据
              * @param [in]info: 握手信息
              * @return 握手响应帧数据，tcp直接发送即可
              */
            string answerHandshake(const HandshakeInfo &info);

            /** @fn makeFrame
              * @brief encode
              * @param [in]msg: 裸数据
              * @param [in]msg_len: 裸数据长度
              * @param [out]buffer: 输出缓冲区
              * @param [int]buffer_len: 输出缓冲区长度
              * @return 帧长度
              */
            int makeFrame(WebSocketFrameType frame_type, const uint8_t *msg,
                          int msg_len, uint8_t *buffer, int buffer_len);

            /** @fn getFrame
              * @brief 解析客户端发来的数据，需要经过掩码处理。服务器发给客户端的不需要
              * @param [in]in_buffer: 接收缓冲区
              * @param [in]in_length: 接收缓冲区大小
              * @param [in]out_buffer: 输出缓冲区
              * @param [in]out_size: 输出缓冲区大小
              * @param [out]out_length: payload载荷数据长度
              * @param [out]use_count: 帧头数据长度+载荷数据长度，即in_buffer已使用长度
              * @return 帧类型
              */
            WebSocketFrameType getFrame(const uint8_t *in_buffer, int in_length, uint8_t *out_buffer,
                                        int out_size, int &out_length, int &use_count);

            string trim(string str);

            vector<string> explode(string theString, string theDelimiter, bool theIncludeEmptyStrings = false);
        };

    }
}

#endif //SAFE_EVPP_WEBSOCKET_H_
