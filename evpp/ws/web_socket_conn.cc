/** @file web_socket_conn.h
  * @brief 
  * @author teng.qing
  * @date 2021/5/22
  */

#include "web_socket_conn.h"
#include "evpp/tcp_conn.h"

namespace evpp {
    namespace ws {

        WebSocketConn::WebSocketConn(EventLoop *loop,
                                     const std::string &name,
                                     evpp_socket_t sockfd,
                                     const std::string &laddr,
                                     const std::string &raddr,
                                     uint64_t id)
                : TCPConn(loop, name, sockfd, laddr, raddr, id),
                  is_handshake_(false) {

        }

        void WebSocketConn::HandleRead() {
            assert(loop_->IsInLoopThread());

            int serrno = 0;
            ssize_t n = input_buffer_.ReadFromFD(chan_->fd(), &serrno);
            if (n > 0) {
                if (!is_handshake_) {
                    HandshakeInfo info;
                    WebSocketFrameType type = helper_.parseHandshake(input_buffer_.data(),
                                                                     input_buffer_.length(), info);
                    if (type == OPENING_FRAME) {
                        DLOG_TRACE << "websocket do handshake, len=" << input_buffer_.length()
                                   << ",path=" << info.resource
                                   << ",Sec-WebSocket-Key=" << info.key
                                   << ",Sec-WebSocket-Version=" << info.version
                                   << ",Sec-WebSocket-Protocol=" << info.protocol
                                   << ",Sec-WebSocket-Extensions=" << info.extensions;
                        string answer = helper_.answerHandshake(info);
                        // raw data
                        TCPConn::SendInLoop((void *) answer.c_str(), answer.size());
                        input_buffer_.Reset();
                        is_handshake_ = true;
                    } else {
                        DLOG_WARN << "unknown frame type = " << type
                                  << ",ws need handshake, close the connection.";
                        HandleError();
                    }
                } else {
                    // ensure out buffer capacity
                    input_frame_buffer_.EnsureWritableBytes(input_buffer_.capacity());

                    // decode client data to frame
                    int use_count = 0;
                    int frame_len = 0;
                    auto frame_type = helper_.getFrame(reinterpret_cast<const uint8_t *>(input_buffer_.data()),
                                                       input_buffer_.length(),
                                                       reinterpret_cast<uint8_t *>(input_frame_buffer_.WriteBegin()),
                                                       input_frame_buffer_.capacity(),
                                                       frame_len, use_count);
                    if (frame_type == WebSocketFrameType::BINARY_FRAME) {
                        input_buffer_.Skip(use_count);
                        input_frame_buffer_.WriteBytes(frame_len);

                        msg_fn_(shared_from_this(), &input_frame_buffer_);
                    } else if (frame_type == WebSocketFrameType::PING_FRAME) {// ping
                        DLOG_TRACE << "ws ping";
                        input_buffer_.Skip(use_count);
                    } else if (frame_type == WebSocketFrameType::TEXT_FRAME) {
                        DLOG_WARN << "not support ws protocol:TEXT_FRAME";
                        input_buffer_.Skip(use_count);
                    } else {
                        DLOG_WARN << "not support ws protocol:TEXT_FRAME";
                        input_buffer_.Skip(use_count);
                    }
                }

            } else if (n == 0) {
                if (type() == kOutgoing) {
                    // This is an outgoing connection, we own it and it's done. so close it
                    DLOG_TRACE << "fd=" << fd_ << ". We read 0 bytes and close the socket.";
                    status_ = kDisconnecting;
                    HandleClose();
                } else {
                    // Fix the half-closing problem : https://github.com/chenshuo/muduo/pull/117

                    chan_->DisableReadEvent();
                    if (close_delay_.IsZero()) {
                        DLOG_TRACE << "channel (fd=" << chan_->fd() << ") DisableReadEvent. delay time "
                                   << close_delay_.Seconds() << "s. We close this connection immediately";
                        DelayClose();
                    } else {
                        // This is an incoming connection, we need to preserve the
                        // connection for a while so that we can reply to it.
                        // And we set a timer to close the connection eventually.
                        DLOG_TRACE << "channel (fd=" << chan_->fd()
                                   << ") DisableReadEvent. And set a timer to delay close this TCPConn, delay time "
                                   << close_delay_.Seconds() << "s";
                        delay_close_timer_ = loop_->RunAfter(close_delay_, std::bind(&WebSocketConn::DelayClose,
                                                                                     shared_from_this())); // TODO leave it to user layer close.
                    }
                }
            } else {
                if (EVUTIL_ERR_RW_RETRIABLE(serrno)) {
                    DLOG_TRACE << "errno=" << serrno << " " << strerror(serrno);
                } else {
                    DLOG_TRACE << "errno=" << serrno << " " << strerror(serrno)
                               << " We are closing this connection now.";
                    HandleError();
                }
            }
        }

        void WebSocketConn::SendInLoop(const void *data, size_t len) {
            // 4: normal len
            // 6: Extended payload length
            // 4: Masking-key
            const int kMaxWebSocketHeaderLen = 14;
            int bufLen = static_cast<int>(len) + kMaxWebSocketHeaderLen;

            // check
            output_buffer_.EnsureWritableBytes(bufLen);

            int out_len = helper_.makeFrame(BINARY_FRAME, (unsigned char *) data, len,
                                            reinterpret_cast<uint8_t *>(output_buffer_.WriteBegin()), bufLen);
            assert(out_len <= bufLen);
            TCPConn::SendInLoop(output_buffer_.data(), out_len);
            output_buffer_.Reset();
        }

    }
}

