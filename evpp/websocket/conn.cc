/** @file web_socket_conn.h
  * @brief 
  * @author teng.qing
  * @date 2021/5/22
  */

#include "conn.h"
#include "evpp/tcp_conn.h"

namespace evpp {
    namespace websocket {

        Conn::Conn(EventLoop *loop,
                   const std::string &name,
                   evpp_socket_t sockfd,
                   const std::string &laddr,
                   const std::string &raddr,
                   uint64_t id)
                : TCPConn(loop, name, sockfd, laddr, raddr, id),
                  is_handshake_(false) {

        }

        void Conn::HandleRead() {
            assert(loop_->IsInLoopThread());

            int serrno = 0;
            ssize_t n = input_buffer_.ReadFromFD(chan_->fd(), &serrno);
            if (n > 0) {
                if (!is_handshake_) {
                    WebSocketFrameType type = helper_.parseHandshake(input_buffer_.data(),
                                                                     input_buffer_.length());
                    if (type == OPENING_FRAME) {
                        DLOG_TRACE << "this is a websocket, len=" << input_buffer_.length() << ", answer handshake";
                        string answer = helper_.answerHandshake();

                        SendInLoop((void *) answer.c_str(), answer.size());
                        input_buffer_.Reset();
                        is_handshake_ = true;
                    } else {
                        DLOG_WARN << "unknown frame type = " << type
                                  << ",websocket need handshake, close the connection.";
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
                        DLOG_TRACE << "websocket ping";
                        input_buffer_.Skip(use_count);
                    } else if (frame_type == WebSocketFrameType::TEXT_FRAME) {
                        DLOG_WARN << "not support websocket protocol:TEXT_FRAME";
                        input_buffer_.Skip(use_count);
                    } else {
                        DLOG_WARN << "not support websocket protocol:TEXT_FRAME";
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
                        delay_close_timer_ = loop_->RunAfter(close_delay_, std::bind(&Conn::DelayClose,
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

        void Conn::SendInLoop(const void *data, size_t len) {
            if (!is_handshake_) {
                LOG_WARN << "websocket not handshake,disconnect ...";
                HandleError();
                return;
            }

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

