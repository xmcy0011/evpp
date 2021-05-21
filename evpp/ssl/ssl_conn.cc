/** @file ssl_conn.h
  * @brief 
  * @author teng.qing
  * @date 2021/5/21
  */

#include "ssl_conn.h"
#include "evpp/fd_channel.h"

namespace evpp {
    namespace ssl {

        SSLConn::SSLConn(EventLoop *loop, const std::string &name, int sockfd, const std::string &laddr,
                         const std::string &raddr, uint64_t id, SSL_CTX *ctx, SSL *ssl)
                : TCPConn(loop, name, sockfd, laddr, raddr, id),
                  ssl_(ssl),
                  ssl_ctx_(ctx) {
            DLOG_TRACE << "SSLConn::[" << name_ << "] channel=" << chan_.get() << " fd=" << sockfd << " addr="
                       << AddrToString();
            assert(ssl_ctx_);
        }

        void SSLConn::SendInLoop(const void *data, size_t len) {
            assert(loop_->IsInLoopThread());

            if (status_ == kDisconnected) {
                LOG_WARN << "disconnected, give up writing";
                return;
            }

            ssize_t nwritten = 0;
            size_t remaining = len;
            bool write_error = false;

            // if no data in output queue, writing directly
            if (!chan_->IsWritable() && output_buffer_.length() == 0) {
                int serrno = errno;
                if (ssl_) {
                    nwritten = evpp::ssl::SSL_write(ssl_, data, len, &serrno);
                    switch (serrno) {
                        case SSL_ERROR_WANT_WRITE:
                            break;
                        case SSL_ERROR_ZERO_RETURN:
                            LOG_WARN << "SSL has been shutdown by remote";
                            HandleError();
                            return;
                        case 0:
                            break;
                        default:
                            LOG_WARN << "SSL unknown error";
                            HandleError();
                            return;
                    }
                } else {
                    nwritten = ::send(chan_->fd(), static_cast<const char *>(data), len, MSG_NOSIGNAL);
                }

                if (nwritten >= 0) {
                    remaining = len - nwritten;
                    if (remaining == 0 && write_complete_fn_) {
                        loop_->QueueInLoop(std::bind(write_complete_fn_, shared_from_this()));
                    }
                } else {
                    nwritten = 0;
                    if (!EVUTIL_ERR_RW_RETRIABLE(serrno)) {
                        LOG_ERROR << "SendInLoop write failed errno=" << serrno << " " << strerror(serrno);
                        if (serrno == EPIPE || serrno == ECONNRESET) {
                            write_error = true;
                        }
                    }
                }
            }

            if (write_error) {
                HandleError();
                return;
            }

            assert(!write_error);
            assert(remaining <= len);

            if (remaining > 0) {
                size_t old_len = output_buffer_.length();
                if (old_len + remaining >= high_water_mark_
                    && old_len < high_water_mark_
                    && high_water_mark_fn_) {
                    loop_->QueueInLoop(std::bind(high_water_mark_fn_, shared_from_this(), old_len + remaining));
                }

                output_buffer_.Append(static_cast<const char *>(data) + nwritten, remaining);

                if (!chan_->IsWritable()) {
                    chan_->EnableWriteEvent();
                }
            }
        }

        void SSLConn::HandleRead() {
            assert(loop_->IsInLoopThread());

            // 启用SSL时，处理SSL握手
            if (!sslConnected_) {
                HandleSSLHandshake();
                return;
            }

            // add openssl support
            int serrno = 0;
            ssize_t n = evpp::ssl::SSL_read(ssl_, &input_buffer_, &serrno);
            if (n > 0) {
                msg_fn_(shared_from_this(), &input_buffer_);
            } else { // <= 0 , 需要进一步处理SSL错误码
                // deal SSL_ERROR_WANT_READ/SSL_ERROR_WANT_WRITE
                // 这里如果不这么处理，则导致接收数据不完整，从而出错
                switch (serrno) {
                    case SSL_ERROR_WANT_READ:
                        chan_->EnableReadEvent();
                        break;
                    case SSL_ERROR_WANT_WRITE:
                        chan_->EnableWriteEvent();
                        break;
                    case SSL_ERROR_ZERO_RETURN://SSL has been shutdown，相当于原生write()返回0，代表对端关闭连接（正常情况）
                        DLOG_TRACE << "SSL has been shutdown(" << serrno << ").";
                        HandleError();
                        break;
                    case SSL_ERROR_SSL:
                        DLOG_TRACE << "SSL has error(" << serrno << ").";
                        HandleError();
                        break;
                    case SSL_ERROR_NONE: // 0，have none error
                        DLOG_TRACE << "SSL has error none";
                        break;
                    default:
                        DLOG_TRACE << "SSL Connection has been aborted(" << serrno << ").";
                        HandleError();
                        break;
                }
            }
        }

        void SSLConn::HandleWrite() {
            assert(loop_->IsInLoopThread());
            assert(!chan_->attached() || chan_->IsWritable());

            // 处理OpenSSL握手的情况，这里可能存在重新协商的问题
            // 参考：https://github.com/chengwuloo/websocket
            if (!sslConnected_) {
                DLOG_WARN << "HandleWrite need SSL_handshake";
                HandleSSLHandshake();
                return;
            }

            // add openssl support
            int serrno = errno;
            ssize_t n = evpp::ssl::SSL_write(ssl_, output_buffer_.data(), output_buffer_.length(), &serrno);
            if (n > 0) {
                output_buffer_.Next(n);

                if (output_buffer_.length() == 0) {
                    chan_->DisableWriteEvent();

                    if (write_complete_fn_) {
                        loop_->QueueInLoop(std::bind(write_complete_fn_, shared_from_this()));
                    }
                }
            } else { // <= 0 , check openssl error
                switch (serrno) {
                    case SSL_ERROR_WANT_READ:
                        chan_->EnableReadEvent();
                        break;
                    case SSL_ERROR_WANT_WRITE:
                        chan_->EnableWriteEvent();
                        break;
                    case SSL_ERROR_ZERO_RETURN: //SSL has been shutdown，相当于原生write()返回0，代表对端关闭连接（正常情况）
                        DLOG_TRACE << "SSL_write SSL has been shutdown(" << serrno << ").";
                        HandleError();
                        break;
                    case SSL_ERROR_NONE: // none error
                        DLOG_TRACE << "SSL has error none";
                        break;
                    case SSL_ERROR_SSL:
                        DLOG_TRACE << "SSL_write has error(" << serrno << ").";
                        HandleError();
                        break;
                    default:
                        DLOG_TRACE << "SSL_write Connection has been aborted(" << serrno << ").";
                        HandleError();
                        break;
                }
            }
        }

        void SSLConn::HandleClose() {
            if (ssl_ != nullptr) {
                evpp::ssl::SSL_free(ssl_);
            }
            TCPConn::HandleClose();
        }

        void SSLConn::HandleSSLHandshake() {
            assert(ssl_ctx_);
            int savedErrno = 0;
            // SSL握手连接
            ssl::SSL_handshake(ssl_ctx_, ssl_, chan_->fd(), savedErrno);
            switch (savedErrno) {
                case SSL_ERROR_WANT_READ: // 等待socket可读，然后再次调用此函数
                    DLOG_WARN << "SSL_handshake recv SSL_ERROR_WANT_READ";
                    chan_->EnableReadEvent();
                    break;
                case SSL_ERROR_WANT_WRITE: // 等待socket可写，然后再次调用此函数
                    DLOG_WARN << "SSL_handshake recv SSL_ERROR_WANT_WRITE";
                    chan_->EnableWriteEvent();
                    break;
                case SSL_ERROR_SSL:
                    HandleError();
                    break;
                case 0: //success
                    sslConnected_ = true;
                    DLOG_TRACE << "SSL do handshake success";
                    break;
                default:
                    DLOG_TRACE << "SSL_handshake error,no=" << savedErrno;
                    HandleError();
                    break;
            }
        }

        SSLConn::~SSLConn() = default;
    }
}