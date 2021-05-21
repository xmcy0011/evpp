/** @file ssl_server.h
  * @brief SSL服务端支持
  * @author xmcy0011@sina.com
  * @date 5/12/21
  */

#include "evpp/inner_pre.h"

#include "ssl_conn.h"
#include "ssl_server.h"

#include "evpp/listener.h"
#include "evpp/tcp_conn.h"
#include "evpp/libevent.h"
#include "evpp/tcp_callbacks.h"

#include <atomic>

namespace evpp {
    namespace ssl {

        SSLServer::SSLServer(EventLoop *loop,
                             const std::string &laddr,
                             const std::string &name,
                             uint32_t thread_num,
                             SSL_CTX *ctx)
                : TCPServer(loop, laddr, name, thread_num),
                  ssl_ctx_(ctx) {

            assert(ctx != nullptr);
        }

        SSLServer::~SSLServer() {
            DLOG_TRACE;
        }

        void SSLServer::HandleNewConn(evpp_socket_t sockfd,
                                      const std::string &remote_addr/*ip:port*/,
                                      const struct sockaddr_in *raddr) {
            DLOG_TRACE << "fd=" << sockfd;
            assert(loop_->IsInLoopThread());
            if (IsStopping()) {
                LOG_WARN << "this=" << this << " The server is at stopping status. Discard this socket fd=" << sockfd
                         << " remote_addr=" << remote_addr;
                EVUTIL_CLOSESOCKET(sockfd);
                return;
            }

            assert(IsRunning());
            EventLoop *io_loop = GetNextLoop(raddr);
#ifdef H_DEBUG_MODE
            std::string n = name_ + "-" + remote_addr + "#" + std::to_string(next_conn_id_);
#else
            std::string n = remote_addr;
#endif
            ++next_conn_id_;

            SSLConnPtr conn(new SSLConn(io_loop, n, sockfd, listen_addr_, remote_addr, next_conn_id_, ssl_ctx_));
            assert(conn->type() == TCPConn::kIncoming);
            conn->SetMessageCallback(msg_fn_);
            conn->SetConnectionCallback(conn_fn_);
            conn->SetCloseCallback(std::bind(&SSLServer::RemoveConnection, this, std::placeholders::_1));
            io_loop->RunInLoop(std::bind(&SSLConn::OnAttachedToLoop, conn));
            connections_[conn->id()] = conn;
        }

    } // namespace ssl
} // namespace evpp