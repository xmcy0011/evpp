/** @file web_socket_server.h
  * @brief 
  * @author teng.qing
  * @date 2021/5/22
  */

#include "evpp/inner_pre.h"
#include "evpp/event_loop.h"
#include "evpp/libevent.h"
#include "evpp/tcp_callbacks.h"
#include "evpp/tcp_conn.h"
#include "web_socket_server.h"
#include "web_socket_conn.h"

namespace evpp {
    namespace ws {
        void WebSocketServer::HandleNewConn(int sockfd, const std::string &remote_addr,
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

            WSConnPtr conn(new WebSocketConn(io_loop, n, sockfd, listen_addr_, remote_addr, next_conn_id_));
            assert(conn->type() == TCPConn::kIncoming);
            conn->SetMessageCallback(msg_fn_);
            conn->SetConnectionCallback(conn_fn_);
            conn->SetCloseCallback(std::bind(&WebSocketServer::RemoveConnection, this, std::placeholders::_1));
            io_loop->RunInLoop(std::bind(&WebSocketConn::OnAttachedToLoop, conn));
            connections_[conn->id()] = conn;
        }

        WebSocketServer::WebSocketServer(EventLoop *loop, const string &listen_addr, const string &name,
                                         uint32_t thread_num) : TCPServer(loop, listen_addr, name, thread_num) {

        }
    }
}

