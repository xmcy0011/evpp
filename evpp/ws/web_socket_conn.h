/** @file web_socket_conn.h
  * @brief 
  * @author teng.qing
  * @date 2021/5/22
  */

#ifndef SAFE_EVPP_WEB_SOCKET_CONN_H_
#define SAFE_EVPP_WEB_SOCKET_CONN_H_

#include "evpp/tcp_conn.h"
#include "evpp/event_loop.h"
#include "evpp/fd_channel.h"
#include "evpp/buffer.h"
#include "evpp/ws/web_socket_helper.h"
#include <atomic>

namespace evpp {
    namespace ws {
        class WebSocketHelper;

        /** @class web_socket_conn
          * @brief
          */
        class EVPP_EXPORT WebSocketConn : public TCPConn {
        public:
            WebSocketConn(EventLoop *loop,
                 const std::string &name,
                 evpp_socket_t sockfd,
                 const std::string &laddr,
                 const std::string &raddr,
                 uint64_t id);

            void HandleRead() override;

            void SendInLoop(const void *data, size_t len) override;

        protected:
            friend class WebSocketServer;

        private:
            std::atomic_bool is_handshake_;
            evpp::ws::WebSocketHelper helper_;
            Buffer input_frame_buffer_;
        };
    }
}

#endif //SAFE_EVPP_WEB_SOCKET_CONN_H_
