/** @file ssl_conn.h
  * @brief 
  * @author teng.qing
  * @date 2021/5/21
  */

#ifndef SAFE_EVPP_SSL_CONN_H_
#define SAFE_EVPP_SSL_CONN_H_

#include "evpp/tcp_conn.h"
#include "evpp/ssl/ssl_server.h"
#include "evpp/ssl/ssl_client.h"

namespace evpp {
    namespace ssl {
        /** @class ssl_conn
          * @brief
          */
        class EVPP_EXPORT SSLConn : public TCPConn {
        public:
            SSLConn(EventLoop *loop,
                    const std::string &name,
                    evpp_socket_t sockfd,
                    const std::string &laddr,
                    const std::string &raddr,
                    uint64_t id,
                    SSL_CTX *ctx = nullptr,
                    SSL *ssl = nullptr);

            ~SSLConn() override;

            SSLConn(const SSLConn &) = delete;

            SSLConn &operator=(const SSLConn &) = delete;

        protected:
            void SendInLoop(const void *data, size_t len) override;

            void HandleRead() override;

            void HandleWrite() override;

            void HandleClose() override;

        private:
            void HandleSSLHandshake();

        protected:
            friend class evpp::ssl::SSLServer;

            friend class evpp::ssl::SSLClient;

        private:
            SSL *ssl_;
            SSL_CTX *ssl_ctx_;
            std::atomic<bool> sslConnected_;
        };
    }
}


#endif //SAFE_EVPP_SSL_CONN_H_
