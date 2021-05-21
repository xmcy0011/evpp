/** @file ssl_server.h
  * @brief 
  * @author xuyc
  * @date 5/12/21
  */

#ifndef _ssl_server_H_
#define _ssl_server_H_

#include "evpp/tcp_server.h"
#include "evpp/ssl/ssl.h"

#include <map>

namespace evpp {
    class Listener;

    namespace ssl {

// We can use this class to create a TCP server.
// The typical usage is :
//      1. Create a SslServer object
//      2. Set the message callback and connection callback
//      3. Call TCPServer::Init()
//      4. Call TCPServer::Start()
//      5. Process TCP client connections and messages in callbacks
//      6. At last call Server::Stop() to stop the whole server
//
// The examples code is as bellow:
// <code>
//    std::string addr = "0.0.0.0:8433";
//    int thread_num = 4;
//    evpp::EventLoop loop;
//
//    if (!evpp::ssl::SSL_CTX_Init("google.com.pem", "google.com.key")) {
//        LOG_ERROR << "SSL_CTX_Init error";
//        return 0;
//    }
//
//    evpp::ssl::SSLServer server(&loop, addr, "TlsServer", thread_num, evpp::ssl::SSL_CTX_Get());
//    server.SetMessageCallback([](const evpp::TCPConnPtr &conn,
//                                 evpp::Buffer *msg) {
//        LOG_INFO << "recv client msg:len=" << msg->length() << ",content=" << msg->ToString();
//        // Do something with the received message
//        conn->Send(msg); // At here, we just send the received message back.
//    });
//    server.SetConnectionCallback([](const evpp::TCPConnPtr &conn) {
//        if (conn->IsConnected()) {
//            LOG_INFO << "A new connection from " << conn->remote_addr();
//        } else {
//            LOG_INFO << "Lost the connection from " << conn->remote_addr();
//        }
//    });
//    server.Init();
//    server.Start();
//    loop.Run();
//
//    evpp::ssl::SSL_CTX_free();
// </code>
//
        class EVPP_EXPORT SSLServer : public TCPServer {
        public:
            // @brief The constructor of a TCPServer.
            // @param loop -
            // @param listen_addr - The listening address with "ip:port" format
            // @param name - The name of this object
            // @param thread_num - The working thread count
            // @param ctx - the openssl ctx, call evpp::ssl::SSL_CTX_Get() after evpp::ssl::SSL_CTX_Init()
            SSLServer(EventLoop *loop,
                      const std::string &listen_addr/*ip:port*/,
                      const std::string &name,
                      uint32_t thread_num,
                      SSL_CTX *ctx);

            ~SSLServer() override;

        protected:
            void HandleNewConn(evpp_socket_t sockfd, const std::string &remote_addr/*ip:port*/,
                               const struct sockaddr_in *raddr) override;

        private:
            SSL_CTX *ssl_ctx_; // SSL ctx, store public and private key
        };
    } // namespace ssl
} // namespace evpp

#endif // _ssl_server_H_