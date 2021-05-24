/** @file web_socket_server.h
  * @brief 
  * @author teng.qing
  * @date 2021/5/22
  */

#ifndef SAFE_EVPP_WEB_SOCKET_SERVER_H_
#define SAFE_EVPP_WEB_SOCKET_SERVER_H_

#include "evpp/windows_port.h"
#include "evpp/tcp_server.h"

namespace evpp {
    namespace ws {
// We can use this class to create a WebSocket server.
// The typical usage is :
//      1. Create a WebSocketServer object
//      2. Set the message callback and connection callback
//      3. Call WebSocketServer::Init()
//      4. Call WebSocketServer::Start()
//      5. Process TCP client connections and messages in callbacks
//      6. At last call Server::Stop() to stop the whole server
//
// The examples code is as bellow:
// <code>
//    std::string addr = "0.0.0.0:8433";
//    int thread_num = 4;
//    evpp::EventLoop loop;
//
//    evpp::ws::WebSocketServer server(&loop, addr, "TlsServer", thread_num);
//    server.SetMessageCallback([](const evpp::WSConnPtr &conn,
//                                 evpp::Buffer *msg) {
//        LOG_INFO << "recv client msg:len=" << msg->length() << ",content=" << msg->ToString();
//        // Do something with the received message
//        conn->Send(msg); // At here, we just send the received message back.
//    });
//    server.SetConnectionCallback([](const evpp::WSConnPtr &conn) {
//        if (conn->IsConnected()) {
//            LOG_INFO << "A new connection from " << conn->remote_addr();
//        } else {
//            LOG_INFO << "Lost the connection from " << conn->remote_addr();
//        }
//    });
//    server.Init();
//    server.Start();
//    loop.Run();
// </code>
//
        class EVPP_EXPORT WebSocketServer : public TCPServer {
        public:
            // @brief The constructor of a TCPServer.
            // @param loop -
            // @param listen_addr - The listening address with "ip:port" format
            // @param name - The name of this object
            // @param thread_num - The working thread count
            WebSocketServer(EventLoop *loop,
                            const std::string &listen_addr/*ip:port*/,
                            const std::string &name,
                            uint32_t thread_num);

        protected:
            void HandleNewConn(evpp_socket_t sockfd, const std::string &remote_addr/*ip:port*/,
                               const struct sockaddr_in *raddr) override;
        };
    }
}


#endif //SAFE_EVPP_WEB_SOCKET_SERVER_H_
