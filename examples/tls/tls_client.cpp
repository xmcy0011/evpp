/** @file tls_client.h
  * @brief 
  * @author xmcy0011@sina.com
  * @date 5/17/21
  */

#include "evpp/ssl/ssl_client.h"

int main(int argc, char* argv[]) {
    std::string addr = "127.0.0.1:8433";
    //std::string addr = "1127.0.0.1:8433";

    if (argc == 2) {
        addr = argv[1];
    }

    evpp::EventLoop loop;
    evpp::ssl::SSLClient client(&loop, addr, "TCPPingPongClient");
    client.SetMessageCallback([&loop, &client](const evpp::TCPConnPtr& conn,
                                               evpp::Buffer* msg) {
        LOG_TRACE << "Receive a message [" << msg->ToString() << "]";
        client.Disconnect();
    });

    client.SetConnectionCallback([](const evpp::TCPConnPtr& conn) {
        if (conn->IsConnected()) {
            LOG_INFO << "Connected to " << conn->remote_addr();
            conn->Send("hello");
        } else {
            conn->loop()->Stop();
        }
    });

    client.Connect();
    loop.Run();

    return 0;
}