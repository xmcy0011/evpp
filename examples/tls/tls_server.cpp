/** @file tls_server.h
  * @brief 
  * @author xmcy0011@sina.com
  * @date 5/17/21
  */

#include <evpp/ssl/ssl_server.h>
#include <evpp/tcp_conn.h>

int main() {

    std::string addr = "0.0.0.0:9099";
    int thread_num = 4;
    evpp::EventLoop loop;

    evpp::ssl::SSL_CTX_Init("cert.pem", "private.key");

    evpp::ssl::SSLServer server(&loop, addr, "TCPEchoServer", thread_num, evpp::ssl::SSL_CTX_Get());
    server.SetMessageCallback([](const evpp::TCPConnPtr &conn,
                                 evpp::Buffer *msg) {
        // Do something with the received message
        conn->Send(msg); // At here, we just send the received message back.
    });
    server.SetConnectionCallback([](const evpp::TCPConnPtr &conn) {
        if (conn->IsConnected()) {
            LOG_INFO << "A new connection from " << conn->remote_addr();
        } else {
            LOG_INFO << "Lost the connection from " << conn->remote_addr();
        }
    });
    server.Init();
    server.Start();
    loop.Run();

    evpp::ssl::SSL_CTX_free();

    return 0;
}