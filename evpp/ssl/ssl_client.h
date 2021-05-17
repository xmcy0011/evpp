/** @file ssl_client.h
  * @brief 
  * @author xmcy0011@sina.com
  * @date 5/17/21
  */

#ifndef SAFE_EVPP_SSL_CLIENT_H
#define SAFE_EVPP_SSL_CLIENT_H

#include "evpp/tcp_client.h"
#include "evpp/tcp_conn.h"

#include <openssl/ssl.h>

namespace evpp {
    namespace ssl {

        // We can use this class to create a SSL client.
        // The typical usage is :
        //      1. Create a SSLClient object
        //      2. Set the message callback and connection callback
        //      3. Call SSLClient::Connect() to try to establish a connection with remote server
        //      4. Use SSLClient::Send(...) to send messages to remote server
        //      5. Handle the connection and messages in callbacks
        //      6. Call SSLClient::Disonnect() to disconnect from remote server
        //
        class EVPP_EXPORT SSLClient : public TCPClient {
        public:
            // @brief The constructor of the class
            // @param[in] loop - The EventLoop runs this object
            // @param[in] remote_addr - The remote server address with format "host:port"
            //  If the host is not IP, it will automatically do the DNS resolving asynchronously
            // @param[in] name -
            SSLClient(EventLoop
                      *loop,
                      const std::string &remote_addr/*host:port*/,
                      const std::string &name
            );

            ~SSLClient() override;

        public:
            // @brief Try to establish a connection with remote server asynchronously
            //  If the connection callback is set properly it will be invoked when
            //  the connection is established successfully or timeout or cannot
            //  establish a connection.
            void Connect() override;

        private:
            void OnConnection(evpp_socket_t sockfd, const std::string &laddr) override;

            void ShowCerts(SSL* ssl);
        private: // added_s by xmcy0011@sina.com openssl support
            SSL_CTX *ssl_ctx_;
        };
    }
}

#endif //SAFE_EVPP_SSL_CLIENT_H
