/** @file ssl_client.h
  * @brief 
  * @author xmcy0011@sina.com
  * @date 5/17/21
  */

#include "ssl_client.h"
#include "evpp/connector.h"
#include "evpp/tcp_conn.h"
#include "evpp/tcp_callbacks.h"

#include "evpp/ssl/ssl.h"
#include <random>

namespace evpp {
    namespace ssl {
        std::atomic<uint64_t> g_ssl_id_(0);

        SSLClient::SSLClient(EventLoop *loop, const std::string &remote_addr, const std::string &name)
                : TCPClient(loop, remote_addr, name),
                  ssl_ctx_(nullptr) {

            SSL_library_init();
            OpenSSL_add_all_algorithms();
            SSL_load_error_strings();

            // create SSL_CTX
            const SSL_METHOD *method = SSLv23_client_method();
            ssl_ctx_ = SSL_CTX_new(method);
            assert(ssl_ctx_);
        }

        void SSLClient::Connect() {
            LOG_INFO << "remote_addr=" << remote_addr();
            auto f = [this]() {
                assert(loop_->IsInLoopThread());
                connector_.reset(new evpp::Connector(loop_, this));
                connector_->SetNewConnectionCallback(
                        std::bind(&SSLClient::OnConnection, this, std::placeholders::_1, std::placeholders::_2));
                connector_->Start();
            };
            loop_->RunInLoop(f);
        }

        SSLClient::~SSLClient() {
            // dispose openssl
            if (ssl_ctx_) {
                SSL_CTX_free(ssl_ctx_);
                ssl_ctx_ = nullptr;
            }
        }

        void SSLClient::OnConnection(evpp_socket_t sockfd, const std::string &laddr) {
            if (sockfd < 0) {
                DLOG_TRACE << "Failed to connect to " << remote_addr_ << ". errno=" << errno << " " << strerror(errno);
                // We need to notify this failure event to the user layer
                // Note: When we could not connect to a server,
                //       the user layer will receive this notification constantly
                //       because the connector_ will retry to do reconnection all the time.
                conn_fn_(TCPConnPtr(new TCPConn(loop_, "", sockfd, laddr, remote_addr_, 0)));
                return;
            }

            DLOG_TRACE << "Successfully connected to " << remote_addr_ << ",doHandshake...";

            SSL *ssl = SSL_new(ssl_ctx_); // disposed by TcpConn

            // ssl do handshake
            SSL_set_fd(ssl, sockfd);

            // no-blocking io
            std::random_device rd;
            std::default_random_engine gen = std::default_random_engine(rd());
            std::uniform_int_distribution<int> dis(5, 10);
            int maxTimes = dis(gen); // 最大次数,5 - 10 次
            int curTimes = 0;
            int ret = -1;

            while (curTimes < maxTimes) { // 100 - 200 ms超时
                ret = SSL_connect(ssl);
                if (ret == -1) {
                    fd_set fds;
                    FD_ZERO(&fds);
                    FD_SET(sockfd, &fds);
                    int ret = SSL_get_error(ssl, -1);
                    switch (ret) {
                        case SSL_ERROR_WANT_READ:
                        case SSL_ERROR_WANT_WRITE: {
                            struct timeval t{};
                            t.tv_sec = 0;
                            t.tv_usec = 100 * 1000; // 100 ms
                            select(sockfd + 1, &fds, nullptr, nullptr, &t);
                            curTimes++;
                            break;
                        }
                        default:
                            break;
                    }
                } else {
                    break;
                }
            }

            if (ret <= 0) {
                LOG_WARN << "SSL_connect error:" << ret;
                conn_fn_(TCPConnPtr(new TCPConn(loop_, "", sockfd, laddr, remote_addr_, 0)));
                return;
            }
            LOG_TRACE << "doHandshake success";
            ShowCerts(ssl);

            assert(loop_->IsInLoopThread());
            TCPConnPtr c = TCPConnPtr(
                    new TCPConn(loop_, name_, sockfd, laddr, remote_addr_, g_ssl_id_++, ssl_ctx_, ssl));
            c->set_type(TCPConn::kOutgoing);
            c->SetMessageCallback(msg_fn_);
            c->SetConnectionCallback(conn_fn_);
            c->SetCloseCallback(std::bind(&SSLClient::OnRemoveConnection, this, std::placeholders::_1));

            {
                std::lock_guard<std::mutex> guard(mutex_);
                conn_ = c;
            }

            c->OnAttachedToLoop();
        }

        void SSLClient::ShowCerts(SSL *ssl) {
            X509 *cert;
            char *line;
            cert = SSL_get_peer_certificate(ssl);
            if (cert != nullptr) {
                line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
                LOG_TRACE << "cert: " << line;
                free(line);
                line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
                LOG_TRACE << "to user: " << line;
                free(line);
                X509_free(cert);
            } else {
                LOG_TRACE << "have no cert";
            }
        }
    }
}



