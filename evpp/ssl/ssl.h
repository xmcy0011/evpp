/************************************************************************/
/*    @author create by andy_ro@qq.com                                  */
/*    @Date		   03.03.2020                                           */
/************************************************************************/
#ifndef _MUDUO_NET_SSL_H_
#define _MUDUO_NET_SSL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
#include <openssl/x509v3.h>

#ifdef __cplusplus
}
#endif

#include <assert.h>
#include <mutex>

#include <iomanip>
#include <sstream>

#include "evpp/buffer.h"
#include "evpp/windows_port.h"

namespace evpp {
    namespace ssl {

        //SSL_CTX_Init
        void EVPP_EXPORT SSL_CTX_Init(
                std::string const &cert_path,
                std::string const &private_key_path,
                std::string const &client_ca_cert_file_path = "",
                std::string const &client_ca_cert_dir_path = "");

        //SSL_CTX_Get
        SSL_CTX *EVPP_EXPORT SSL_CTX_Get();

        //SSL_CTX_free
        void EVPP_EXPORT SSL_CTX_free();

        //SSL_read
        ssize_t EVPP_EXPORT SSL_read(SSL *ssl, Buffer *buf, int *savedErrno);

        //SSL_write
        ssize_t EVPP_EXPORT SSL_write(SSL *ssl, void const *data, size_t len, int *savedErrno);

        //SSL_handshake
        bool EVPP_EXPORT SSL_handshake(SSL_CTX *ctx, SSL *&ssl, int sockFd, int &saveErrno);

        //SSL_free
        void EVPP_EXPORT SSL_free(SSL *&ssl);

    };//namespace ssl
}; //namespace evpp

#endif
