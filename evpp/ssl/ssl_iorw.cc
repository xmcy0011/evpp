/************************************************************************/
/*    @author create by andy_ro@qq.com                                  */
/*    @Date		   03.03.2020                                           */
/************************************************************************/

#include <cerrno>
#include <cstring>  // memset
#include <cassert>

#include "evpp/ssl/ssl.h"
#include "evpp/logging.h"

static inline void memZero(void *p, size_t n) {
    memset(p, 0, n);
}

//implicit_cast<ToType>(expr)
template<typename To, typename From>
inline To implicit_cast(From const &f) {
    return f;
}

// use like this: down_cast<T*>(foo);
// so we only accept pointers
template<typename To, typename From>
inline To down_cast(From *f) {
    if (false) {
        implicit_cast<From *, To>(0);
    }
    assert(f == NULL || dynamic_cast<To>(f) != NULL);
    return static_cast<To>(f);
}

namespace evpp {
    namespace ssl {

        ///
        /// @code
        /// +-------------------+------------------+------------------+
        /// | prependable bytes |  readable bytes  |  writable bytes  |
        /// |                   |     (CONTENT)    |                  |
        /// +-------------------+------------------+------------------+
        /// |                   |                  |                  |
        /// 0      <=      readerIndex   <=   writerIndex    <=     size
        /// @endcode
        ///
        //SSL_read
        ssize_t SSL_read(SSL *ssl, Buffer *buf, int *savedErrno) {
            assert(buf->WritableBytes() >= 0);
            LOG_TRACE << "ssl_iorw::SSL_read SSL_pending = " << SSL_pending(ssl);
            ssize_t n = 0;
            do {
                //make sure that writable > 0
                if (buf->WritableBytes() == 0) {
                    buf->EnsureWritableBytes(static_cast<size_t>(4096));
                }
#if 0 //test
                const size_t writable = 5;
                if (buf->length() < writable) {
                    buf->EnsureWritableBytes(implicit_cast<size_t>(writable));
                }
#else
                const size_t writable = buf->WritableBytes();
#endif
                int rc = ::SSL_read(ssl, buf->WriteBegin(), static_cast<int>(writable));
                if (rc > 0) {
                    assert(::SSL_get_error(ssl, rc) == 0);
                }
                //returns the number of bytes which are available inside ssl for immediate read
                //make sure that call it after SSL_read is called
                auto left = (size_t) ::SSL_pending(ssl);
                LOG_TRACE << "ssl_iorw::SSL_read rc = " << rc << " left = " << left << " err = "
                          << SSL_get_error(ssl, rc);
                if (rc > 0) {
                    assert(::SSL_get_error(ssl, rc) == 0);
                    n += (ssize_t) rc;
                    buf->WriteBytes(rc);
                    if (left > 0) {
                        const size_t writableBytes = buf->WritableBytes();
                        if (static_cast<size_t>(left) > writableBytes) {
                            buf->EnsureWritableBytes(static_cast<size_t>(left));
                        }
                        continue;
                    }
#if 0
                        const char* c = "HTTP/1.1 200 OK\r\nConnection: Close\r\n\r\n";
                        evpp::ssl::SSL_write(ssl, c, strlen(c));
#endif
                    //read all of buf then return
                    assert(left == 0);
                    break;
                } else if (rc < 0) {
                    int err = ::SSL_get_error(ssl, rc);
                    LOG_TRACE << "ssl_iorw::SSL_read rc = " << rc << " err = " << err << " errno = " << errno
                              << " errmsg = " << strerror(errno);
                    switch (err) {
                        case SSL_ERROR_WANT_READ:
                            *savedErrno = SSL_ERROR_WANT_READ;
                            break;
                        case SSL_ERROR_WANT_WRITE:
                            *savedErrno = SSL_ERROR_WANT_WRITE;
                            break;
                        case SSL_ERROR_SSL:
                            *savedErrno = SSL_ERROR_SSL;
                            break;
                            //SSL has been shutdown
                        case SSL_ERROR_ZERO_RETURN:
                            *savedErrno = SSL_ERROR_ZERO_RETURN;
                            LOG_TRACE << "ssl_iorw::SSL_read SSL has been shutdown(" << err << ").";
                            break;
                        default:
                            if (errno != EAGAIN /*&&
								errno != EWOULDBLOCK &&
								errno != ECONNABORTED &&
								errno != EPROTO*/ &&
                                errno != EINTR) {
                                //*savedErrno = errno;
                            }
                            *savedErrno = err;
                            break;
                    }
                    break;
                } else /*if (rc == 0)*/ {
                    //ssl_iorw::SSL_read() been called last time
                    assert(left == 0);
                    int err = ::SSL_get_error(ssl, rc);
                    switch (err) {
                        case SSL_ERROR_WANT_READ:
                            *savedErrno = SSL_ERROR_WANT_READ;
                            break;
                        case SSL_ERROR_WANT_WRITE:
                            *savedErrno = SSL_ERROR_WANT_WRITE;
                            break;
                        case SSL_ERROR_SSL:
                            *savedErrno = SSL_ERROR_SSL;
                            break;
                            //SSL has been shutdown
                        case SSL_ERROR_ZERO_RETURN:
                            *savedErrno = SSL_ERROR_ZERO_RETURN;
                            LOG_TRACE << "ssl_iorw::SSL_read SSL has been shutdown(" << err << ").";
                            break;
                            //Connection has been aborted by peer
                        default:
                            *savedErrno = err;
                            LOG_TRACE << "ssl_iorw::SSL_read Connection has been aborted(" << err << ").";
                            break;
                    }
                    break;
                }
            } while (true);
            return n;
        }//SSL_read

        //SSL_write
        ssize_t SSL_write(SSL *ssl, void const *data, size_t len, int *savedErrno) {
            //printf("\nssl_iorw::SSL_read SSL_write {{{\n");
            assert(len > 0);
            ssize_t left = (ssize_t) len;
            ssize_t n = 0;
            while (left > 0) {
                int rc = ::SSL_write(ssl, (char const *) data + n, left);
                if (rc > 0) {
                    n += (ssize_t) rc;
                    left -= (ssize_t) rc;
                    LOG_TRACE << "ssl_iorw::SSL_write rc = " << rc << " left = " << left << " err = "
                              << SSL_get_error(ssl, rc);
                    assert(::SSL_get_error(ssl, rc) == 0);
                } else if (rc < 0) {
                    //ssl_iorw::SSL_write rc = -1 err = 1 errno = 0 errmsg = Success
                    int err = ::SSL_get_error(ssl, rc);
                    if (errno != EINTR || errno != EAGAIN) {
                        LOG_WARN << "ssl_iorw::SSL_write rc = " << rc << " err = " << err << " errno = " << errno
                                 << " errmsg = " << strerror(errno);
                    }
                    switch (err) {
                        case SSL_ERROR_WANT_READ:
                            *savedErrno = SSL_ERROR_WANT_READ;
                            break;
                        case SSL_ERROR_WANT_WRITE:
                            *savedErrno = SSL_ERROR_WANT_WRITE;
                            break;
                        case SSL_ERROR_SSL:
                            *savedErrno = SSL_ERROR_SSL;
                            break;
                        default:
                            if (errno != EAGAIN /*&&
								errno != EWOULDBLOCK &&
								errno != ECONNABORTED &&
								errno != EPROTO*/ &&
                                errno != EINTR) {
                                //*savedErrno = errno;
                            }
                            *savedErrno = err;
                            break;
                    }
                    break;
                } else /*if (rc == 0)*/ {
                    //assert(left == 0);
                    int err = ::SSL_get_error(ssl, rc);
                    switch (err) {
                        //SSL has been shutdown
                        case SSL_ERROR_ZERO_RETURN:
                            *savedErrno = SSL_ERROR_ZERO_RETURN;
                            LOG_TRACE << "ssl_iorw::SSL_write SSL has been shutdown(" << err << ").";
                            break;
                            //Connection has been aborted by peer
                        default:
                            *savedErrno = err;
                            LOG_TRACE << "ssl_iorw::SSL_write Connection has been aborted(" << err << ").";
                            break;
                    }
                    break;
                }
            }
            return n;
        }//SSL_write

    }//namespace ssl
} // namespace evpp
