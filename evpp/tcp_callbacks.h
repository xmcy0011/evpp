#pragma once

#include "evpp/inner_pre.h"

namespace evpp {
    class Buffer;

    class TCPConn;

    namespace ssl {
        class SSLConn;
    }

    namespace ws {
        class WebSocketConn;
    }

    typedef std::shared_ptr<TCPConn> TCPConnPtr;
    typedef std::shared_ptr<ssl::SSLConn> SSLConnPtr;
    typedef std::shared_ptr<ws::WebSocketConn> WSConnPtr;
    typedef std::function<void()> TimerCallback;

// When a connection established, broken down, connecting failed, this callback will be called
// This is called from a work-thread this is not the listening thread probably
    typedef std::function<void(const TCPConnPtr &)> ConnectionCallback;


    typedef std::function<void(const TCPConnPtr &)> CloseCallback;
    typedef std::function<void(const TCPConnPtr &)> WriteCompleteCallback;
    typedef std::function<void(const TCPConnPtr &, size_t)> HighWaterMarkCallback;

    typedef std::function<void(const TCPConnPtr &, Buffer *)> MessageCallback;

    namespace internal {
        inline void DefaultConnectionCallback(const TCPConnPtr &) {}

        inline void DefaultMessageCallback(const TCPConnPtr &, Buffer *) {}
    }

}
