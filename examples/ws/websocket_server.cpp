/** @file websocket_server.h
  * @brief WebSocketServer示例
  * @author teng.qing
  * @date 2021/5/23
  */
#include "evpp/event_loop.h"
#include "evpp/tcp_callbacks.h"
#include "evpp/ws/web_socket_conn.h"
#include "evpp/ws/web_socket_server.h"
#include "evpp/logging.h"

struct WsHeader {
    int32_t packet_len; // 总长度
    int16_t header_len; // 头长度
    int16_t ver;        // 版本
    int32_t op;         // 消息类型
    int32_t seq;        // 序号
};

/**@fn parseHeader
  *@brief 读取头部，同时移动buff的读指针
  *@param buff：缓冲区
  *@param header: 头部信息
  *@return 结果
  */
bool parseHeader(evpp::Buffer *buff, WsHeader &header) {
    int32_t packet_len = buff->PeekInt32();
    if (packet_len > 65535) {
        LOG_WARN << "bad packet";
        return false;
    }

    // 16 bytes header
    header.packet_len = buff->ReadInt32();
    header.header_len = buff->ReadInt16();
    header.ver = buff->ReadInt16();
    header.op = buff->ReadInt32();
    header.seq = buff->ReadInt32();

    size_t body_len = header.packet_len - header.header_len;
    if (body_len > buff->length()) {
        LOG_WARN << "bad packet";
        return false;
    }

    return true;
}

int main() {
    std::string addr = "0.0.0.0:8002";
    int thread_num = 4;
    evpp::EventLoop loop;

    evpp::ws::WebSocketServer server(&loop, addr, "TlsServer", thread_num);
    server.SetMessageCallback([](const evpp::TCPConnPtr &conn,
                                 evpp::Buffer *msg) {
        //LOG_INFO << "recv client msg:len=" << msg->length();

        // 16 bytes header
        WsHeader header = {};
        while (true) {
            if (parseHeader(msg, header)) {
                int32_t body_len = header.packet_len - header.header_len;
                std::string body = msg->NextString(body_len);

                LOG_INFO << "recv client msg,packetLen=" << header.packet_len
                         << ",header_len=" << header.header_len
                         << ",ver=" << header.ver
                         << ",op=" << header.op
                         << ",seq=" << header.seq
                         << ",body=" << body;

                switch (header.op) {
                    case 2: // heartbeat
                    case 7: // auth
                    {
                        if (header.op == 2) {
                            LOG_INFO << "recv client auth msg";
                        } else {
                            LOG_INFO << "recv client heartbeat";
                        }
                        header.op++; // 2->3 7->8

                        evpp::Buffer b;
                        b.AppendInt32(sizeof(WsHeader));
                        b.AppendInt16(sizeof(WsHeader));
                        b.AppendInt16(header.ver);
                        b.AppendInt32(header.op);
                        b.AppendInt32(header.seq);

                        // PS: BigEndian
                        //b.Write(reinterpret_cast<void *>(&header), sizeof(header));
                        conn->Send(&b);
                        break;
                    }
                    default:
                        evpp::Buffer b;
                        b.AppendInt32(sizeof(WsHeader) + static_cast<int32_t>(body.length()));
                        b.AppendInt16(sizeof(WsHeader));
                        b.AppendInt16(header.ver);
                        b.AppendInt32(header.op);
                        b.AppendInt32(header.seq);
                        b.Write(body.data(), body.length());

                        conn->Send(&b); // At here, we just send the received message back.
                        break;
                }
            } else {
                break;
            }

            if (msg->length() <= 0) {
                break;
            } else {
                LOG_TRACE << "buffer reset, continue decode";
            }
        }
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

    return 0;
}