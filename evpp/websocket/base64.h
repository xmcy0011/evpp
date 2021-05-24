/** @file base64.h
  * @brief 
  * @author teng.qing
  * @date 2021/5/21
  */

#ifndef SAFE_EVPP_BASE64_H_
#define SAFE_EVPP_BASE64_H_

#include <string>

namespace evpp {
    namespace websocket {
        std::string base64_encode2(unsigned char const *, unsigned int len);

        std::string base64_decode2(std::string const &s);
    }
}


#endif //SAFE_EVPP_BASE64_H_
