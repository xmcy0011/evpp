#pragma once

#include <string>
#include <sstream>

#ifndef H_CASE_STRING_BIGIN
#define H_CASE_STRING_BIGIN(state) switch(state){
#define H_CASE_STRING(state) case state:return #state;break;
#define H_CASE_STRING_END()  default:return "Unknown";break;}
#endif

#ifdef H_OS_WINDOWS

#include <windows.h>

#else
#include <unistd.h>
#endif

namespace evpp {

    template<class StringVector,
            class StringType,
            class DelimType>
    inline void StringSplit(
            const StringType &str,
            const DelimType &delims,
            unsigned int maxSplits,
            StringVector &ret) {

        if (str.empty()) {
            return;
        }

        unsigned int numSplits = 0;

        // Use STL methods
        size_t start, pos;
        start = 0;

        do {
            pos = str.find_first_of(delims, start);

            if (pos == start) {
                ret.push_back(StringType());
                start = pos + 1;
            } else if (pos == StringType::npos || (maxSplits && numSplits + 1 == maxSplits)) {
                // Copy the rest of the string
                ret.emplace_back(StringType());
                *(ret.rbegin()) = StringType(str.data() + start, str.size() - start);
                break;
            } else {
                // Copy up to delimiter
                //ret.push_back( str.substr( start, pos - start ) );
                ret.push_back(StringType());
                *(ret.rbegin()) = StringType(str.data() + start, pos - start);
                start = pos + 1;
            }

            ++numSplits;

        } while (pos != StringType::npos);
    }

#ifdef H_OS_WINDOWS

    /**@fn stringToWstring
      *@brief 转换
      *@return
      */
    inline std::wstring stringToWstring(const std::string &str) {
        LPCSTR pszSrc = str.c_str();
        int nLen = MultiByteToWideChar(CP_ACP, 0, pszSrc, -1, nullptr, 0);
        if (nLen == 0)
            return (std::wstring(L""));

        auto *dst = new wchar_t[nLen];

        MultiByteToWideChar(CP_ACP, 0, pszSrc, -1, dst, nLen);
        std::wstring wstr(dst);
        delete[] dst;

        return (wstr);
    }

#endif

    /**@fn FilePathIsExist
      *@brief 检测文件路径是否存在
      *@param file_name：文件路径
      *@return
      */
    inline bool FilePathIsExist(const std::string &file_name) {
#ifdef H_OS_WINDOWS
        const DWORD file_attr = ::GetFileAttributesW(stringToWstring(file_name).c_str());
        if (file_attr != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
        return false;
#else
        return ::access(file_name.c_str(), 0) == F_OK;
#endif
    }
}
