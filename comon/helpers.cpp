/*
   Copyright 2022 Sebastian Solnica

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <string>
#include <cassert>
#include <vector>
#include <sstream>
#include <ranges>
#include <format>
#include <functional>
#include <Windows.h>
#include <wil/result.h>

#include "comon.h"

namespace comon_ext
{

std::wstring widen(std::string_view s) {
    std::wstring out{};
    if (!s.empty()) {
        int len = ::MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, s.data(), static_cast<int>(s.size()), nullptr, 0);
        if (len == 0) {
            THROW_LAST_ERROR();
        }

        out.resize(len, '\0');
        assert(static_cast<int>(out.size()) == len);

        if (len != ::MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, s.data(), static_cast<int>(s.size()),
            out.data(), static_cast<int>(out.size()))) {
            THROW_LAST_ERROR();
        }
    }
    return out;
}

std::string narrow(std::wstring_view ws) {
    std::string out{};
    if (!ws.empty()) {
        int len = ::WideCharToMultiByte(CP_ACP, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
        if (len == 0) {
            THROW_LAST_ERROR();
        }

        out.resize(len, '\0');
        assert(static_cast<int>(out.size()) == len);

        if (len != ::WideCharToMultiByte(CP_ACP, 0, ws.data(), static_cast<int>(ws.size()), out.data(),
            static_cast<int>(out.size()), nullptr, nullptr)) {
            THROW_LAST_ERROR();
        }
    }
    return out;
}


std::string to_utf8(std::wstring_view ws) {
    std::string out{};
    if (!ws.empty()) {
        int len = ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
        if (len == 0) {
            THROW_LAST_ERROR();
        }

        out.resize(len, '\0');
        assert(static_cast<int>(out.size()) == len);

        if (len != ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), out.data(),
            static_cast<int>(out.size()), nullptr, nullptr)) {
            THROW_LAST_ERROR();
        }
    }
    return out;
}

std::wstring from_utf8(std::string_view s) {
    std::wstring out{};
    if (!s.empty()) {
        int len = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
        if (len == 0) {
            THROW_LAST_ERROR();
        }

        out.resize(len, '\0');
        assert(static_cast<int>(out.size()) == len);

        if (len != ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
            out.data(), static_cast<int>(out.size()))) {
            THROW_LAST_ERROR();
        }
    }
    return out;
}

std::wstring wstring_from_guid(const GUID& guid) {
    wil::unique_cotaskmem_string s{};
    auto hr = ::StringFromIID(guid, s.put());
    if (SUCCEEDED(hr)) {
        return { s.get() };
    }
    return std::format(L"<invalid: {:#x}>", static_cast<DWORD>(hr));
}

GUID parse_guid(std::wstring_view ws) {
    GUID guid;
    THROW_IF_FAILED(try_parse_guid(ws, guid));
    return guid;
}

HRESULT try_parse_guid(std::wstring_view ws, GUID& guid) {
    if (ws.size() > 2 && ws[0] != '{' && ws[ws.size() - 1] != '}') {
        std::wstring nws(ws.size() + 2, '\0');
        nws[0] = '{';
        std::ranges::copy(ws.cbegin(), ws.cend(), nws.begin() + 1);
        nws[nws.size() - 1] = '}';

        return ::IIDFromString(nws.c_str(), &guid);
    }

    return ::IIDFromString(ws.data(), &guid);
}
}
