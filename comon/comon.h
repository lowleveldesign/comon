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

#pragma once

#include <string>
#include <format>
#include <unordered_set>
#include <unordered_map>
#include <span>

#include <Windows.h>
#include <DbgEng.h>

#include <wil/com.h>

namespace comon_ext
{
std::wstring widen(std::string_view s);

std::string narrow(std::wstring_view ws);

std::string to_utf8(std::wstring_view ws);

std::wstring from_utf8(std::string_view s);

std::wstring wstring_from_guid(const GUID& guid);

HRESULT try_parse_guid(std::wstring_view ws, GUID& guid);

GUID parse_guid(std::wstring_view ws);
}

// inspired by boost container hash
template <typename T>
inline void hash_combine(std::size_t& seed, const T& v) {
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

template<> struct std::hash<GUID>
{
    std::size_t operator()(const GUID& g) const noexcept {
        const unsigned long* r{ &g.Data1 };
        return *r ^ *(r + 1) ^ *(r + 2) ^ *(r + 3);
    }
};

template<> struct std::hash<std::pair<CLSID, IID>>
{
    std::size_t operator()(const std::pair<CLSID, IID>& p) const noexcept {
        std::hash<GUID> hasher{};
        auto seed{ hasher(p.first) };
        hash_combine(seed, p.second);
        return seed;
    }
};

template<>
class std::formatter<GUID, wchar_t>
{
public:
    constexpr auto parse(auto& context) {
        auto iter{ context.begin() };
        const auto end{ context.end() };
        if (iter == end || *iter == L'}') {  // {} format specifier
            _output_type = L'd';
            return iter;
        }

        switch (*iter) {
        case L'n':
        case L'd':
        case L'b':
            _output_type = *iter;
            break;
        default:
            throw std::format_error{ "Invalid GUID format specifier." };
        }

        ++iter;
        if (iter != end && *iter != L'}') {
            throw format_error{ "Invalid GUID format specifier." };
        }

        return iter;
    }

    auto format(const GUID& g, auto& context) {
        auto gstr{ comon_ext::wstring_from_guid(g) };

        if (_output_type == L'n') {
            auto iter{ gstr.begin() };
            while (iter != gstr.end()) {
                if (*iter == L'{' || *iter == L'}' || *iter == L'-') {
                    iter = gstr.erase(iter);
                } else {
                    iter++;
                }
            }
        } else if (_output_type != L'b') {
            gstr.erase(0, 1);
            gstr.pop_back();
        }

        return format_to(context.out(), L"{}", gstr.c_str());
    }

private:
    wchar_t _output_type{ L'd' };
};

#define RETURN_VOID_IF_FAILED(hr)  __WI_SUPPRESS_4127_S do { const auto __hrRet = wil::verify_hresult(hr); if (FAILED(__hrRet)) { __R_INFO_ONLY(#hr); return; }} __WI_SUPPRESS_4127_E while ((void)0, 0)

namespace comon_ext
{

class dbgeng_logger
{
private:
    const wil::com_ptr<IDebugControl4> _dbgcontrol;

public:
    static std::wstring_view get_error_msg(HRESULT hr) {
        static std::unordered_map<HRESULT, std::wstring> error_messages{};
        if (!error_messages.contains(hr)) {
            wchar_t error_msg[256];
            auto cnt{ ::FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), error_msg, ARRAYSIZE(error_msg), nullptr) };
            if (cnt == 0) {
                return L"";
            }
            // skip new line at the end
            if (cnt >= 2 && error_msg[cnt - 2] == '\r' && error_msg[cnt - 1] == '\n') {
                cnt -= 2;
            }

            error_messages.insert({ hr, { error_msg, cnt } });
        }
        return error_messages.at(hr);
    };

    dbgeng_logger(IDebugControl4* dbgcontrol):
        _dbgcontrol{ dbgcontrol } {}

    void log_info(std::wstring_view message) const {
        LOG_IF_FAILED(_dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, std::format(L"[comon] {}\n", message).c_str()));
    }

    void log_info_dml(std::wstring_view message) const {
        LOG_IF_FAILED(_dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL,
            std::format(L"[comon] {}\n", message).c_str()));
    }

    void log_warning(std::wstring_view message) const {
        LOG_IF_FAILED(_dbgcontrol->OutputWide(DEBUG_OUTPUT_WARNING, std::format(L"[comon] {}\n", message).c_str()));
    }

    void log_error(std::wstring_view message, HRESULT hr) const {
        log_error_dml(message, hr);
    }

    void log_error_dml(std::wstring_view message, HRESULT hr) const {
        LOG_IF_FAILED(_dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_ERROR,
            std::format(L"[comon] {}, <col fg=\"srcstr\">error: {:#x} - {}</col>\n",
                message, static_cast<unsigned long>(hr), get_error_msg(hr)).c_str()));
    }
};
}

