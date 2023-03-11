
#pragma once

#include <string>
#include <variant>
#include <vector>
#include <tuple>
#include <memory>
#include <optional>
#include <algorithm>

#include <Windows.h>
#include <DbgEng.h>

#include <wil/com.h>

namespace comon_ext
{

/*
 * This class contains a lot of messy code to read the arguments of a function call
 * and work with the stack. It is in many ways limited and may require some work to
 * make it work to less common architectures/calling conventions/etc.
*/
class call_context
{
    struct arch_x86
    {
        const ULONG effmach_code;
        const bool is_wow64;

        const ULONG esp, eax;
    };

    struct arch_x64
    {
        const ULONG effmach_code;

        const ULONG rsp, rax;

        const ULONG reg_args[8];
    };

    using arch = std::variant<arch_x86, arch_x64>;

    static arch get_process_arch(IDebugControl4* dbgcontrol, IDebugSymbols3* dbgsymbols, IDebugRegisters2* dbgregisters);

    const wil::com_ptr<IDebugControl4> _dbgcontrol;
    const wil::com_ptr<IDebugDataSpaces3> _dbgdataspaces;
    const wil::com_ptr<IDebugRegisters2> _dbgregisters;

    const arch _arch;
    const ULONG _pointer_size;

public:
    struct arg_val {
        std::wstring type;
        ULONG64 value;
    };

    explicit call_context(IDebugControl4* dbgcontrol, IDebugDataSpaces3* dbgdataspaces,
        IDebugRegisters2* dbgregisters, IDebugSymbols3* dbgsymbols);

    HRESULT read_pointer(ULONG64 addr, ULONG64& value) const {
        RETURN_IF_FAILED(_dbgdataspaces->ReadPointersVirtual(1, addr, &value));
        return S_OK;
    }

    HRESULT read_wstring(ULONG64 addr, std::wstring& value, int maxlen = 1000) const {
        std::unique_ptr<wchar_t[]> buf(new wchar_t[maxlen]);
        ULONG bytes_read{};
        RETURN_IF_FAILED(_dbgdataspaces->ReadVirtual(addr, buf.get(), maxlen * sizeof(wchar_t), &bytes_read));
        if (const wchar_t* end = std::char_traits<wchar_t>::find(buf.get(), maxlen, L'\0')) {
            value.assign(buf.get(), end - buf.get());
        } else {
            value.assign(buf.get(), maxlen);
        }
        return S_OK;
    }

    HRESULT read_string(ULONG64 addr, std::string& value, int maxlen = 1000) const {
        std::unique_ptr<char[]> buf(new char[maxlen]);
        ULONG bytes_read{};
        RETURN_IF_FAILED(_dbgdataspaces->ReadVirtual(addr, buf.get(), maxlen * sizeof(char), &bytes_read));
        if (const char* end = std::char_traits<char>::find(buf.get(), maxlen, '\0')) {
            value.assign(buf.get(), end - buf.get());
        } else {
            value.assign(buf.get(), maxlen);
        }
        return S_OK;
    }

    HRESULT read_object(ULONG64 addr, PVOID obj, ULONG obj_size) const {
        ULONG bytes_read{};
        RETURN_IF_FAILED(_dbgdataspaces->ReadVirtual(addr, obj, obj_size, &bytes_read));
        RETURN_HR_IF(E_UNEXPECTED, bytes_read != obj_size);
        return S_OK;
    }

    HRESULT read_method_return_code(arg_val& return_value) const;

    HRESULT read_method_frame(CALLCONV cc, std::vector<arg_val>& args, ULONG64& ret_addr) const;

    HRESULT get_arg_value_in_text(const arg_val& arg, std::wstring& text) const;

    ULONG get_pointer_size() const noexcept {
        return _pointer_size;
    }

    bool is_64bit() const noexcept { return _pointer_size == 8; }

    bool is_wow64() const noexcept {
        if (std::holds_alternative<arch_x86>(_arch)) {
            return std::get<arch_x86>(_arch).is_wow64;
        } else {
            return false;
        }
    }
};

}

