
#pragma once

#include <variant>

#include <Windows.h>
#include <DbgEng.h>

#include <wil/com.h>

namespace comon_ext
{
struct arch_x86
{
    const ULONG effmach_code;
    const bool is_wow64;

    const ULONG esp, eax;
};

struct arch_x64
{
    static constexpr int X64_REG_ARGS{ 4 };

    const ULONG effmach_code;

    const ULONG rcx, rdx, r8, r9, rsp, rax;
};

using arch = std::variant<arch_x86, arch_x64>;

// decodes stdcall method call context (arguments and the return address)
class call_context
{
    const wil::com_ptr<IDebugControl4> _dbgcontrol;
    const wil::com_ptr<IDebugDataSpaces> _dbgdataspaces;
    const wil::com_ptr<IDebugRegisters2> _dbgregisters;

    const arch _arch;
    const ULONG _pointer_size;

public:
    explicit call_context(IDebugControl4* dbgcontrol, IDebugDataSpaces* dbgdataspaces,
        IDebugRegisters2* dbgregisters, const arch& arch) :
        _dbgcontrol{ dbgcontrol }, _dbgdataspaces{ dbgdataspaces },
        _dbgregisters{ dbgregisters }, _arch{ arch },
        _pointer_size{ std::holds_alternative<arch_x86>(arch) ? 4UL : 8UL } {
    }

    HRESULT read_pointer(ULONG64 addr, ULONG64& value) {
        ULONG bytes_read{};
        RETURN_IF_FAILED(_dbgdataspaces->ReadVirtual(addr, &value, _pointer_size, &bytes_read));
        RETURN_HR_IF(E_UNEXPECTED, bytes_read != _pointer_size);
        return S_OK;
    }

    HRESULT read_object(ULONG64 addr, PVOID obj, ULONG obj_size) {
        ULONG bytes_read{};
        RETURN_IF_FAILED(_dbgdataspaces->ReadVirtual(addr, obj, obj_size, &bytes_read));
        RETURN_HR_IF(E_UNEXPECTED, bytes_read != obj_size);
        return S_OK;
    }

    HRESULT read_method_return_code(HRESULT& hr) {
        if (std::holds_alternative<arch_x86>(_arch)) {
            DEBUG_VALUE r{};
            RETURN_IF_FAILED(_dbgregisters->GetValue(
                std::get<arch_x86>(_arch).eax, &r));
            hr = static_cast<HRESULT>(r.I32);
            return S_OK;
        } else if (std::holds_alternative<arch_x64>(_arch)) {
            DEBUG_VALUE r{};
            RETURN_IF_FAILED(_dbgregisters->GetValue(
                std::get<arch_x64>(_arch).rax, &r));
            hr = static_cast<HRESULT>(r.I64);
            return S_OK;
        } else {
            hr = E_FAIL;
            return E_UNEXPECTED;
        }
    }

    // works only when called at the method breakpoint (before first instruction)
    HRESULT read_method_frame(std::vector<ULONG64>& args, ULONG64& ret_addr);

    ULONG64 get_pointer_size() const noexcept {
        return _pointer_size;
    }
};

}

