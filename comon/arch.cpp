
#include <array>
#include <vector>

#include "cometa.h"
#include "arch.h"

using namespace comon_ext;

HRESULT call_context::read_method_frame(std::vector<ULONG64>& args, ULONG64& ret_addr) {
    auto read_x86 = [this, &args, &ret_addr](const arch_x86& arch) {
        DEBUG_VALUE esp{};
        RETURN_IF_FAILED(_dbgregisters->GetValue(arch.esp, &esp));

        std::vector<ULONG> stack(args.size() + 1);
        RETURN_IF_FAILED(read_object(esp.I64, stack.data(), static_cast<ULONG>(stack.size() * sizeof(ULONG))));
        ret_addr = stack[0];
        args.assign(std::cbegin(stack) + 1, std::cend(stack));

        return S_OK;
    };

    auto read_amd64 = [this, &args, &ret_addr](const arch_x64& arch) {
        std::array<DEBUG_VALUE, arch_x64::X64_REG_ARGS> reg_pass_args{};
        std::array<ULONG, arch_x64::X64_REG_ARGS> params_idx{ arch.rcx, arch.rdx, arch.r8, arch.r9 };

        RETURN_IF_FAILED(_dbgregisters->GetValues2(DEBUG_REGSRC_DEBUGGEE,
            arch_x64::X64_REG_ARGS, params_idx.data(), 0, reg_pass_args.data()));

        auto len{ reg_pass_args.size() < args.size() ? reg_pass_args.size() : args.size() };
        std::transform(std::cbegin(reg_pass_args), std::cbegin(reg_pass_args) + len, std::begin(args),
            [](const DEBUG_VALUE& v) { return v.I64; });

        DEBUG_VALUE rsp{};
        RETURN_IF_FAILED(_dbgregisters->GetValue(arch.rsp, &rsp));
        if (args.size() > arch_x64::X64_REG_ARGS) {
            // the resf of the arguments and the return address we need to read from the stack
            std::vector<ULONG64> stack(args.size() + 1);
            RETURN_IF_FAILED(read_object(rsp.I64, stack.data(), static_cast<ULONG>(stack.size() * sizeof(ULONG64))));
            ret_addr = stack[0];
            // we start from X64_REG_ARGS because of the shadow space
            for (size_t i{ arch_x64::X64_REG_ARGS }; i < stack.size() - 1; i++) {
                args[i] = stack[i + 1];
            }
        } else {
            RETURN_IF_FAILED(read_pointer(rsp.I64, ret_addr));
        }
        return S_OK;
    };

    if (std::holds_alternative<arch_x86>(_arch)) {
        return read_x86(std::get<arch_x86>(_arch));
    } else if (std::holds_alternative<arch_x64>(_arch)) {
        return read_amd64(std::get<arch_x64>(_arch));
    } else {
        return E_UNEXPECTED;
    }
}


