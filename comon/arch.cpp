
#include <array>
#include <vector>

#include "cometa.h"
#include "arch.h"

using namespace comon_ext;

HRESULT call_context::read_method_frame(std::vector<ULONG64>& args, ULONG64& ret_addr) {
    auto read_x86 = [this, &args, &ret_addr](const arch_x86& arch) {
        DEBUG_VALUE esp{};
        RETURN_IF_FAILED(_dbgregisters->GetValue(arch.esp, &esp));
        RETURN_IF_FAILED(_dbgdataspaces->ReadPointersVirtual(1, esp.I64, &ret_addr));
        RETURN_IF_FAILED(_dbgdataspaces->ReadPointersVirtual(args.size(), esp.I64 + _pointer_size, args.data()));
        return S_OK;
    };

    auto read_amd64 = [this, &args, &ret_addr](const arch_x64& arch) {
        DEBUG_VALUE rsp{};
        RETURN_IF_FAILED(_dbgregisters->GetValue(arch.rsp, &rsp));
        RETURN_IF_FAILED(_dbgdataspaces->ReadPointersVirtual(1, rsp.I64, &ret_addr));

        if (args.size() > arch_x64::X64_REG_ARGS) {
            // because of the shadow space, we can fill all the arguments and later read 
            // the values pass by registers
            RETURN_IF_FAILED(_dbgdataspaces->ReadPointersVirtual(args.size(), rsp.I64 + _pointer_size, args.data()));
        }

        std::array<DEBUG_VALUE, arch_x64::X64_REG_ARGS> reg_pass_args{};
        std::array<ULONG, arch_x64::X64_REG_ARGS> params_idx{ arch.rcx, arch.rdx, arch.r8, arch.r9 };

        RETURN_IF_FAILED(_dbgregisters->GetValues2(DEBUG_REGSRC_DEBUGGEE,
            arch_x64::X64_REG_ARGS, params_idx.data(), 0, reg_pass_args.data()));

        auto len{ reg_pass_args.size() < args.size() ? reg_pass_args.size() : args.size() };
        std::transform(std::cbegin(reg_pass_args), std::cbegin(reg_pass_args) + len, std::begin(args),
            [](const DEBUG_VALUE& v) { return v.I64; });

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


