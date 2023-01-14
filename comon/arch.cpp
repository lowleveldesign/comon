
#include <array>
#include <vector>

#include "cometa.h"
#include "arch.h"

using namespace comon_ext;

call_context::arch call_context::get_process_arch(IDebugControl4* dbgcontrol, IDebugSymbols3* dbgsymbols, IDebugRegisters2* dbgregisters) {
    auto init_arch_x86 = [dbgcontrol, dbgregisters](bool is_wow64) {
        ULONG eax, esp;
        THROW_IF_FAILED(dbgregisters->GetIndexByName("eax", &eax));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("esp", &esp));
        return arch_x86{ IMAGE_FILE_MACHINE_I386, is_wow64, esp, eax };
    };

    auto init_arch_x64 = [dbgcontrol, dbgregisters]() {
        ULONG rax, rsp, rcx, rdx, r8, r9;
        THROW_IF_FAILED(dbgregisters->GetIndexByName("rax", &rax));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("rsp", &rsp));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("rcx", &rcx));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("rdx", &rdx));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("r8", &r8));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("r9", &r9));

        return arch_x64{ IMAGE_FILE_MACHINE_AMD64, rcx, rdx, r8, r9, rsp, rax };
    };

    ULONG effmach{};
    THROW_IF_FAILED(dbgcontrol->GetEffectiveProcessorType(&effmach));

    bool is_wow64{};
    if (ULONG idx;
        SUCCEEDED(dbgsymbols->GetModuleByModuleName2Wide(L"wow64", 0, DEBUG_GETMOD_NO_UNLOADED_MODULES, &idx, nullptr)) && idx >= 0) {
        is_wow64 = true;
    }

    if (effmach == IMAGE_FILE_MACHINE_I386) {
        return init_arch_x86(is_wow64);
    } else if (effmach == IMAGE_FILE_MACHINE_AMD64) {
        return is_wow64 ? arch{ init_arch_x86(true) } : arch{ init_arch_x64() };
    } else {
        throw std::invalid_argument{ "unsupported effective CPU architecture" };
    }
}

call_context::call_context(IDebugControl4* dbgcontrol, IDebugDataSpaces3* dbgdataspaces, 
    IDebugRegisters2* dbgregisters, IDebugSymbols3* dbgsymbols): _dbgcontrol{ dbgcontrol }, _dbgdataspaces{ dbgdataspaces },
    _dbgregisters{ dbgregisters }, _arch{ get_process_arch(_dbgcontrol.get(), dbgsymbols, _dbgregisters.get()) },
    _pointer_size{ std::holds_alternative<arch_x86>(_arch) ? 4UL : 8UL } {
}

HRESULT call_context::read_method_frame(std::vector<ULONG64>& args, ULONG64& ret_addr) const {
    auto read_x86 = [this, &args, &ret_addr](const arch_x86& arch) {
        DEBUG_VALUE esp{};
        RETURN_IF_FAILED(_dbgregisters->GetValue(arch.esp, &esp));
        RETURN_IF_FAILED(_dbgdataspaces->ReadPointersVirtual(1, esp.I64, &ret_addr));
        RETURN_IF_FAILED(_dbgdataspaces->ReadPointersVirtual(static_cast<ULONG>(args.size()), esp.I64 + _pointer_size, args.data()));
        return S_OK;
    };

    auto read_amd64 = [this, &args, &ret_addr](const arch_x64& arch) {
        DEBUG_VALUE rsp{};
        RETURN_IF_FAILED(_dbgregisters->GetValue(arch.rsp, &rsp));
        RETURN_IF_FAILED(_dbgdataspaces->ReadPointersVirtual(1, rsp.I64, &ret_addr));

        if (args.size() > arch_x64::X64_REG_ARGS) {
            // because of the shadow space, we can fill all the arguments and later read 
            // the values pass by registers
            RETURN_IF_FAILED(_dbgdataspaces->ReadPointersVirtual(static_cast<ULONG>(args.size()), rsp.I64 + _pointer_size, args.data()));
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


