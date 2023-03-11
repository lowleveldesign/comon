
#include <array>
#include <vector>
#include <cassert>
#include <string>
#include <format>
#include <variant>
#include <unordered_set>
#include <ranges>

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
        ULONG rax, rsp, rcx, rdx, r8, r9, xmm0, xmm1, xmm2, xmm3;
        THROW_IF_FAILED(dbgregisters->GetIndexByName("rax", &rax));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("rsp", &rsp));

        THROW_IF_FAILED(dbgregisters->GetIndexByName("rcx", &rcx));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("rdx", &rdx));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("r8", &r8));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("r9", &r9));

        THROW_IF_FAILED(dbgregisters->GetIndexByName("xmm0", &xmm0));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("xmm1", &xmm1));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("xmm2", &xmm2));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("xmm3", &xmm3));

        return arch_x64{ IMAGE_FILE_MACHINE_AMD64, rsp, rax, { rcx, rdx, r8, r9, xmm0, xmm1, xmm2, xmm3 } };
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

HRESULT call_context::read_method_return_code(arg_val& return_arg) const {
    // FUTURE: currently, only HRESULT is supported
    if (return_arg.type != L"HRESULT") {
        return E_NOTIMPL;
    }

    if (std::holds_alternative<arch_x86>(_arch)) {
        DEBUG_VALUE r{};
        RETURN_IF_FAILED(_dbgregisters->GetValue(
            std::get<arch_x86>(_arch).eax, &r));
        return_arg.value = r.I32;
        return S_OK;
    } else if (std::holds_alternative<arch_x64>(_arch)) {
        DEBUG_VALUE r{};
        RETURN_IF_FAILED(_dbgregisters->GetValue(
            std::get<arch_x64>(_arch).rax, &r));
        return_arg.value = r.I64;
        return S_OK;
    } else {
        return_arg.value = 0xdeadbeef;
        return E_UNEXPECTED;
    }
}

namespace {

// types that we deal with in the following methods are the same as defined in cometa_helpers.cpp

bool is_primitive_type(std::wstring_view type) {
    static const std::unordered_set<std::wstring_view> primitive_types{
        L"bool", L"char", L"unsigned char", L"short", L"unsigned short", L"long", L"unsigned long",
            L"int", L"unsigned int", L"int64", L"uint64", L"HRESULT", L"DISPID"
    };

    return primitive_types.contains(type);
}

bool is_float_type(std::wstring_view type) {
    return type == L"float" || type == L"double" || type == L"single";
}

bool is_pointer_type(std::wstring_view type) {
    return type.ends_with(L"*") || type == L"LPWSTR" || type == L"LPSTR" || type == L"BSTR";
}

std::wstring get_primitive_arg_value_in_text(std::wstring_view type, ULONG64 raw_val) {
    if (type == L"bool") {
        return std::format(L"{}", raw_val ? L"true" : L"false", type);
    } else if (type == L"char") {
        return std::format(L"'{}'", static_cast<char>(raw_val), type);
    } else if (type == L"unsigned char") {
        return std::format(L"'{}'", static_cast<unsigned char>(raw_val), type);
    } else if (type == L"short") {
        return std::format(L"{}", static_cast<short>(raw_val), type);
    } else if (type == L"unsigned short") {
        return std::format(L"{}", static_cast<short>(raw_val), type);
    } else if (type == L"long") {
        return std::format(L"{}", static_cast<long>(raw_val), type);
    } else if (type == L"unsigned long") {
        return std::format(L"{}", static_cast<unsigned long>(raw_val), type);
    } else if (type == L"int") {
        return std::format(L"{}", static_cast<int>(raw_val), type);
    } else if (type == L"unsigned int") {
        return std::format(L"{}", static_cast<unsigned int>(raw_val), type);
    } else if (type == L"int64") {
        return std::format(L"{}", static_cast<int64_t>(raw_val), type);
    } else if (type == L"uint64") {
        return std::format(L"{}", static_cast<uint64_t>(raw_val), type);
    } else if (type == L"single" || type == L"float") {
        return std::format(L"{}", static_cast<float>(raw_val), type);
    } else if (type == L"double") {
        return std::format(L"{}", static_cast<double>(raw_val), type);
    } else if (type == L"DISPID") {
        return std::format(L"{:#x}", static_cast<unsigned long>(raw_val), type);
    } else if (type == L"HRESULT" || type == L"SCODE") {
        return std::format(L"{:#x}", static_cast<unsigned long>(raw_val), type);
    } else {
        assert(false);
        return std::wstring{ L"??" };
    }
};

}

HRESULT call_context::read_method_frame(CALLCONV cc, std::vector<arg_val>& args, ULONG64& ret_addr) const {

    if (!is_64bit() && cc != CALLCONV::CC_STDCALL) {
        return E_NOTIMPL;
    }

    auto get_stack_base = [this](ULONG64& stack_base) -> HRESULT {
        if (std::holds_alternative<arch_x86>(_arch)) {
            auto& arch = std::get<arch_x86>(_arch);
            DEBUG_VALUE r{};
            RETURN_IF_FAILED(_dbgregisters->GetValue(arch.esp, &r));
            stack_base = r.I32;
            return S_OK;
        } else if (std::holds_alternative<arch_x64>(_arch)) {
            auto& arch = std::get<arch_x64>(_arch);
            DEBUG_VALUE r{};
            RETURN_IF_FAILED(_dbgregisters->GetValue(arch.rsp, &r));
            stack_base = r.I64;
            return S_OK;
        } else {
            assert(false);
            return E_UNEXPECTED;
        }
    };

    DEBUG_VALUE x64_reg_values[8]{};
    if (is_64bit()) {
        auto& arch = std::get<arch_x64>(_arch);
        RETURN_IF_FAILED(_dbgregisters->GetValues(8, const_cast<PULONG>(arch.reg_args), 0, x64_reg_values));
    }

    ULONG64 offset{};
    RETURN_IF_FAILED(get_stack_base(offset));
    RETURN_IF_FAILED(_dbgdataspaces->ReadPointersVirtual(1, offset, &ret_addr));
    offset += _pointer_size; // return address

    // FIXME: calculate how much space is needed for the arguments
    auto buffer{ std::make_unique<BYTE[]>(args.size() * _pointer_size) };
    RETURN_IF_FAILED(_dbgdataspaces->ReadVirtual(offset, buffer.get(), static_cast<ULONG>(args.size() * _pointer_size), nullptr));

    // FUTURE: only stdcall is currently supported on x86
    auto get_nth_arg_value = [this, &buffer, &x64_reg_values](unsigned int n, arg_val& arg, ULONG64& offset) -> HRESULT {
        if (n < 4 && is_64bit()) {
            if (is_primitive_type(arg.type) || is_pointer_type(arg.type)) {
                arg.value = x64_reg_values[n].I64;
                offset += _pointer_size; // shadow space
            } else if (is_float_type(arg.type)) {
                arg.value = x64_reg_values[n + 4].I64;
                offset += _pointer_size; // shadow space
            } else {
                return E_NOTIMPL;
            }
        } else {
            // FIXME: what about arguments requiring more space
            if (is_64bit()) {
                arg.value = *reinterpret_cast<ULONG64*>(buffer.get() + n * _pointer_size);
            } else {
                arg.value = *reinterpret_cast<ULONG32*>(buffer.get() + n * _pointer_size);
            }
            offset += _pointer_size;
        }
        return S_OK;
    };

    for (unsigned int i = 0; i < args.size(); i++) {
        RETURN_IF_FAILED(get_nth_arg_value(i, args[i], offset));
    }

    return S_OK;
}

HRESULT call_context::get_arg_value_in_text(const arg_val& arg, std::wstring& text) const {
    auto read_wstring = [this](ULONG64 addr, std::wstring& value, int maxlen = 1000) {
        std::unique_ptr<wchar_t[]> buf(new wchar_t[maxlen]);
        SIZE_T bytes_read{};
        RETURN_IF_FAILED(_dbgdataspaces->ReadVirtual(addr, buf.get(), maxlen * sizeof(wchar_t), &bytes_read));
        if (const wchar_t* end = std::char_traits<wchar_t>::find(buf.get(), maxlen, L'\0')) {
            value.assign(buf.get(), end - buf.get());
        } else {
            value.assign(buf.get(), maxlen);
        }
        return S_OK;
    };

    auto read_string = [this](ULONG64 addr, std::string& value, int maxlen = 1000) {
        std::unique_ptr<char[]> buf(new char[maxlen]);
        SIZE_T bytes_read{};
        RETURN_IF_FAILED(_dbgdataspaces->ReadVirtual(addr, buf.get(), maxlen * sizeof(char), &bytes_read));
        if (const char* end = std::char_traits<char>::find(buf.get(), maxlen, '\0')) {
            value.assign(buf.get(), end - buf.get());
        } else {
            value.assign(buf.get(), maxlen);
        }
        return S_OK;
    };

    auto get_pointer_arg_value_in_text = [this, &read_string, &read_wstring](std::wstring_view type, ULONG64 addr, std::wstring& text) {
        constexpr int max_string_len = 100;

        if (addr == 0) {
            text = std::format(L"null ({})", type);
        } else if (type == L"GUID*") {
            GUID guid{};
            RETURN_IF_FAILED(read_object(addr, &guid, sizeof(guid)));
            text = std::format(L"{:#x} ({}) -> {:b}", addr, type, guid);
        } else if (type == L"LPWSTR" || type == L"BSTR") {
            std::wstring str{};
            RETURN_IF_FAILED(read_wstring(addr, str, max_string_len));
            text = std::format(L"{:#x} ({}) -> \"{}\"", addr, type, str);
        } else if (type == L"LPSTR") {
            std::string str{};
            RETURN_IF_FAILED(read_string(addr, str, max_string_len));
            text = std::format(L"{:#x} ({}) -> \"{}\"", addr, type, widen(str));
        } else if (type == L"DISPPARAMS*") {
            auto offset{ addr };
            ULONG64 args{};
            RETURN_IF_FAILED(read_pointer(offset, args));
            offset += _pointer_size;
            ULONG64 named_args{};
            RETURN_IF_FAILED(read_pointer(offset, named_args));
            offset += _pointer_size;
            DWORD arg_count{};
            RETURN_IF_FAILED(read_object(offset, &arg_count, sizeof(arg_count)));
            offset += sizeof(arg_count);
            DWORD named_arg_count{};
            RETURN_IF_FAILED(read_object(offset, &named_arg_count, sizeof(named_arg_count)));
            text = std::format(L"{:#x} ({}) -> {{ {:#x}, {:#x}, {}, {} }}", addr, type, args,
                named_args, arg_count, named_arg_count);
        } else if (is_primitive_type(type.substr(0, type.size() - 1))) {
            ULONG64 val{};
            RETURN_IF_FAILED(read_pointer(addr, val));
            auto val_text{ get_primitive_arg_value_in_text(type.substr(0, type.size() - 1), val) };
            text = std::format(L"{:#x} ({}) -> {}", addr, type, val_text);
        } else if (type.ends_with(L"**")) {
            ULONG64 pval{};
            RETURN_IF_FAILED(read_pointer(addr, pval));
            text = std::format(L"{:#x} ({}) -> {:#x}", addr, type, pval);
        } else {
            text = std::format(L"{:#x} ({})", addr, type);
        }
        return S_OK;
    };

    std::wstring_view type{ arg.type };

    if (type == L"void" || type == L"null" || type == typelib::bad_type_name) {
        text = std::format(L"({})", type);
    } else if (is_primitive_type(type)) {
        text = std::format(L"{} ({})", get_primitive_arg_value_in_text(type, arg.value), type);
    } else if (is_pointer_type(arg.type)) {
        RETURN_IF_FAILED(get_pointer_arg_value_in_text(type, arg.value, text));
    } else {
        text = std::format(L"?? ({})", type);
        return E_NOTIMPL;
    }

    return S_OK;
}