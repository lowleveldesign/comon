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

#include <algorithm>
#include <array>
#include <cassert>
#include <filesystem>
#include <format>
#include <ranges>
#include <string>
#include <utility>

#include <DbgEng.h>
#include <Windows.h>
#include <wil/com.h>
#include <wil/result.h>

#include "comon.h"
#include "comonitor.h"

using namespace comon_ext;

namespace views = std::ranges::views;
namespace fs = std::filesystem;

HRESULT comonitor::set_breakpoint(const breakpoint& brk, ULONG64 address, [[maybe_unused]] PULONG id) {

    auto get_breakpoint_command = [this, &brk]() {
        if (std::holds_alternative<coquery_single_return_breakpoint>(brk)) {
            auto& fbrk{ std::get<coquery_single_return_breakpoint>(brk) };
            return std::format(L"* [comon] return breakpoint (CLSID: {:b}, IID: {:b})", fbrk.clsid, fbrk.iid);
        } else if (std::holds_alternative<coregister_return_breakpoint>(brk)) {
            auto& crbrk{ std::get<coregister_return_breakpoint>(brk) };
            return std::format(L"* [comon] register return breakpoint (CLSID: {:b}, IID: {:b}, function: {})",
                crbrk.clsid, crbrk.iid, crbrk.register_function_name);
        } else if (std::holds_alternative<function_breakpoint>(brk)) {
            auto& fbrk{ std::get<function_breakpoint>(brk) };
            return std::format(L"* [comon] function breakpoint (name: {})", fbrk.function_name);
        } else if (std::holds_alternative<cobreakpoint>(brk)) {
            auto& cobrk{ std::get<cobreakpoint>(brk) };
            return std::format(L"* [comon] interface breakpoint (CLSID: {:b}, IID: {:b}, method: {})",
                cobrk.clsid, cobrk.iid, cobrk.method_name);
        } else if (std::holds_alternative<cobreakpoint_return>(brk)) {
            auto& corbrk{ std::get<cobreakpoint_return>(brk) };
            return std::format(L"* [comon] interface return breakpoint (CLSID: {:b}, IID: {:b}, method: {})",
                corbrk.clsid, corbrk.iid, corbrk.method_name);
        } else {
            assert(false);
            return std::wstring{};
        }
    };

    ULONG brk_id{};

    if (auto found_brk_id{ _breakpoint_addresses.find(address) }; found_brk_id != std::end(_breakpoint_addresses)) {
        brk_id = found_brk_id->second;
        // we need to replace the breakpoint data as it may have been updated by the user
        if (auto found_brk{ _breakpoints.find(brk_id) }; found_brk != std::end(_breakpoints)) {
            assert(found_brk->second.addr == address);
            auto mem_protect{ found_brk->second.mem_protect };
            _breakpoints.erase(found_brk);
            _breakpoints.insert({ brk_id, { brk, address, mem_protect } });
        } else {
            assert(false);
            _logger.log_error(std::format(L"Breakpoint {} found in the address map, but not in the breakpoint map.", brk_id), E_UNEXPECTED);
        }
    } else {
        IDebugBreakpoint2* dbgbrk{};
        RETURN_IF_FAILED(_dbgcontrol->AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &dbgbrk));

        std::optional<memory_protect> memprotect{};

        /* I discovered that dbgeng from WinDbgX explicitly calls VirtualProtectEx when setting a breakpoint in read-only memory.
           The old engine relies on WriteProcessMemory (and its implicit calls to NtProtectVirtualMemory) and fails on a COM pre-stub
           However, the call to VirtualProtectEx in WinDbgX makes the .NET process thread enter an endless loop, as the call to ComCallPreStub
           is never replaced by JITer. It must have  something to do with the copy-on-write protection that WindDgbX sets on this memory page.

           I try to detect such a situation here and set the memory page protection to PAGE_EXECUTE_READWRITE.
        */
        if (MEMORY_BASIC_INFORMATION meminfo{}; ::VirtualQueryEx(_process_handle, reinterpret_cast<LPCVOID>(address), &meminfo, sizeof(meminfo)) != 0) {
            if (meminfo.State == MEM_COMMIT) {
                if (meminfo.Type != MEM_IMAGE && (meminfo.Protect & PAGE_EXECUTE_READWRITE) == 0) {
                    memory_protect mp{ .old_protect{}, .new_protect{ PAGE_EXECUTE_READWRITE } };
                    RETURN_IF_WIN32_BOOL_FALSE(::VirtualProtectEx(_process_handle, meminfo.BaseAddress, 1, mp.new_protect, &mp.old_protect));
                    _logger.log_info(std::format(L"Changed memory page ({}) protection ({:#x} -> {:#x}) to set a breakpoint.", meminfo.BaseAddress, mp.old_protect, mp.new_protect));
                    memprotect = mp;
                }
            } else {
                _logger.log_warning(std::format(L"Invalid address for a breakpoint (memory is not committed): {:#x}", address));
                return E_INVALIDARG;
            }
        } else {
            RETURN_LAST_ERROR();
        }

        RETURN_IF_FAILED(dbgbrk->SetOffset(address));
        dbgbrk->SetCommandWide(get_breakpoint_command().c_str());

        RETURN_IF_FAILED(dbgbrk->GetId(&brk_id));
        RETURN_IF_FAILED(dbgbrk->AddFlags(DEBUG_BREAKPOINT_ENABLED | (is_onetime_breakpoint(brk) ? DEBUG_BREAKPOINT_ONE_SHOT : 0)));

        _breakpoints.insert({ brk_id, { brk, address, memprotect } });
        _breakpoint_addresses.insert({ address, brk_id });
    }

    if (id != nullptr) {
        *id = brk_id;
    }
    return S_OK;
}

void comonitor::unset_inner_breakpoint(decltype(_breakpoints)::iterator& iter) {
    auto address{ iter->second.addr };

    if (auto& mp{ iter->second.mem_protect }; mp) {
        if (MEMORY_BASIC_INFORMATION meminfo{}; ::VirtualQueryEx(_process_handle, reinterpret_cast<LPCVOID>(address), &meminfo, sizeof(meminfo)) != 0) {
            // we will revert the memory protection only if it equals the protection we set previously
            if (meminfo.Protect == mp->new_protect) {
                DWORD curr_protect{};
                if (::VirtualProtectEx(_process_handle, meminfo.BaseAddress, 1, mp->old_protect, &curr_protect)) {
                    _logger.log_info(std::format(L"Changed memory page ({}) protection ({:#x} -> {:#x}) when unsetting a breakpoint.",
                        meminfo.BaseAddress, curr_protect, mp->old_protect));
                }
            }
        }
    }

    _breakpoint_addresses.erase(address);
    iter = _breakpoints.erase(iter);
}

HRESULT comonitor::unset_breakpoint(decltype(_breakpoints)::iterator& iter) {
    auto brk_id{ iter->first };

    // the order of operations is important here as dbgsession will get notification about the breakpoint removal
    // and will try to re-remove it from the monitor again
    unset_inner_breakpoint(iter);

    if (IDebugBreakpoint2* bp{}; SUCCEEDED(_dbgcontrol->GetBreakpointById2(brk_id, &bp))) {
        return _dbgcontrol->RemoveBreakpoint2(bp);
    } else {
        return S_OK;
    }
}

HRESULT comonitor::modify_breakpoint_flag(ULONG brk_id, ULONG flag, bool enable) {
    IDebugBreakpoint2* bp;
    RETURN_IF_FAILED(_dbgcontrol->GetBreakpointById2(brk_id, &bp));

    ULONG flags{};
    RETURN_IF_FAILED(bp->GetFlags(&flags));
    flags = enable ? (flags | flag) : (flags & ~flag);
    return bp->SetFlags(flags);
}

HRESULT comonitor::create_cobreakpoint(const CLSID& clsid, const IID& iid, DWORD method_num, cobreakpoint_behavior behavior) {
    if (method_num < 0) {
        return E_INVALIDARG;
    }

    if (auto methods{ _cometa.get_type_methods(iid) }; methods && methods->size() > method_num) {
        auto& method{ methods->at(method_num) };
        if (auto vtable{ _cotype_with_vtables.find({ clsid, iid }) }; vtable != std::end(_cotype_with_vtables)) {
            ULONG64 addr{};
            RETURN_IF_FAILED(_cc.read_pointer(vtable->second + method_num * _cc.get_pointer_size(), addr));

            auto args{ _cometa.get_type_method_args(method) };
            cobreakpoint cobrk{ clsid, iid, method.name, method.callconv, method.return_type,
                args ? *args : method_arg_collection{}, behavior };

            ULONG brk_id{};
            if (auto hr{ set_breakpoint(cobrk, addr, &brk_id) }; SUCCEEDED(hr)) {
                _logger.log_info(std::format(L"Breakpoint {} (address {:#x}) created / updated", brk_id, addr));
                return S_OK;
            } else {
                _logger.log_error(std::format(L"Could not create a breakpoint on address {:#x}", addr), hr);
                return hr;
            }
        } else {
            _logger.log_error(L"No virtual table registered for the given CLSID and IID pair in the current session", E_INVALIDARG);
            return E_INVALIDARG;
        }
    } else {
        _logger.log_error(L"Can't find type information in the metadata", E_INVALIDARG);
        return E_INVALIDARG;
    }
}


bool comonitor::handle_breakpoint(ULONG id) {
    bool handled{};

    if (auto found_brk{ _breakpoints.find(id) }; found_brk != std::end(_breakpoints)) {
        if (auto brk{ found_brk->second.brk }; std::holds_alternative<coquery_single_return_breakpoint>(brk)) {
            handle_coquery_return(std::get<coquery_single_return_breakpoint>(brk));
            handled = true;
        } else if (std::holds_alternative<coregister_return_breakpoint>(brk)) {
            handle_coregister_return(std::get<coregister_return_breakpoint>(brk));
            handled = true;
        } else if (std::holds_alternative<function_breakpoint>(brk)) {
            auto& fbrk{ std::get<function_breakpoint>(brk) };
            if (fbrk.function_name.ends_with(L"!CoRegisterClassObject")) {
                handle_CoRegisterClassObject(fbrk);
                handled = true;
            } else if (fbrk.function_name.ends_with(L"!DllGetClassObject")) {
                handle_DllGetClassObject(fbrk);
                handled = true;
            } else {
                assert(false);
            }
        } else if (std::holds_alternative<cobreakpoint>(brk)) {
            auto& cobrk{ std::get<cobreakpoint>(brk) };
            if (cobrk.method_name == L"QueryInterface") {
                handle_IUnknown_QueryInterface(cobrk.clsid);
                handled = true;
            } else if (cobrk.iid == __uuidof(IClassFactory) && cobrk.method_name == L"CreateInstance") {
                handle_IClassFactory_CreateInstance(cobrk.clsid);
                handled = true;
            } else {
                handled = handle_cobreakpoint(cobrk);
            }
        } else if (std::holds_alternative<cobreakpoint_return>(brk)) {
            handled = handle_cobreakpoint_return(std::get<cobreakpoint_return>(brk));
        } else {
            assert(false);
        }

        if (is_onetime_breakpoint(found_brk->second.brk)) {
            unset_breakpoint(found_brk);
        }
    }

    return handled;
}

void comonitor::handle_coquery_return(const coquery_single_return_breakpoint& brk) {
    call_context::arg_val function_return_code{ L"HRESULT" };
    RETURN_VOID_IF_FAILED(_cc.read_method_return_code(function_return_code));

    if (SUCCEEDED(function_return_code.value)) {
        log_com_call_success(brk.clsid, brk.iid, brk.create_function_name);

        ULONG64 object_addr{};
        RETURN_VOID_IF_FAILED(_cc.read_pointer(brk.object_address_address, object_addr));
        ULONG64 vtbl_addr{};
        RETURN_VOID_IF_FAILED(_cc.read_pointer(object_addr, vtbl_addr));

        register_vtable(brk.clsid, brk.iid, vtbl_addr, true, false);
    } else {
        log_com_call_error(brk.clsid, {}, brk.create_function_name, static_cast<HRESULT>(function_return_code.value));
    }
}

void comonitor::handle_coregister_return(const coregister_return_breakpoint& brk) {
    call_context::arg_val function_return_code{ L"HRESULT" };
    RETURN_VOID_IF_FAILED(_cc.read_method_return_code(function_return_code));

    if (SUCCEEDED(function_return_code.value)) {
        register_vtable(brk.clsid, brk.iid, brk.vtbl_address, true, false);
        log_com_call_success(brk.clsid, brk.iid, brk.register_function_name);
    } else {
        log_com_call_error(brk.clsid, {}, brk.register_function_name, static_cast<HRESULT>(function_return_code.value));
    }
}

bool comonitor::handle_cobreakpoint(const cobreakpoint& brk) {
    std::wstring output_dml{};
    output_dml.reserve(1024);

    if (auto type_name_v{ _cometa.resolve_type_name(brk.iid) }; type_name_v) {
        output_dml.append(std::format(L"[comon breakpoint] <b>{}::{}</b> (iid: {:b}, clsid: {:b})\n", *type_name_v,
            brk.method_name, brk.iid, brk.clsid));
    } else {
        output_dml.append(std::format(L"[comon breakpoint] <b>{:b}::{}</b> (iid: {:b}, clsid: {:b})\n", brk.iid, brk.method_name,
            brk.iid, brk.clsid));
    }

    if (brk.args.size() > 0 && brk.callconv == CALLCONV::CC_STDCALL /* TODO: currently we support only STDCALL */) {
        output_dml.append(L"\nParameters:\n");

        std::vector<call_context::arg_val> arg_vals{};
        arg_vals.reserve(brk.args.size());
        std::ranges::transform(brk.args, std::back_inserter(arg_vals),
            [](const auto& arg) { return call_context::arg_val { arg.type }; });

        ULONG64 return_addr{};
        if (auto hr{ _cc.read_method_frame(brk.callconv, arg_vals, return_addr) }; SUCCEEDED(hr)) {
            std::vector<comethod_arg> out_args{};
            std::vector<call_context::arg_val> out_arg_values{};

            for (auto [arg, arg_val] : views::zip(brk.args, arg_vals)) {
                std::wstring arg_val_text{};
                if (SUCCEEDED(hr = _cc.get_arg_value_in_text(arg_val, arg_val_text))) {
                    output_dml.append(std::format(L"- <b>{}</b>: {}", arg.name, arg_val_text));
                } else {
                    output_dml.append(std::format(L"- <b>{}</b>: error {:#x} when reading the value", arg.name,
                        static_cast<ULONG>(hr)));
                }
                if (arg.flags & (IDLFLAG_FOUT | IDLFLAG_FRETVAL)) {
                    output_dml.append(L" [out]");
                    out_args.push_back(arg);
                    out_arg_values.push_back(arg_val);
                }
                output_dml.append(L"\n");
            }

            bool stop_on_return = brk.behavior == cobreakpoint_behavior::stop_after_call || brk.behavior == cobreakpoint_behavior::always_stop;
            if (FAILED(hr = set_breakpoint(cobreakpoint_return{ brk.clsid, brk.iid, brk.method_name, brk.return_type, out_args,
                out_arg_values, stop_on_return }, return_addr))) {
                _logger.log_error(std::format(L"Error when setting the return breakpoint"), hr);
            }
        } else {
            output_dml.append(std::format(L"Error {:#x} when reading the parameters\n", static_cast<ULONG>(hr)));
        }
    }
    output_dml.append(L"\n");

    _dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL, output_dml.c_str());

    return brk.behavior != cobreakpoint_behavior::stop_before_call && brk.behavior != cobreakpoint_behavior::always_stop;
}

bool comonitor::handle_cobreakpoint_return(const cobreakpoint_return& brk) {
    std::wstring output_dml{};
    output_dml.reserve(1024);

    if (auto type_name_v{ _cometa.resolve_type_name(brk.iid) }; type_name_v) {
        output_dml.append(std::format(L"[comon breakpoint] <b>{}::{}</b> (iid: {:b}, clsid: {:b}) return\n", *type_name_v,
            brk.method_name, brk.iid, brk.clsid));
    } else {
        output_dml.append(std::format(L"[comon breakpoint] <b>{:b}::{}</b> (iid: {:b}, clsid: {:b}) return\n", brk.iid, brk.method_name,
            brk.iid, brk.clsid));
    }

    call_context::arg_val result{ brk.return_type };
    if (auto hr{ _cc.read_method_return_code(result) }; SUCCEEDED(hr)) {
        std::wstring result_val_text{};
        if (SUCCEEDED(hr = _cc.get_arg_value_in_text(result, result_val_text))) {
            output_dml.append(std::format(L"Result: {}\n", result_val_text));
        } else {
            output_dml.append(std::format(L"Result: {:#x}\n", result.value));
        }
    } else {
        output_dml.append(std::format(L"Result: error {:#x} when reading the result\n", hr));
    }

    output_dml.append(L"\nOut parameters:\n");
    assert(brk.out_args.size() == brk.out_arg_values.size());

    for (auto [arg, arg_val] : views::zip(brk.out_args, brk.out_arg_values)) {
        std::wstring arg_val_text{};
        if (auto hr{ _cc.get_arg_value_in_text(arg_val, arg_val_text) }; SUCCEEDED(hr)) {
            output_dml.append(std::format(L"- <b>{}</b>: {}\n", arg.name, arg_val_text));
        } else {
            output_dml.append(std::format(L"- <b>{}</b>: error {:#x} when reading the value\n", arg.name, hr));
        }
    }
    output_dml.append(L"\n");


    _dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL, output_dml.c_str());

    return !brk.should_stop;
}

void comonitor::handle_DllGetClassObject(const function_breakpoint& brk) {
    assert(brk.function_name.ends_with(L"!DllGetClassObject"));
    static const std::vector<std::wstring> arg_types { L"GUID*", L"GUID*", L"void**" };

    std::vector<call_context::arg_val> args{};
    args.reserve(arg_types.size());
    std::ranges::transform(arg_types, std::back_inserter(args), [](const auto& type) { return call_context::arg_val { type }; });

    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(_cc.read_method_frame(CALLCONV::CC_STDCALL, args, return_addr));

    CLSID clsid{};
    RETURN_VOID_IF_FAILED(_cc.read_object(args[0].value, &clsid, sizeof clsid));

    if (is_clsid_allowed(clsid)) {
        IID iid{};
        RETURN_VOID_IF_FAILED(_cc.read_object(args[1].value, &iid, sizeof iid));

        if (auto hr{ set_breakpoint(coquery_single_return_breakpoint{ clsid, iid, args[2].value, brk.function_name }, return_addr) }; FAILED(hr)) {
            _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", brk.function_name), hr);
        }
    }
}

void comonitor::handle_CoRegisterClassObject(const function_breakpoint& brk) {
    assert(brk.function_name.ends_with(L"!CoRegisterClassObject"));
    static const std::vector<std::wstring> arg_types { L"GUID*", L"IUnknown*" }; // we only need the first two

    std::vector<call_context::arg_val> args{};
    args.reserve(arg_types.size());
    std::ranges::transform(arg_types, std::back_inserter(args), [](const auto& type) { return call_context::arg_val { type }; });

    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(_cc.read_method_frame(CALLCONV::CC_STDCALL, args, return_addr));

    CLSID clsid{};
    RETURN_VOID_IF_FAILED(_cc.read_object(args[0].value, &clsid, sizeof clsid));

    if (is_clsid_allowed(clsid)) {
        constexpr IID iid{ __uuidof(IUnknown) };

        ULONG64 vtbl_addr{};
        RETURN_VOID_IF_FAILED(_cc.read_pointer(args[1].value, vtbl_addr));

        if (auto hr{ set_breakpoint(coregister_return_breakpoint{ clsid, iid, vtbl_addr, brk.function_name }, return_addr) }; FAILED(hr)) {
            _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", brk.function_name), hr);
        }
    }
}

void comonitor::handle_IUnknown_QueryInterface(const CLSID& clsid) {
    static const std::wstring_view function_name{ L"IUnknown::QueryInterface" };
    static const std::vector<std::wstring> arg_types { L"IUnknown*", L"GUID*", L"void**" };

    std::vector<call_context::arg_val> args{};
    args.reserve(arg_types.size());
    std::ranges::transform(arg_types, std::back_inserter(args), [](const auto& type) { return call_context::arg_val { type }; });

    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(_cc.read_method_frame(CALLCONV::CC_STDCALL, args, return_addr));

    IID iid{};
    RETURN_VOID_IF_FAILED(_cc.read_object(args[1].value, &iid, sizeof iid));

    if (!_cotype_with_vtables.contains({ clsid, iid })) {
        // we assume here that if previous calls were successful, this one should be as well so no need to wait for the query return
        if (auto hr{ set_breakpoint(coquery_single_return_breakpoint{ clsid, iid, args[2].value, function_name.data() }, return_addr) }; FAILED(hr)) {
            _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", function_name), hr);
        }
    }
};

void comonitor::handle_IClassFactory_CreateInstance(const CLSID& clsid) {
    static const std::wstring_view function_name{ L"IClassFactory::CreateInstance" };
    static const std::vector<std::wstring> arg_types { L"IClassFactory*", L"IUnknown*", L"GUID*", L"void**" };

    std::vector<call_context::arg_val> args{};
    args.reserve(arg_types.size());
    std::ranges::transform(arg_types, std::back_inserter(args), [](const auto& type) { return call_context::arg_val { type }; });

    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(_cc.read_method_frame(CALLCONV::CC_STDCALL, args, return_addr));

    IID iid{};
    RETURN_VOID_IF_FAILED(_cc.read_object(args[2].value, &iid, sizeof iid));

    if (auto hr{ set_breakpoint(coquery_single_return_breakpoint{ clsid, iid, args[3].value, function_name.data() }, return_addr) }; FAILED(hr)) {
        _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", function_name), hr);
    }
}
