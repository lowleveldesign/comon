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
        } else if (std::holds_alternative<cointerface_method_breakpoint>(brk)) {
            auto& cmbrk{ std::get<cointerface_method_breakpoint>(brk) };
            return std::format(L"* [comon] interface breakpoint (CLSID: {:b}, IID: {:b}, method: {})",
                cmbrk.clsid, cmbrk.iid, cmbrk.method_name);
        } else {
            assert(false);
            return std::wstring{};
        }
    };

    ULONG brk_id{};

    if (auto found_brk_id{ _breakpoint_addresses.find(address) }; found_brk_id != std::end(_breakpoint_addresses)) {
        brk_id = found_brk_id->second;
        assert(_breakpoints.contains(brk_id));
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

bool comonitor::handle_breakpoint(ULONG id) {
    if (auto found_brk{ _breakpoints.find(id) }; found_brk != std::end(_breakpoints)) {
        if (auto brk{ found_brk->second.brk }; std::holds_alternative<coquery_single_return_breakpoint>(brk)) {
            handle_coquery_return(std::get<coquery_single_return_breakpoint>(brk));
        } else if (std::holds_alternative<coregister_return_breakpoint>(brk)) {
            handle_coregister_return(std::get<coregister_return_breakpoint>(brk));
        } else if (std::holds_alternative<function_breakpoint>(brk)) {
            auto& fbrk{ std::get<function_breakpoint>(brk) };
            if (fbrk.function_name.ends_with(L"!CoRegisterClassObject")) {
                handle_CoRegisterClassObject(fbrk);
            } else if (fbrk.function_name.ends_with(L"!DllGetClassObject")) {
                handle_DllGetClassObject(fbrk);
            } else {
                assert(false);
            }
        } else if (std::holds_alternative<cointerface_method_breakpoint>(brk)) {
            auto& cmbrk{ std::get<cointerface_method_breakpoint>(brk) };
            if (cmbrk.method_name == L"QueryInterface") {
                handle_IUnknown_QueryInterface(cmbrk.clsid);
            } else if (cmbrk.iid == __uuidof(IClassFactory) && cmbrk.method_name == L"CreateInstance") {
                handle_IClassFactory_CreateInstance(cmbrk.clsid);
            } else {
                assert(false);
            }
        } else {
            assert(false);
        }

        if (is_onetime_breakpoint(found_brk->second.brk)) {
            unset_breakpoint(found_brk);
        }

        return true;
    } else {
        return false;
    }
}

void comonitor::handle_coquery_return(const coquery_single_return_breakpoint& brk) {
    HRESULT function_return_code{};
    RETURN_VOID_IF_FAILED(_cc.read_method_return_code(function_return_code));

    if (SUCCEEDED(function_return_code)) {
        log_com_call_success(brk.clsid, brk.iid, brk.create_function_name);

        ULONG64 object_addr{};
        RETURN_VOID_IF_FAILED(_cc.read_pointer(brk.object_address_address, object_addr));
        ULONG64 vtbl_addr{};
        RETURN_VOID_IF_FAILED(_cc.read_pointer(object_addr, vtbl_addr));

        register_vtable(brk.clsid, brk.iid, vtbl_addr, true, false);
    } else {
        log_com_call_error(brk.clsid, {}, brk.create_function_name, function_return_code);
    }
}

void comonitor::handle_coregister_return(const coregister_return_breakpoint& brk) {
    HRESULT function_return_code{};
    RETURN_VOID_IF_FAILED(_cc.read_method_return_code(function_return_code));

    if (SUCCEEDED(function_return_code)) {
        register_vtable(brk.clsid, brk.iid, brk.vtbl_address, true, false);
        log_com_call_success(brk.clsid, brk.iid, brk.register_function_name);
    } else {
        log_com_call_error(brk.clsid, {}, brk.register_function_name, function_return_code);
    }
}

void comonitor::handle_DllGetClassObject(const function_breakpoint& brk) {
    assert(brk.function_name.ends_with(L"!DllGetClassObject"));

    std::vector<ULONG64> args(3);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(_cc.read_method_frame(args, return_addr));

    CLSID clsid{};
    RETURN_VOID_IF_FAILED(_cc.read_object(args[0], &clsid, sizeof clsid));

    if (is_clsid_allowed(clsid)) {
        IID iid{};
        RETURN_VOID_IF_FAILED(_cc.read_object(args[1], &iid, sizeof iid));

        if (auto hr{ set_breakpoint(coquery_single_return_breakpoint{ clsid, iid, args[2], brk.function_name }, return_addr) }; FAILED(hr)) {
            _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", brk.function_name), hr);
        }
    }
}

void comonitor::handle_CoRegisterClassObject(const function_breakpoint& brk) {
    assert(brk.function_name.ends_with(L"!CoRegisterClassObject"));

    std::vector<ULONG64> args(2);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(_cc.read_method_frame(args, return_addr));

    CLSID clsid{};
    RETURN_VOID_IF_FAILED(_cc.read_object(args[0], &clsid, sizeof clsid));

    if (is_clsid_allowed(clsid)) {
        constexpr IID iid{ __uuidof(IUnknown) };

        ULONG64 vtbl_addr{};
        RETURN_VOID_IF_FAILED(_cc.read_pointer(args[1], vtbl_addr));

        if (auto hr{ set_breakpoint(coregister_return_breakpoint{ clsid, iid, vtbl_addr, brk.function_name }, return_addr) }; FAILED(hr)) {
            _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", brk.function_name), hr);
        }
    }
}

void comonitor::handle_IUnknown_QueryInterface(const CLSID& clsid) {
    static const std::wstring_view function_name{ L"IUnknown::QueryInterface" };

    std::vector<ULONG64> args(3);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(_cc.read_method_frame(args, return_addr));

    IID iid{};
    RETURN_VOID_IF_FAILED(_cc.read_object(args[1], &iid, sizeof iid));

    if (!_cotype_with_vtables.contains({ clsid, iid })) {
        // we assume here that if previous calls were successful, this one should be as well so no need to wait for the query return
        if (auto hr{ set_breakpoint(coquery_single_return_breakpoint{ clsid, iid, args[2], function_name.data() }, return_addr) }; FAILED(hr)) {
            _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", function_name), hr);
        }
    }
};

void comonitor::handle_IClassFactory_CreateInstance(const CLSID& clsid) {
    static const std::wstring_view function_name{ L"IClassFactory::CreateInstance" };

    std::vector<ULONG64> args(5);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(_cc.read_method_frame(args, return_addr));

    IID iid{};
    RETURN_VOID_IF_FAILED(_cc.read_object(args[2], &iid, sizeof iid));

    if (auto hr{ set_breakpoint(coquery_single_return_breakpoint{ clsid, iid, args[3], function_name.data() }, return_addr) }; FAILED(hr)) {
        _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", function_name), hr);
    }
}
