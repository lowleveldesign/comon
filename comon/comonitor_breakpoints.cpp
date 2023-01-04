
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
                memory_protect mp{ .old_protect{}, .new_protect{PAGE_EXECUTE_READWRITE} };
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

    ULONG brk_id{};
    RETURN_IF_FAILED(dbgbrk->GetId(&brk_id));
    RETURN_IF_FAILED(dbgbrk->AddFlags(DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_ADDER_ONLY));
    _breakpoints.insert({ brk_id, { brk, address, memprotect } });
    if (id != nullptr) {
        *id = brk_id;
    }
    return S_OK;
}


HRESULT comonitor::unset_breakpoint(decltype(_breakpoints)::iterator& iter) {
    IDebugBreakpoint2* bp;
    RETURN_IF_FAILED(_dbgcontrol->GetBreakpointById2(iter->first, &bp));
    RETURN_IF_FAILED(_dbgcontrol->RemoveBreakpoint2(bp));

    if (auto& mp{ iter->second.mem_protect }; mp) {
        auto address{ iter->second.addr };
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

    iter = _breakpoints.erase(iter);

    return S_OK;
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
        } else if (std::holds_alternative<IUnknown_QueryInterface_breakpoint>(brk)) {
            handle_IUnknown_QueryInterface(std::get<IUnknown_QueryInterface_breakpoint>(brk));
        } else if (std::holds_alternative<IClassFactory_CreateInstance_breakpoint>(brk)) {
            handle_IClassFactory_CreateInstance(std::get<IClassFactory_CreateInstance_breakpoint>(brk));
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
    call_context cc{ _dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch };

    HRESULT function_return_code{};
    RETURN_VOID_IF_FAILED(cc.read_method_return_code(function_return_code));

    if (SUCCEEDED(function_return_code)) {
        log_com_call_success(brk.clsid, brk.iid, brk.create_function_name);

        if (!_cotype_with_vtables.contains({ brk.clsid, brk.iid })) {
            ULONG64 object_addr{};
            RETURN_VOID_IF_FAILED(cc.read_pointer(brk.object_address_address, object_addr));
            ULONG64 vtbl_addr{};
            RETURN_VOID_IF_FAILED(cc.read_pointer(object_addr, vtbl_addr));

            register_vtable(brk.clsid, brk.iid, vtbl_addr, true);
        }
    } else {
        log_com_call_error(brk.clsid, {}, brk.create_function_name, function_return_code);
    }
}

void comonitor::handle_coregister_return(const coregister_return_breakpoint& brk) {
    call_context cc{ _dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch };

    HRESULT function_return_code{};
    RETURN_VOID_IF_FAILED(cc.read_method_return_code(function_return_code));

    if (SUCCEEDED(function_return_code)) {
        if (!_cotype_with_vtables.contains({ brk.clsid, brk.iid })) {
            register_vtable(brk.clsid, brk.iid, brk.vtbl_address, true);
        }
        log_com_call_success(brk.clsid, brk.iid, brk.register_function_name);
    } else {
        log_com_call_error(brk.clsid, {}, brk.register_function_name, function_return_code);
    }
}

void comonitor::handle_DllGetClassObject(const function_breakpoint& brk) {
    assert(brk.function_name.ends_with(L"!DllGetClassObject"));

    call_context cc{ _dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch };

    std::vector<ULONG64> args(3);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    CLSID clsid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[0], &clsid, sizeof clsid));
    IID iid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[1], &iid, sizeof iid));

    if (auto hr{ set_breakpoint(coquery_single_return_breakpoint{clsid, iid, args[2], brk.function_name }, return_addr) }; FAILED(hr)) {
        _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", brk.function_name), hr);
    }
}

void comonitor::handle_CoRegisterClassObject(const function_breakpoint& brk) {
    assert(brk.function_name == L"CoRegisterClassObject");

    call_context cc{ _dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch };

    std::vector<ULONG64> args(2);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    CLSID clsid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[0], &clsid, sizeof clsid));

    constexpr IID iid{ __uuidof(IUnknown) };

    ULONG64 vtbl_addr{};
    RETURN_VOID_IF_FAILED(cc.read_pointer(args[1], vtbl_addr));

    if (auto hr{ set_breakpoint(coregister_return_breakpoint{clsid, iid, vtbl_addr, brk.function_name }, return_addr) }; FAILED(hr)) {
        _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", brk.function_name), hr);
    }
}

void comonitor::handle_IUnknown_QueryInterface(const IUnknown_QueryInterface_breakpoint& brk) {
    static const std::wstring_view function_name{ L"IUnknown::QueryInterface" };

    call_context cc{ _dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch };

    std::vector<ULONG64> args(3);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    IID iid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[1], &iid, sizeof iid));

    if (auto hr{ set_breakpoint(coquery_single_return_breakpoint{brk.clsid, iid, args[2], function_name.data()}, return_addr) }; FAILED(hr)) {
        _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", function_name), hr);
    }
};

void comonitor::handle_IClassFactory_CreateInstance(const IClassFactory_CreateInstance_breakpoint& brk) {
    static const std::wstring_view function_name{ L"IClassFactory::CreateInstance" };

    call_context cc{ _dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch };

    std::vector<ULONG64> args(5);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    IID iid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[2], &iid, sizeof iid));

    if (auto hr{ set_breakpoint(coquery_single_return_breakpoint{brk.clsid, iid, args[3], function_name.data() }, return_addr) }; FAILED(hr)) {
        _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", function_name), hr);
    }
}
