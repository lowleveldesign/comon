
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

HRESULT comonitor::set_breakpoint(const breakpoint &brk, PULONG id) {
    IDebugBreakpoint2 *dbgbrk{};
    RETURN_IF_FAILED(_dbgcontrol->AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &dbgbrk));
    ULONG64 address{};
    if (std::holds_alternative<function_breakpoint>(brk)) {
        address = std::get<function_breakpoint>(brk).address;
    } else if (std::holds_alternative<GetClassFile_breakpoint>(brk)) {
        auto &b{std::get<GetClassFile_breakpoint>(brk)};
        RETURN_IF_FAILED(dbgbrk->SetMatchThreadId(b.match_thread_id));
        address = b.address;
    } else if (std::holds_alternative<coquery_single_return_breakpoint>(brk)) {
        address = std::get<coquery_single_return_breakpoint>(brk).address;
    } else if (std::holds_alternative<coquery_multi_return_breakpoint>(brk)) {
        address = std::get<coquery_multi_return_breakpoint>(brk).address;
    } else if (std::holds_alternative<coregister_return_breakpoint>(brk)) {
        address = std::get<coregister_return_breakpoint>(brk).address;
    } else if (std::holds_alternative<GetClassFile_return_breakpoint>(brk)) {
        auto &b{std::get<GetClassFile_return_breakpoint>(brk)};
        address = b.address;
        RETURN_IF_FAILED(dbgbrk->SetMatchThreadId(b.match_thread_id));
    } else if (std::holds_alternative<IUnknown_QueryInterface_breakpoint>(brk)) {
        address = std::get<IUnknown_QueryInterface_breakpoint>(brk).address;
    } else if (std::holds_alternative<IClassFactory_CreateInstance_breakpoint>(brk)) {
        address = std::get<IClassFactory_CreateInstance_breakpoint>(brk).address;
    } else {
        assert(false);
    }

    RETURN_IF_FAILED(dbgbrk->SetOffset(address));

    ULONG brk_id{};
    RETURN_IF_FAILED(dbgbrk->GetId(&brk_id));
    auto flags = DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_ADDER_ONLY | (is_onetime_breakpoint(brk) ? DEBUG_BREAKPOINT_ONE_SHOT : 0);
    RETURN_IF_FAILED(dbgbrk->AddFlags(flags));
    _breakpoints.insert({brk_id, brk});
    if (id != nullptr) {
        *id = brk_id;
    }
    return S_OK;
}

bool comonitor::handle_breakpoint(ULONG id) {
    if (auto found_brk{_breakpoints.find(id)}; found_brk != std::end(_breakpoints)) {
        if (auto brk{found_brk->second}; std::holds_alternative<coquery_single_return_breakpoint>(brk)) {
            handle_coquery_return(std::get<coquery_single_return_breakpoint>(brk));
        } else if (std::holds_alternative<coquery_multi_return_breakpoint>(brk)) {
            handle_coquery_return(std::get<coquery_multi_return_breakpoint>(brk));
        } else if (std::holds_alternative<coregister_return_breakpoint>(brk)) {
            handle_coregister_return(std::get<coregister_return_breakpoint>(brk));
        } else if (std::holds_alternative<function_breakpoint>(brk)) {
            auto &fbrk{std::get<function_breakpoint>(brk)};
            if (fbrk.function_name == L"CoCreateInstance") {
                handle_CoCreateInstance(fbrk);
            } else if (fbrk.function_name == L"CoGetClassObject") {
                handle_CoGetClassObject(fbrk);
            } else if (fbrk.function_name == L"CoGetInstanceFromFile") {
                handle_CoGetInstanceFromFile(fbrk);
            } else if (fbrk.function_name == L"CoRegisterClassObject") {
                handle_CoRegisterClassObject(fbrk);
            } else {
                assert(false);
            }
        } else if (std::holds_alternative<IUnknown_QueryInterface_breakpoint>(brk)) {
            handle_IUnknown_QueryInterface(std::get<IUnknown_QueryInterface_breakpoint>(brk));
        } else if (std::holds_alternative<IClassFactory_CreateInstance_breakpoint>(brk)) {
            handle_IClassFactory_CreateInstance(std::get<IClassFactory_CreateInstance_breakpoint>(brk));
        } else if (std::holds_alternative<GetClassFile_breakpoint>(brk)) {
            handle_GetClassFile(std::get<GetClassFile_breakpoint>(brk));
        } else if (std::holds_alternative<GetClassFile_return_breakpoint>(brk)) {
            handle_GetClassFile_return(std::get<GetClassFile_return_breakpoint>(brk));
        } else {
            assert(false);
        }

        if (is_onetime_breakpoint(found_brk->second)) {
            _breakpoints.erase(found_brk);
        }

        return true;
    } else {
        return false;
    }
}

void comonitor::handle_coquery_return(const coquery_single_return_breakpoint &brk) {
    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    HRESULT function_return_code{};
    RETURN_VOID_IF_FAILED(cc.read_method_return_code(function_return_code));

    if (SUCCEEDED(function_return_code)) {
        log_com_call_success(brk.clsid, brk.iid, brk.create_function_name);

        if (!_cotype_with_vtables.contains({brk.clsid, brk.iid})) {
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

void comonitor::handle_coquery_return(const coquery_multi_return_breakpoint &brk) {
    if (brk.clsid == CLSID{}) {
        _logger.log_error_dml(std::format(L"CLSID was not resolved for function {}", brk.create_function_name), E_INVALIDARG);
        return;
    }

    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    HRESULT function_return_code{};
    RETURN_VOID_IF_FAILED(cc.read_method_return_code(function_return_code));

    if (SUCCEEDED(function_return_code) || function_return_code == CO_S_NOTALLINTERFACES) {
        const auto ptr_size = cc.get_pointer_size();
        const auto mqi_size = 3 * ptr_size;
        for (auto offset = brk.results_address; offset < brk.results_address + brk.results_count * mqi_size; offset += mqi_size) {
            ULONG64 iid_ptr{};
            RETURN_VOID_IF_FAILED(cc.read_pointer(offset, iid_ptr));
            IID iid{};
            RETURN_VOID_IF_FAILED(cc.read_object(iid_ptr, &iid, sizeof iid));

            ULONG64 object_addr{};
            RETURN_VOID_IF_FAILED(cc.read_pointer(offset + ptr_size, object_addr));

            HRESULT hr{};
            RETURN_VOID_IF_FAILED(cc.read_object(offset + 2 * ptr_size, &hr, sizeof hr));

            if (SUCCEEDED(hr)) {
                log_com_call_success(brk.clsid, iid, brk.create_function_name);
                if (!_cotype_with_vtables.contains({brk.clsid, iid})) {
                    ULONG64 vtbl_addr{};
                    RETURN_VOID_IF_FAILED(cc.read_pointer(object_addr, vtbl_addr));
                    register_vtable(brk.clsid, iid, vtbl_addr, true);
                }
            } else {
                log_com_call_error(brk.clsid, iid, brk.create_function_name, hr);
            }
        }
    } else {
        log_com_call_error(brk.clsid, {}, brk.create_function_name, function_return_code);
    }
}

void comonitor::handle_coregister_return(const coregister_return_breakpoint &brk) {
    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    HRESULT function_return_code{};
    RETURN_VOID_IF_FAILED(cc.read_method_return_code(function_return_code));

    if (SUCCEEDED(function_return_code)) {
        if (!_cotype_with_vtables.contains({brk.clsid, brk.iid})) {
            register_vtable(brk.clsid, brk.iid, brk.vtbl_address, true);
        }
        log_com_call_success(brk.clsid, brk.iid, brk.register_function_name);
    } else {
        log_com_call_error(brk.clsid, {}, brk.register_function_name, function_return_code);
    }
}

void comonitor::handle_CoCreateInstance(const function_breakpoint &brk) {
    assert(brk.function_name == L"CoCreateInstance");

    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    std::vector<ULONG64> args(5);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    CLSID clsid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[0], &clsid, sizeof clsid));
    IID iid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[3], &iid, sizeof iid));

    if (auto hr{set_breakpoint(coquery_single_return_breakpoint{clsid, iid, args[4], brk.function_name, return_addr})}; FAILED(hr)) {
        _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", brk.function_name), hr);
    }
}

void comonitor::handle_CoGetClassObject(const function_breakpoint &brk) {
    assert(brk.function_name == L"CoGetClassObject");

    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    std::vector<ULONG64> args(5);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    CLSID clsid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[0], &clsid, sizeof clsid));
    IID iid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[3], &iid, sizeof iid));

    if (auto hr{set_breakpoint(coquery_single_return_breakpoint{clsid, iid, args[4], brk.function_name, return_addr})}; FAILED(hr)) {
        _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", brk.function_name), hr);
    }
}

void comonitor::handle_CoGetInstanceFromFile(const function_breakpoint &brk) {
    assert(brk.function_name == L"CoGetInstanceFromFile");

    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    std::vector<ULONG64> args(8);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    DWORD results_cnt = static_cast<DWORD>(args[6]);

    auto results_addr{args[7]};

    auto is_clsid_provided = args[1] != 0;
    CLSID clsid{};
    if (is_clsid_provided) {
        RETURN_VOID_IF_FAILED(cc.read_object(args[1], &clsid, sizeof clsid));
    }

    ULONG brk_id{};
    if (auto hr{set_breakpoint(coquery_multi_return_breakpoint{clsid, results_cnt, results_addr, brk.function_name, return_addr}, &brk_id)};
        SUCCEEDED(hr)) {
        if (!is_clsid_provided) {
            ULONG tid{};
            RETURN_VOID_IF_FAILED(_dbgsystemobjects->GetCurrentThreadId(&tid));

            ULONG64 address;
            RETURN_VOID_IF_FAILED(_dbgsymbols->GetOffsetByNameWide(L"ole32!GetClassFile", &address));

            hr = set_breakpoint(GetClassFile_breakpoint{brk_id, tid, address});
            if (FAILED(hr)) {
                _logger.log_error_dml(L"Error when setting GetClassFile breakpoint", hr);
            }
        }
    } else {
        _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", brk.function_name), hr);
    }
}

void comonitor::handle_CoRegisterClassObject(const function_breakpoint &brk) {
    assert(brk.function_name == L"CoRegisterClassObject");

    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    std::vector<ULONG64> args(2);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    CLSID clsid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[0], &clsid, sizeof clsid));

    constexpr IID iid{__uuidof(IUnknown)};

    ULONG64 vtbl_addr{};
    RETURN_VOID_IF_FAILED(cc.read_pointer(args[1], vtbl_addr));

    if (auto hr{set_breakpoint(coregister_return_breakpoint{clsid, iid, vtbl_addr, brk.function_name, return_addr})}; FAILED(hr)) {
        _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", brk.function_name), hr);
    }
}

void comonitor::handle_IUnknown_QueryInterface(const IUnknown_QueryInterface_breakpoint &brk) {
    static const std::wstring_view function_name{L"IUnknown::QueryInterface"};

    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    std::vector<ULONG64> args(3);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    IID iid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[1], &iid, sizeof iid));

    if (auto hr{set_breakpoint(coquery_single_return_breakpoint{brk.clsid, iid, args[2], function_name.data(), return_addr})}; FAILED(hr)) {
        _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", function_name), hr);
    }
};

void comonitor::handle_IClassFactory_CreateInstance(const IClassFactory_CreateInstance_breakpoint &brk) {
    static const std::wstring_view function_name{L"IClassFactory::CreateInstance"};

    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    std::vector<ULONG64> args(5);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    IID iid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[2], &iid, sizeof iid));

    if (auto hr{set_breakpoint(coquery_single_return_breakpoint{brk.clsid, iid, args[3], function_name.data(), return_addr})}; FAILED(hr)) {
        _logger.log_error_dml(std::format(L"Error when setting return breakpoint from {}", function_name), hr);
    }
}

void comonitor::handle_GetClassFile(const GetClassFile_breakpoint &brk) {
    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    std::vector<ULONG64> args(2);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    RETURN_VOID_IF_FAILED(
        set_breakpoint(GetClassFile_return_breakpoint{brk.referenced_breakpoint_id, brk.match_thread_id, args[1], return_addr}));
}

void comonitor::handle_GetClassFile_return(const GetClassFile_return_breakpoint &brk) {
    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    CLSID clsid{};
    RETURN_VOID_IF_FAILED(cc.read_object(brk.CLSID_address, &clsid, sizeof clsid));

    auto &b{_breakpoints.at(brk.referenced_breakpoint_id)};
    assert(std::holds_alternative<coquery_multi_return_breakpoint>(b));
    auto &refbrk{std::get<coquery_multi_return_breakpoint>(b)};

    breakpoint new_refbrk{
        coquery_multi_return_breakpoint{clsid, refbrk.results_count, refbrk.results_address, refbrk.create_function_name, refbrk.address}};
    _breakpoints.erase(brk.referenced_breakpoint_id);
    _breakpoints.insert({brk.referenced_breakpoint_id, new_refbrk});
}
