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
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>

#include <DbgEng.h>
#include <Windows.h>
#include <wil/com.h>
#include <wil/result.h>

#include "comon.h"
#include "comonitor.h"

using namespace comon_ext;

namespace views = std::ranges::views;
namespace fs = std::filesystem;

arch comonitor::get_process_arch(IDebugControl4 *dbgcontrol, IDebugSymbols3 *dbgsymbols, IDebugRegisters2 *dbgregisters) {
    auto init_arch_x86 = [dbgcontrol, dbgregisters](bool is_wow64) {
        ULONG eax, esp;
        THROW_IF_FAILED(dbgregisters->GetIndexByName("eax", &eax));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("esp", &esp));
        return arch_x86{IMAGE_FILE_MACHINE_I386, is_wow64, esp, eax};
    };

    auto init_arch_x64 = [dbgcontrol, dbgregisters]() {
        ULONG rax, rsp, rcx, rdx, r8, r9;
        THROW_IF_FAILED(dbgregisters->GetIndexByName("rax", &rax));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("rsp", &rsp));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("rcx", &rcx));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("rdx", &rdx));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("r8", &r8));
        THROW_IF_FAILED(dbgregisters->GetIndexByName("r9", &r9));

        return arch_x64{IMAGE_FILE_MACHINE_AMD64, rcx, rdx, r8, r9, rsp, rax};
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
        return is_wow64 ? arch{init_arch_x86(true)} : arch{init_arch_x64()};
    } else {
        throw std::invalid_argument{"unsupported effective CPU architecture"};
    }
}

comonitor::comonitor(IDebugClient5 *dbgclient, std::shared_ptr<cometa> cometa, std::shared_ptr<cofilter> log_filter)
    : _dbgclient{dbgclient}, _dbgcontrol{_dbgclient.query<IDebugControl4>()}, _dbgsymbols{_dbgclient.query<IDebugSymbols3>()},
      _dbgdataspaces{_dbgclient.query<IDebugDataSpaces>()}, _dbgsystemobjects{_dbgclient.query<IDebugSystemObjects>()},
      _dbgregisters{_dbgclient.query<IDebugRegisters2>()}, _cometa{cometa}, _log_filter{log_filter}, _logger{_dbgcontrol.get()},
      _arch{get_process_arch(_dbgcontrol.get(), _dbgsymbols.get(), _dbgregisters.get())} {
    if (ULONG loaded_modules_cnt, unloaded_modules_cnt;
        SUCCEEDED(_dbgsymbols->GetNumberModules(&loaded_modules_cnt, &unloaded_modules_cnt))) {
        std::vector<DEBUG_MODULE_PARAMETERS> modules(loaded_modules_cnt);
        if (auto hr{_dbgsymbols->GetModuleParameters(loaded_modules_cnt, nullptr, 0, modules.data())}; SUCCEEDED(hr)) {
            for (auto &m : modules) {
                if (auto buffer{std::make_unique<wchar_t[]>(m.ModuleNameSize)}; SUCCEEDED(_dbgsymbols->GetModuleNameStringWide(
                        DEBUG_MODNAME_MODULE, DEBUG_ANY_ID, m.Base, buffer.get(), m.ModuleNameSize, nullptr))) {
                    handle_module_load({buffer.get(), m.ModuleNameSize - 1}, m.TimeDateStamp, m.Base);
                }
            }
        } else {
            _logger.log_error(L"Error when retrieving information about module.", hr);
        }
    }

    for (const auto &m : {L"combase!CoCreateInstance", L"combase!CoGetClassObject"}) {
        if (auto hr{set_breakpoint(function_breakpoint{m})}; FAILED(hr)) {
            _logger.log_error(std::format(L"Failed to set a breakpoint on method '{}'", m), hr);
        }
    }
}

comonitor::~comonitor() {
    for (auto iter{std::begin(_breakpoints)}; iter != std::end(_breakpoints);) {
        if (auto hr{unset_breakpoint(iter)}; FAILED(hr)) {
            LOG_HR(hr);
            iter++;
        }
    }
    _cotype_with_vtables.clear();
}

HRESULT comonitor::set_breakpoint(const breakpoint &brk, PULONG id) {
    bool one_time{};

    IDebugBreakpoint2 *dbgbrk{};
    RETURN_IF_FAILED(_dbgcontrol->AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &dbgbrk));
    if (std::holds_alternative<function_breakpoint>(brk)) {
        RETURN_IF_FAILED(dbgbrk->SetOffsetExpressionWide(std::get<function_breakpoint>(brk).function_name.c_str()));
    } else {
        ULONG64 address{};
        if (std::holds_alternative<function_return_breakpoint>(brk)) {
            address = std::get<function_return_breakpoint>(brk).address;
            one_time = true;
        } else if (std::holds_alternative<IUnknown_QueryInterface_breakpoint>(brk)) {
            address = std::get<IUnknown_QueryInterface_breakpoint>(brk).address;
        } else if (std::holds_alternative<IClassFactory_CreateInstance_breakpoint>(brk)) {
            address = std::get<IClassFactory_CreateInstance_breakpoint>(brk).address;
        } else {
            assert(false);
        }
        RETURN_IF_FAILED(dbgbrk->SetOffset(address));
    }
    ULONG brk_id{};
    RETURN_IF_FAILED(dbgbrk->GetId(&brk_id));
    auto flags = DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_ADDER_ONLY | (one_time ? DEBUG_BREAKPOINT_ONE_SHOT : 0);
    RETURN_IF_FAILED(dbgbrk->AddFlags(flags));
    _breakpoints.insert({brk_id, brk});
    if (id != nullptr) {
        *id = brk_id;
    }
    return S_OK;
}

HRESULT comonitor::create_cobreakpoint(const CLSID &clsid, const IID &iid, DWORD method_num, std::wstring_view method_display_name) {
    assert(method_num >= 0);
    if (auto vtable{_cotype_with_vtables.find({clsid, iid})}; vtable != std::end(_cotype_with_vtables)) {
        call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};
        ULONG64 addr{};
        RETURN_IF_FAILED(cc.read_pointer(vtable->second + method_num * cc.get_pointer_size(), addr));

        IDebugBreakpoint2 *brk{};
        RETURN_IF_FAILED(_dbgcontrol->AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &brk));
        RETURN_IF_FAILED(brk->SetOffset(addr));

        auto clsid_name{_cometa->resolve_class_name(clsid)};
        auto iid_name{_cometa->resolve_type_name(iid)};
        auto cmd{std::format(
            L".printf /D \"== Method <b>{} [{}]</b> called on a COM object (CLSID: <b>{:b} ({})</b>, IID <b>{:b} ({})</b>) ==\"; .echo",
            method_display_name, method_num, iid, iid_name ? *iid_name : L"N/A", clsid, clsid_name ? *clsid_name : L"N/A")};
        RETURN_IF_FAILED(brk->SetCommandWide(cmd.c_str()));

        ULONG brk_id{};
        RETURN_IF_FAILED(brk->GetId(&brk_id));
        RETURN_IF_FAILED(brk->AddFlags(DEBUG_BREAKPOINT_ENABLED));

        return S_OK;
    } else {
        return E_INVALIDARG;
    }
}

HRESULT comonitor::create_cobreakpoint(const CLSID &clsid, const IID &iid, DWORD method_num) {
    if (method_num < 0) {
        return E_INVALIDARG;
    }

    auto cotype{_cometa->resolve_type(iid)};

    std::wstring method_name{};
    if (cotype && cotype->methods_available) {
        if (auto methods{_cometa->get_type_methods(iid)}; methods && methods->size() > method_num) {
            method_name = methods->at(method_num);
        }
    }
    return create_cobreakpoint(clsid, iid, method_num, method_name);
}

HRESULT comonitor::create_cobreakpoint(const CLSID &clsid, const IID &iid, std::wstring_view method_name) {
    if (auto methods{_cometa->get_type_methods(iid)}; methods) {
        if (auto res{std::ranges::find(*methods, method_name)}; res != std::end(*methods)) {
            auto method_num = static_cast<DWORD>(res - std::begin(*methods));
            return create_cobreakpoint(clsid, iid, method_num, method_name);
        } else {
            _logger.log_error(L"Could not resolve the method name.", E_INVALIDARG);
            return E_INVALIDARG;
        }
    } else {
        _logger.log_error(L"No methods found for the type.", E_INVALIDARG);
        return E_INVALIDARG;
    }
}

HRESULT comonitor::register_vtable(const CLSID &clsid, const IID &iid, ULONG64 vtable_addr, bool save_in_database) {
    // the vtable might have been already added by the IClassFactory_CreateInstance method
    if (!_cotype_with_vtables.contains({clsid, iid})) {

        // save info about vtable in the database
        if (ULONG64 base_addr{}; save_in_database && SUCCEEDED(_dbgsymbols->GetModuleByOffset2(
                                                         vtable_addr, 0, DEBUG_GETMOD_NO_UNLOADED_MODULES, nullptr, &base_addr))) {

            std::wstring module_name;
            ULONG module_size{}, module_timestamp{};
            if (auto hr{get_module_info(base_addr, module_name, module_timestamp, module_size)}; SUCCEEDED(hr)) {
                _cometa->save_module_vtable({module_name, module_timestamp, std::holds_alternative<arch_x64>(_arch)},
                                            {clsid, iid, vtable_addr - base_addr});
            } else {
                LOG_HR(hr);
            }
        } else {
            _logger.log_warning(std::format(L"Virtual table address {:x} does not belong to any module.", vtable_addr));
        }

        call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

        // the first method is always the QueryInterface and we need to break on cv_it
        ULONG64 fn_address{};
        RETURN_IF_FAILED(cc.read_pointer(vtable_addr, fn_address));

        if (_log_filter->is_clsid_allowed(clsid)) {
            ULONG brk_id{};
            if (auto hr{set_breakpoint(IUnknown_QueryInterface_breakpoint{clsid, iid, fn_address}, &brk_id)}; FAILED(hr)) {
                _logger.log_error(std::format(L"Failed to set a breakpoint on QueryInterface method (CLSID: {:b}, IID: {:b})", clsid, iid), hr);
            }
        }

        _cotype_with_vtables.insert({{clsid, iid}, vtable_addr});

        // special case for IClassFactory when we need to set breakpoint on the CreateInstance (4th method in the vtbl)
        if (iid == __uuidof(IClassFactory) && SUCCEEDED((cc.read_pointer(vtable_addr + 3 * cc.get_pointer_size(), fn_address)))) {
            if (auto hr{set_breakpoint(IClassFactory_CreateInstance_breakpoint{clsid, fn_address})}; FAILED(hr)) {
                _logger.log_error(std::format(L"Failed to set a breakpoint on CreateInstance method (CLSID: {:b})", clsid), hr);
            }
        }
    } else {
        // a given vtable could be used by a different pair <CLSID, IID>,
        // so we always update the cotypes vtables map
        _cotype_with_vtables[{clsid, iid}] = vtable_addr;
    }

    return S_OK;
}

void comonitor::pause() noexcept {
    for (const auto &[brk_id, brk] : _breakpoints) {
        if (std::holds_alternative<function_return_breakpoint>(brk)) {
            continue;
        }
        if (auto hr{modify_breakpoint_flag(brk_id, DEBUG_BREAKPOINT_ENABLED, false)}; FAILED(hr)) {
            _logger.log_error(std::format(L"Error when modifying flag for breakpoint {}", brk_id), hr);
        }
    }
}

void comonitor::resume() noexcept {
    for (const auto &[brk_id, brk] : _breakpoints) {
        if (std::holds_alternative<function_return_breakpoint>(brk)) {
            continue;
        }
        if (auto hr{modify_breakpoint_flag(brk_id, DEBUG_BREAKPOINT_ENABLED, true)}; FAILED(hr)) {
            _logger.log_error(std::format(L"Error when modifying flag for breakpoint {}", brk_id), hr);
        }
    }
}

void comonitor::handle_module_load(std::wstring_view module_name, ULONG module_timestamp, ULONG64 module_base_addr) {
    for (auto &[clsid, iid, vtable] :
         _cometa->get_module_vtables({module_name, module_timestamp, std::holds_alternative<arch_x64>(_arch)})) {
        if (_log_filter->is_clsid_allowed(clsid)) {
            call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};
            if (ULONG64 fn_query_interface{}; SUCCEEDED(cc.read_pointer(module_base_addr + vtable, fn_query_interface))) {
                if (auto hr{set_breakpoint(IUnknown_QueryInterface_breakpoint{clsid, iid, fn_query_interface})}; FAILED(hr)) {
                    _logger.log_error(
                        std::format(L"Failed to set a breakpoint on QueryInterface method (CLSID: {:b}, IID: {:b})", clsid, iid), hr);
                }
            }
        }
        _cotype_with_vtables.insert({{clsid, iid}, module_base_addr + vtable});
    }
}

void comonitor::handle_module_unload(ULONG64 base_address) {
    std::wstring module_name;
    ULONG module_size{}, module_timestamp{};

    if (auto hr{get_module_info(base_address, module_name, module_timestamp, module_size)}; SUCCEEDED(hr)) {
        // remove all function name breakpoints from the specified module
        for (auto iter{std::begin(_breakpoints)}; iter != std::end(_breakpoints);) {
            if (auto fbrk{std::get_if<function_breakpoint>(&iter->second)};
                fbrk != nullptr && fbrk->function_name.starts_with(module_name + L'!')) {
                if (auto hr2{unset_breakpoint(iter)}; FAILED(hr2)) {
                    _logger.log_error(std::format(L"Failed to remove a breakpoint {}", iter->first), hr2);
                    iter++;
                }
            } else {
                iter++;
            }
        }

        for (auto iter{std::begin(_cotype_with_vtables)}; iter != std::end(_cotype_with_vtables);) {
            auto &[key, vtlb]{*iter};
            if (vtlb >= base_address && vtlb <= base_address + module_size) {
                iter = _cotype_with_vtables.erase(iter);
            } else {
                iter++;
            }
        }

        for (auto iter{std::begin(_breakpoints)}; iter != std::end(_breakpoints);) {
            if (auto b{std::get_if<IUnknown_QueryInterface_breakpoint>(&iter->second)};
                b != nullptr && b->address >= base_address && b->address <= base_address + module_size) {
                if (auto hr2{unset_breakpoint(iter)}; FAILED(hr2)) {
                    _logger.log_error(std::format(L"Failed to remove a breakpoint {}", iter->first), hr2);
                    iter++;
                }
                continue;
            }
            if (auto b{std::get_if<IClassFactory_CreateInstance_breakpoint>(&iter->second)};
                b != nullptr && b->address >= base_address && b->address <= base_address + module_size) {
                if (auto hr2{unset_breakpoint(iter)}; FAILED(hr2)) {
                    _logger.log_error(std::format(L"Failed to remove a breakpoint {}", iter->first), hr2);
                    iter++;
                }
                continue;
            }
            if (auto b{std::get_if<function_return_breakpoint>(&iter->second)};
                b != nullptr && b->address >= base_address && b->address <= base_address + module_size) {
                if (auto hr2{unset_breakpoint(iter)}; FAILED(hr2)) {
                    _logger.log_error(std::format(L"Failed to remove a breakpoint {}", iter->first), hr2);
                    iter++;
                }
                continue;
            }
            iter++;
        }
    } else {
        LOG_HR(hr);
    }
}

void comonitor::list_breakpoints() const {
    for (const auto &[brk_id, brk] : _breakpoints) {
        if (std::holds_alternative<function_return_breakpoint>(brk)) {
            auto &fbrk{std::get<function_return_breakpoint>(brk)};
            _dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, std::format(L"{}: return breakpoint, CLSID: {:b}, IID: {:b}, address: {:#x}\n",
                                                                     brk_id, fbrk.clsid, fbrk.iid, fbrk.address)
                                                             .c_str());
        } else if (std::holds_alternative<function_breakpoint>(brk)) {
            auto &fbrk{std::get<function_breakpoint>(brk)};
            _dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL,
                                    std::format(L"{}: function breakpoint, function name: {}\n", brk_id, fbrk.function_name).c_str());
        } else if (std::holds_alternative<IUnknown_QueryInterface_breakpoint>(brk)) {
            auto &qibrk{std::get<IUnknown_QueryInterface_breakpoint>(brk)};
            _dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL,
                                    std::format(L"{}: IUnknown::QueryInterface breakpoint, CLSID: {:b}, IID: {:b}, address: {:#x}\n",
                                                brk_id, qibrk.clsid, qibrk.iid, qibrk.address)
                                        .c_str());
        } else if (std::holds_alternative<IClassFactory_CreateInstance_breakpoint>(brk)) {
            auto &cibrk{std::get<IClassFactory_CreateInstance_breakpoint>(brk)};
            _dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL,
                                    std::format(L"{}: IClassFactory::CreateInstance breakpoint, CLSID: {:b}, address: {:#x}\n", brk_id,
                                                cibrk.clsid, cibrk.address)
                                        .c_str());
        } else {
            assert(false);
        }
    }
}

void comonitor::set_filter(std::shared_ptr<cofilter> log_filter) {
    _log_filter = log_filter;

    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};
    for (auto &[key, vtbl] : _cotype_with_vtables) {
        auto &[clsid, iid] = key;
        if (_log_filter->is_clsid_allowed(clsid)) {
            if (ULONG64 fn_address{}; SUCCEEDED(cc.read_pointer(vtbl, fn_address))) {
                if (auto hr{set_breakpoint(IUnknown_QueryInterface_breakpoint{clsid, iid, fn_address})}; FAILED(hr)) {
                    _logger.log_error(
                        std::format(L"Failed to set a breakpoint on QueryInterface method (CLSID: {:b}, IID: {:b})", clsid, iid), hr);
                }
            }
        }
    }

    for (auto iter{std::begin(_breakpoints)}; iter != std::end(_breakpoints);) {
        if (auto b{std::get_if<IUnknown_QueryInterface_breakpoint>(&iter->second)};
            b != nullptr && !_log_filter->is_clsid_allowed(b->clsid)) {
            if (auto hr{unset_breakpoint(iter)}; FAILED(hr)) {
                _logger.log_error(std::format(L"Failed to remove a breakpoint {}", iter->first), hr);
                iter++;
            }
        } else {
            iter++;
        }
    }
}

// Breakpoint handling

bool comonitor::handle_breakpoint(ULONG id) {
    if (auto found_brk{_breakpoints.find(id)}; found_brk != std::end(_breakpoints)) {
        if (auto brk{found_brk->second}; std::holds_alternative<function_return_breakpoint>(brk)) {
            _breakpoints.erase(found_brk); // one time breakpoint - cv_it won't fire again
            handle_fuction_return(std::get<function_return_breakpoint>(brk));
        } else if (std::holds_alternative<function_breakpoint>(brk)) {
            auto &fbrk{std::get<function_breakpoint>(brk)};
            if (fbrk.function_name == L"combase!CoCreateInstance") {
                handle_CoCreateInstance(std::get<function_breakpoint>(brk));
            } else if (fbrk.function_name == L"combase!CoGetClassObject") {
                handle_CoGetClassObject(std::get<function_breakpoint>(brk));
            }
        } else if (std::holds_alternative<IUnknown_QueryInterface_breakpoint>(brk)) {
            handle_IUnknown_QueryInterface(std::get<IUnknown_QueryInterface_breakpoint>(brk));
        } else if (std::holds_alternative<IClassFactory_CreateInstance_breakpoint>(brk)) {
            handle_IClassFactory_CreateInstance(std::get<IClassFactory_CreateInstance_breakpoint>(brk));
        } else {
            assert(false);
        }
        return true;
    } else {
        return false;
    }
}

void comonitor::handle_fuction_return(const function_return_breakpoint &brk) {
    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    HRESULT function_return_code{};
    RETURN_VOID_IF_FAILED(cc.read_method_return_code(function_return_code));

    if (SUCCEEDED(function_return_code)) {
        ULONG64 addr{};
        RETURN_VOID_IF_FAILED(cc.read_pointer(brk.object_address, addr));
        ULONG64 vtbl_address{};
        RETURN_VOID_IF_FAILED(cc.read_pointer(addr, vtbl_address));

        log_com_call(brk.clsid, brk.iid, brk.create_function_name);

        register_vtable(brk.clsid, brk.iid, vtbl_address, true);
    } else {
        log_com_error(brk.clsid, brk.iid, brk.create_function_name, function_return_code);
    }
}

void comonitor::handle_CoCreateInstance(const function_breakpoint &brk) {
    assert(brk.function_name == L"combase!CoCreateInstance");

    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    std::vector<ULONG64> args(5);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    CLSID clsid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[0], &clsid, sizeof(decltype(clsid))));
    IID iid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[3], &iid, sizeof(decltype(iid))));

    set_function_return_breakpoint(clsid, iid, args[4], brk.function_name, return_addr);
}

void comonitor::handle_CoGetClassObject(const function_breakpoint &brk) {
    assert(brk.function_name == L"combase!CoGetClassObject");

    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    std::vector<ULONG64> args(5);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    CLSID clsid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[0], &clsid, sizeof(decltype(clsid))));
    IID iid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[3], &iid, sizeof(decltype(iid))));

    set_function_return_breakpoint(clsid, iid, args[4], brk.function_name, return_addr);
}

void comonitor::handle_IUnknown_QueryInterface(const IUnknown_QueryInterface_breakpoint &brk) {
    static const std::wstring_view function_name{L"IUnknown::QueryInterface"};

    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    std::vector<ULONG64> args(3);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    IID iid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[1], &iid, sizeof(decltype(iid))));

    set_function_return_breakpoint(brk.clsid, iid, args[2], function_name.data(), return_addr);
};

void comonitor::handle_IClassFactory_CreateInstance(const IClassFactory_CreateInstance_breakpoint &brk) {
    static const std::wstring_view function_name{L"IClassFactory::CreateInstance"};

    call_context cc{_dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch};

    std::vector<ULONG64> args(5);
    ULONG64 return_addr{};
    RETURN_VOID_IF_FAILED(cc.read_method_frame(args, return_addr));

    IID iid{};
    RETURN_VOID_IF_FAILED(cc.read_object(args[2], &iid, sizeof(decltype(iid))));

    set_function_return_breakpoint(brk.clsid, iid, args[3], function_name.data(), return_addr);
}
