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

#include "comon.h"
#include "comonitor.h"

using namespace comon_ext;

namespace views = std::ranges::views;
namespace fs = std::filesystem;

namespace
{

arch get_process_arch(IDebugControl4* dbgcontrol, IDebugSymbols3* dbgsymbols, IDebugRegisters2* dbgregisters) {
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

HANDLE get_current_process_handle(IDebugSystemObjects* dbgsystemobjects) {
    ULONG64 handle;
    THROW_IF_FAILED(dbgsystemobjects->GetCurrentProcessHandle(&handle));
    return reinterpret_cast<HANDLE>(handle);
}

ULONG get_current_process_id(IDebugSystemObjects* dbgsystemobjects) {
    ULONG pid{};
    dbgsystemobjects->GetCurrentProcessId(&pid);
    return pid;
}

}

comonitor::comonitor(IDebugClient5* dbgclient, std::shared_ptr<cometa> cometa, const cofilter& filter)
    : _dbgclient{ dbgclient }, _dbgcontrol{ _dbgclient.query<IDebugControl4>() }, _dbgsymbols{ _dbgclient.query<IDebugSymbols3>() },
    _dbgdataspaces{ _dbgclient.query<IDebugDataSpaces>() }, _dbgsystemobjects{ _dbgclient.query<IDebugSystemObjects>() },
    _dbgregisters{ _dbgclient.query<IDebugRegisters2>() }, _cometa{ cometa }, _logger{ _dbgcontrol.get() },
    _arch{ get_process_arch(_dbgcontrol.get(), _dbgsymbols.get(), _dbgregisters.get()) },
    _process_handle{ get_current_process_handle(_dbgsystemobjects.get()) }, _process_id{ get_current_process_id(_dbgsystemobjects.get()) },
    _filter{ filter } {

    if (ULONG loaded_modules_cnt, unloaded_modules_cnt;
        SUCCEEDED(_dbgsymbols->GetNumberModules(&loaded_modules_cnt, &unloaded_modules_cnt))) {
        auto modules{ std::make_unique<DEBUG_MODULE_PARAMETERS[]>(loaded_modules_cnt) };
        if (auto hr{ _dbgsymbols->GetModuleParameters(loaded_modules_cnt, nullptr, 0, modules.get()) }; SUCCEEDED(hr)) {
            for (ULONG i = 0; i < loaded_modules_cnt; i++) {
                auto& m{ modules[i] };
                if (auto buffer{ std::make_unique<wchar_t[]>(m.ModuleNameSize) }; SUCCEEDED(_dbgsymbols->GetModuleNameStringWide(
                    DEBUG_MODNAME_MODULE, DEBUG_ANY_ID, m.Base, buffer.get(), m.ModuleNameSize, nullptr))) {
                    handle_module_load({ buffer.get(), m.ModuleNameSize - 1 }, m.TimeDateStamp, m.Base);
                }
            }
        } else {
            _logger.log_error(L"Error when retrieving information about module.", hr);
        }
    }
}

comonitor::~comonitor() {
    for (auto iter{ std::begin(_breakpoints) }; iter != std::end(_breakpoints);) {
        if (auto hr{ unset_breakpoint(iter) }; FAILED(hr)) {
            LOG_HR(hr);
            iter++;
        }
    }
    _cotype_with_vtables.clear();
}

HRESULT comonitor::get_module_info(ULONG64 base_address, std::wstring& module_name, ULONG& module_timestamp, ULONG& module_size) {
    DEBUG_MODULE_PARAMETERS m{};
    RETURN_IF_FAILED(_dbgsymbols->GetModuleParameters(1, &base_address, DEBUG_ANY_ID /* ignored */, &m));

    module_timestamp = m.TimeDateStamp;
    module_size = m.Size;

    auto buffer{ std::make_unique<wchar_t[]>(m.ModuleNameSize) };
    RETURN_IF_FAILED(_dbgsymbols->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, DEBUG_ANY_ID, base_address, buffer.get(),
        m.ModuleNameSize, nullptr));
    module_name.assign(buffer.get(), static_cast<size_t>(m.ModuleNameSize) - 1);

    return S_OK;
}

HRESULT comonitor::create_cobreakpoint(const CLSID& clsid, const IID& iid, DWORD method_num, std::wstring_view method_display_name) {
    assert(method_num >= 0);
    if (auto vtable{ _cotype_with_vtables.find({ clsid, iid }) }; vtable != std::end(_cotype_with_vtables)) {
        call_context cc{ _dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch };
        ULONG64 addr{};
        RETURN_IF_FAILED(cc.read_pointer(vtable->second + method_num * cc.get_pointer_size(), addr));

        IDebugBreakpoint2* brk{};
        RETURN_IF_FAILED(_dbgcontrol->AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &brk));
        RETURN_IF_FAILED(brk->SetOffset(addr));

        auto clsid_name{ _cometa->resolve_class_name(clsid) };
        auto iid_name{ _cometa->resolve_type_name(iid) };
        auto cmd{ std::format(
            L".printf /D \"== Method <b>{} [{}]</b> called on a COM object (CLSID: <b>{:b} ({})</b>, IID <b>{:b} ({})</b>) ==\"; .echo",
            method_display_name, method_num, iid, iid_name ? *iid_name : L"N/A", clsid, clsid_name ? *clsid_name : L"N/A") };
        RETURN_IF_FAILED(brk->SetCommandWide(cmd.c_str()));

        ULONG brk_id{};
        RETURN_IF_FAILED(brk->GetId(&brk_id));
        RETURN_IF_FAILED(brk->AddFlags(DEBUG_BREAKPOINT_ENABLED));

        return S_OK;
    } else {
        _logger.log_error(L"Could not locate COM class metadata.", E_INVALIDARG);
        return E_INVALIDARG;
    }
}

HRESULT comonitor::create_cobreakpoint(const CLSID& clsid, const IID& iid, DWORD method_num) {
    if (method_num < 0) {
        return E_INVALIDARG;
    }

    auto cotype{ _cometa->resolve_type(iid) };

    std::wstring method_name{};
    if (cotype && cotype->methods_available) {
        if (auto methods{ _cometa->get_type_methods(iid) }; methods && methods->size() > method_num) {
            method_name = methods->at(method_num);
        }
    }
    return create_cobreakpoint(clsid, iid, method_num, method_name);
}

HRESULT comonitor::create_cobreakpoint(const CLSID& clsid, const IID& iid, std::wstring_view method_name) {
    if (auto methods{ _cometa->get_type_methods(iid) }; methods) {
        if (auto res{ std::ranges::find(*methods, method_name) }; res != std::end(*methods)) {
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

HRESULT comonitor::register_vtable(const CLSID& clsid, const IID& iid, ULONG64 vtable_addr, bool save_in_database) {
    assert(is_clsid_allowed(clsid));

    // the vtable might have been already added by the IClassFactory_CreateInstance method
    if (!_cotype_with_vtables.contains({ clsid, iid })) {

        // save info about vtable in the database
        if (ULONG64 base_addr{}; save_in_database && SUCCEEDED(_dbgsymbols->GetModuleByOffset2(
            vtable_addr, 0, DEBUG_GETMOD_NO_UNLOADED_MODULES, nullptr, &base_addr))) {

            std::wstring module_name;
            ULONG module_size{}, module_timestamp{};
            if (auto hr{ get_module_info(base_addr, module_name, module_timestamp, module_size) }; SUCCEEDED(hr)) {
                _cometa->save_module_vtable({ module_name, module_timestamp, std::holds_alternative<arch_x64>(_arch) },
                    { clsid, iid, vtable_addr - base_addr });
            } else {
                LOG_HR(hr);
            }
        } else {
            _logger.log_warning(std::format(L"Virtual table address {:x} does not belong to any module.", vtable_addr));
        }

        call_context cc{ _dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch };

        // the first method is always the QueryInterface and we need to break on cv_it
        ULONG64 fn_address{};
        RETURN_IF_FAILED(cc.read_pointer(vtable_addr, fn_address));

        if (auto hr{ set_breakpoint(IUnknown_QueryInterface_breakpoint{ clsid }, fn_address) }; FAILED(hr)) {
            _logger.log_error(std::format(L"Failed to set a breakpoint on QueryInterface method (CLSID: {:b}, IID: {:b})", clsid, iid), hr);
        }

        _cotype_with_vtables.insert({ { clsid, iid }, vtable_addr });

        // special case for IClassFactory when we need to set breakpoint on the CreateInstance (4th method in the vtbl)
        if (iid == __uuidof(IClassFactory)) {
            if (SUCCEEDED((cc.read_pointer(vtable_addr + 3 * cc.get_pointer_size(), fn_address)))) {
                if (auto hr{ set_breakpoint(cointerface_method_breakpoint{ clsid, iid, L"CreateInstance" }, fn_address) }; FAILED(hr)) {
                    _logger.log_error(std::format(L"Failed to set a breakpoint on IClassFactory::CreateInstance method (CLSID: {:b})", clsid), hr);
                }
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
    for (const auto& [brk_id, brk_data] : _breakpoints) {
        auto& brk = brk_data.brk;
        if (is_onetime_breakpoint(brk)) {
            continue;
        }
        if (auto hr{ modify_breakpoint_flag(brk_id, DEBUG_BREAKPOINT_ENABLED, false) }; FAILED(hr)) {
            _logger.log_error(std::format(L"Error when modifying flag for breakpoint {}", brk_id), hr);
        }
    }
    _is_paused = true;
}

void comonitor::resume() noexcept {
    for (const auto& [brk_id, brk_data] : _breakpoints) {
        auto& brk = brk_data.brk;
        if (is_onetime_breakpoint(brk)) {
            continue;
        }
        if (auto hr{ modify_breakpoint_flag(brk_id, DEBUG_BREAKPOINT_ENABLED, true) }; FAILED(hr)) {
            _logger.log_error(std::format(L"Error when modifying flag for breakpoint {}", brk_id), hr);
        }
    }
    _is_paused = false;
}

void comonitor::handle_module_load(std::wstring_view module_name, ULONG module_timestamp, ULONG64 module_base_addr) {
    for (auto& [clsid, iid, vtable] :
        _cometa->get_module_vtables({ module_name, module_timestamp, std::holds_alternative<arch_x64>(_arch) })) {
        if (is_clsid_allowed(clsid)) {
            call_context cc{ _dbgcontrol.get(), _dbgdataspaces.get(), _dbgregisters.get(), _arch };
            if (ULONG64 fn_query_interface{}; SUCCEEDED(cc.read_pointer(module_base_addr + vtable, fn_query_interface))) {
                if (auto hr{ set_breakpoint(IUnknown_QueryInterface_breakpoint{ clsid }, fn_query_interface) }; FAILED(hr)) {
                    _logger.log_error(
                        std::format(L"Failed to set a breakpoint on QueryInterface method (CLSID: {:b}, IID: {:b})", clsid, iid), hr);
                }
            }
        }
        _cotype_with_vtables.insert({ { clsid, iid }, module_base_addr + vtable });
    }

    // if a given module exports DllGetClassObject we will set a breakpoint on it
    std::vector<std::wstring_view> functions_to_monitor{ L"DllGetClassObject" };
    if (module_name == L"ole32" || module_name == L"combase") {
        // additional function breakpoints related to COM
        // NOTE: on older systems those functions were located in ole32.dll, in newer
        // systems they are in combase.dll
        functions_to_monitor.push_back(L"CoRegisterClassObject");
    }


    // We are here forcing symbol loading for a specific module. A better approach would be to use an interface
    // that would give us exported functions per module, but I haven't found a way to do that.
    for (const auto& fn_name : functions_to_monitor) {
        std::wstring fn_fullname{ module_name };
        // when there is a dot in the module name, windbg replaces it with underscore - we need to do the same,
        // otherwise, symbol resolution won't work
        std::replace(std::begin(fn_fullname), std::end(fn_fullname), L'.', L'_');
        fn_fullname.append(L"!").append(fn_name);

        if (ULONG64 offset{}; SUCCEEDED(_dbgsymbols->GetOffsetByNameWide(fn_fullname.c_str(), &offset))) {
            if (auto hr{ set_breakpoint(function_breakpoint{ fn_fullname }, offset) }; FAILED(hr)) {
                _logger.log_error(std::format(L"Failed to set a breakpoint on function '{}'", fn_fullname), hr);
            }
        }
    }
}

void comonitor::handle_module_unload(ULONG64 base_address) {
    std::wstring module_name;
    ULONG module_size{}, module_timestamp{};

    if (auto hr{ get_module_info(base_address, module_name, module_timestamp, module_size) }; SUCCEEDED(hr)) {
        // remove all function name breakpoints from the specified module
        for (auto iter{ std::begin(_cotype_with_vtables) }; iter != std::end(_cotype_with_vtables);) {
            auto& [key, vtlb] {*iter};
            if (vtlb >= base_address && vtlb <= base_address + module_size) {
                iter = _cotype_with_vtables.erase(iter);
            } else {
                iter++;
            }
        }

        for (auto iter{ std::begin(_breakpoints) }; iter != std::end(_breakpoints);) {
            auto address{ iter->second.addr };
            if (address >= base_address && address <= base_address + module_size) {
                if (auto hr2{ unset_breakpoint(iter) }; FAILED(hr2)) {
                    _logger.log_error(std::format(L"Failed to remove a breakpoint {}", iter->first), hr2);
                    iter++;
                }
            } else {
                iter++;
            }
        }
    } else {
        LOG_HR(hr);
    }
}

void comonitor::log_com_call_success(const CLSID& clsid, const IID& iid, std::wstring_view caller_name) {
    if (is_clsid_allowed(clsid)) {
        ULONG tid{};
        _dbgsystemobjects->GetCurrentThreadId(&tid);

        auto clsid_name{ _cometa->resolve_class_name(clsid) };
        auto iid_name{ _cometa->resolve_type_name(iid) };
        _logger.log_info_dml(std::format(L"<col fg=\"normfg\">{}:{:03} [{}] CLSID: <b>{:b} ({})</b>, IID: <b>{:b} "
            L"({})</b></col> -> <col fg=\"srccmnt\">SUCCESS (0x0)</col>",
            _process_id, tid, caller_name, clsid, clsid_name ? *clsid_name : L"N/A", iid,
            iid_name ? *iid_name : L"N/A"));
    }
}

void comonitor::log_com_call_error(const CLSID& clsid, const IID& iid, std::wstring_view caller_name, HRESULT result_code) {
    if (is_clsid_allowed(clsid)) {
        ULONG pid{};
        _dbgsystemobjects->GetCurrentProcessId(&pid);
        ULONG tid{};
        _dbgsystemobjects->GetCurrentThreadId(&tid);

        auto clsid_name{ _cometa->resolve_class_name(clsid) };
        auto iid_name = _cometa->resolve_type_name(iid);
        _logger.log_info_dml(std::format(L"<col fg=\"changed\">{}:{:03} [{}] CLSID: <b>{:b} ({})</b>, IID: <b>{:b} "
            L"({})</b></col> -> <col fg=\"srcstr\">ERROR ({:#x}) - {}</col>",
            pid, tid, caller_name, clsid, clsid_name ? *clsid_name : L"N/A", iid,
            iid_name ? *iid_name : L"N/A", static_cast<unsigned long>(result_code),
            dbgeng_logger::get_error_msg(result_code)));
    }
}

std::unordered_map<CLSID, std::vector<std::pair<ULONG64, IID>>> comonitor::list_cotypes() const {
    std::unordered_map<CLSID, std::vector<std::pair<ULONG64, IID>>> result{};

    for (const auto& [key, addr] : _cotype_with_vtables) {
        const auto& [clsid, iid] {key};

        if (!result.contains(clsid)) {
            result.insert({ clsid, std::vector<std::pair<ULONG64, IID>> { { addr, iid } } });
        } else {
            result[clsid].push_back({ addr, iid });
        }
    }

    return result;
}
