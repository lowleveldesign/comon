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

#pragma once

#include <array>
#include <filesystem>
#include <memory>
#include <optional>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include <Windows.h>
#include <wil/com.h>
#include <wil/result.h>

#include "arch.h"
#include "cometa.h"
#include "comon.h"

namespace comon_ext {

namespace fs = std::filesystem;

class comonitor {
  private:
    struct coquery_single_return_breakpoint {
        const CLSID clsid;
        const IID iid;
        const ULONG64 object_address_address;
        const std::wstring create_function_name;
        const ULONG64 address;
    };

    struct coquery_multi_return_breakpoint {
        const CLSID clsid;
        const DWORD results_count;
        const ULONG64 results_address;
        const std::wstring create_function_name;
        const ULONG64 address;
    };

    struct coregister_return_breakpoint {
        const CLSID clsid;
        const IID iid;
        const ULONG64 vtbl_address;
        const std::wstring register_function_name;
        const ULONG64 address;
    };

    struct function_breakpoint {
        const std::wstring function_name;
        const ULONG64 address;
    };

    struct GetClassFile_breakpoint {
        const ULONG referenced_breakpoint_id;
        const ULONG match_thread_id;
        const ULONG64 address;
    };

    struct GetClassFile_return_breakpoint {
        const ULONG referenced_breakpoint_id;
        const ULONG match_thread_id;
        const ULONG64 CLSID_address;
        const ULONG64 address;
    };

    struct IUnknown_QueryInterface_breakpoint {
        const CLSID clsid;
        const IID iid;
        const ULONG64 address;
    };

    struct IClassFactory_CreateInstance_breakpoint {
        const CLSID clsid;
        const ULONG64 address;
    };

    static wil::com_ptr_t<IDebugClient5> create_IDebugClient() {
        wil::com_ptr_t<IDebugClient5> client;
        THROW_IF_FAILED(::DebugCreate(__uuidof(IDebugClient5), client.put_void()));
        return client;
    }

    static arch get_process_arch(IDebugControl4 *dbgcontrol, IDebugSymbols3 *dbgsymbols, IDebugRegisters2 *dbgregisters);

    const wil::com_ptr<IDebugClient5> _dbgclient;
    const wil::com_ptr<IDebugControl4> _dbgcontrol;
    const wil::com_ptr<IDebugSymbols3> _dbgsymbols;
    const wil::com_ptr<IDebugDataSpaces> _dbgdataspaces;
    const wil::com_ptr<IDebugSystemObjects> _dbgsystemobjects;
    const wil::com_ptr<IDebugRegisters2> _dbgregisters;
    const dbgeng_logger _logger;

    using breakpoint = std::variant<function_breakpoint, coquery_single_return_breakpoint, coquery_multi_return_breakpoint,
                                    coregister_return_breakpoint, IUnknown_QueryInterface_breakpoint,
                                    IClassFactory_CreateInstance_breakpoint, GetClassFile_breakpoint, GetClassFile_return_breakpoint>;

    std::unordered_map<ULONG, breakpoint> _breakpoints{};
    std::unordered_map<std::pair<CLSID, IID>, ULONG64> _cotype_with_vtables{};
    std::shared_ptr<cofilter> _log_filter;

    const std::shared_ptr<cometa> _cometa;

    const arch _arch;

    HRESULT get_module_info(ULONG64 base_address, std::wstring &module_name, ULONG &module_timestamp, ULONG &module_size) {
        DEBUG_MODULE_PARAMETERS m{};
        RETURN_IF_FAILED(_dbgsymbols->GetModuleParameters(1, &base_address, DEBUG_ANY_ID /* ignored */, &m));

        module_timestamp = m.TimeDateStamp;
        module_size = m.Size;

        auto buffer{std::make_unique<wchar_t[]>(m.ModuleNameSize)};
        RETURN_IF_FAILED(_dbgsymbols->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, DEBUG_ANY_ID, base_address, buffer.get(),
                                                              m.ModuleNameSize, nullptr));
        module_name.assign(buffer.get(), static_cast<size_t>(m.ModuleNameSize) - 1);

        return S_OK;
    }

    bool is_onetime_breakpoint(const breakpoint &brk) {
        return std::holds_alternative<GetClassFile_breakpoint>(brk) || std::holds_alternative<coquery_single_return_breakpoint>(brk) ||
               std::holds_alternative<coquery_multi_return_breakpoint>(brk) ||
               std::holds_alternative<GetClassFile_return_breakpoint>(brk) || std::holds_alternative<coregister_return_breakpoint>(brk);
    }

    HRESULT set_breakpoint(const breakpoint &brk, PULONG brk_id = nullptr);

    HRESULT unset_breakpoint(decltype(_breakpoints)::iterator &iter) {
        IDebugBreakpoint2 *bp;
        RETURN_IF_FAILED(_dbgcontrol->GetBreakpointById2(iter->first, &bp));
        RETURN_IF_FAILED(_dbgcontrol->RemoveBreakpoint2(bp));

        iter = _breakpoints.erase(iter);

        return S_OK;
    }

    HRESULT modify_breakpoint_flag(ULONG brk_id, ULONG flag, bool enable) {
        IDebugBreakpoint2 *bp;
        RETURN_IF_FAILED(_dbgcontrol->GetBreakpointById2(brk_id, &bp));

        ULONG flags{};
        RETURN_IF_FAILED(bp->GetFlags(&flags));
        flags = enable ? (flags | flag) : (flags & ~flag);
        return bp->SetFlags(flags);
    }

    auto log_com_call_success(const CLSID &clsid, const IID &iid, std::wstring_view caller_name) {
        if (_log_filter->is_clsid_allowed(clsid)) {
            ULONG pid{};
            _dbgsystemobjects->GetCurrentProcessId(&pid);
            ULONG tid{};
            _dbgsystemobjects->GetCurrentThreadId(&tid);

            auto clsid_name{_cometa->resolve_class_name(clsid)};
            auto iid_name{_cometa->resolve_type_name(iid)};
            _logger.log_info_dml(std::format(L"<col fg=\"normfg\" bg=\"normbg\">{}:{:03} [{}] CLSID: <b>{:b} ({})</b>, IID: <b>{:b} "
                                             L"({})</b></col> -> <col fg=\"srccmnt\" bg=\"wbg\">SUCCESS (0x0)</col>",
                                             pid, tid, caller_name, clsid, clsid_name ? *clsid_name : L"N/A", iid,
                                             iid_name ? *iid_name : L"N/A"));
        }
    }

    auto log_com_call_error(const CLSID &clsid, const IID &iid, std::wstring_view caller_name, HRESULT result_code) {
        if (_log_filter->is_clsid_allowed(clsid)) {
            ULONG pid{};
            _dbgsystemobjects->GetCurrentProcessId(&pid);
            ULONG tid{};
            _dbgsystemobjects->GetCurrentThreadId(&tid);

            auto clsid_name{_cometa->resolve_class_name(clsid)};
            auto iid_name = _cometa->resolve_type_name(iid);
            _logger.log_info_dml(std::format(L"<col fg=\"changed\" bg=\"normbg\">{}:{:03} [{}] CLSID: <b>{:b} ({})</b>, IID: <b>{:b} "
                                             L"({})</b></col> -> <col fg=\"srcstr\" bg=\"wbg\">ERROR ({:#x}) - {}</col>",
                                             pid, tid, caller_name, clsid, clsid_name ? *clsid_name : L"N/A", iid,
                                             iid_name ? *iid_name : L"N/A", static_cast<unsigned long>(result_code),
                                             dbgeng_logger::get_error_msg(result_code)));
        }
    }

    HRESULT create_cobreakpoint(const CLSID &clsid, const IID &iid, DWORD method_num, std::wstring_view method_display_name);

    /* Breakpoints handling */
    void handle_coquery_return(const coquery_single_return_breakpoint &brk);

    void handle_coquery_return(const coquery_multi_return_breakpoint &brk);

    void handle_coregister_return(const coregister_return_breakpoint &brk);

    void handle_CoCreateInstance(const function_breakpoint &);

    void handle_IUnknown_QueryInterface(const IUnknown_QueryInterface_breakpoint &brk);

    void handle_CoGetClassObject(const function_breakpoint &);

    void handle_CoGetInstanceFromFile(const function_breakpoint &brk);

    void handle_CoRegisterClassObject(const function_breakpoint &brk);

    void handle_GetClassFile(const GetClassFile_breakpoint &brk);

    void handle_GetClassFile_return(const GetClassFile_return_breakpoint &brk);

    void handle_IClassFactory_CreateInstance(const IClassFactory_CreateInstance_breakpoint &brk);

  public:
    explicit comonitor(IDebugClient5 *dbgclient, std::shared_ptr<cometa> cometa, std::shared_ptr<cofilter> log_filter);

    comonitor(const comonitor &) = delete;

    comonitor(comonitor &&) = default;

    ~comonitor();

    bool handle_breakpoint(ULONG id);

    void handle_module_load(std::wstring_view module_name, ULONG module_timestamp, ULONG64 module_base_addr);
    void handle_module_unload(ULONG64 base_address);

    void list_breakpoints() const;

    HRESULT create_cobreakpoint(const CLSID &clsid, const IID &iid, DWORD method_num);
    HRESULT create_cobreakpoint(const CLSID &clsid, const IID &iid, std::wstring_view method_name);

    HRESULT register_vtable(const CLSID &clsid, const IID &iid, ULONG64 vtable_addr, bool save_in_database);

    void pause() noexcept;

    void resume() noexcept;

    void set_filter(std::shared_ptr<cofilter> log_filter);
};

} // namespace comon_ext
