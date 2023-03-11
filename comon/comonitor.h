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
#include <optional>
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

struct no_filter {};
struct including_filter { const std::unordered_set<CLSID> clsids; };
struct excluding_filter { const std::unordered_set<CLSID> clsids; };
using cofilter = std::variant<no_filter, including_filter, excluding_filter>;

enum class cobreakpoint_behavior {
    stop_before_call,
    stop_after_call,
    always_stop,
    never_stop
};

class comonitor {
private:

    /* Entry functions (those functions create new class objects):
     *
     * - CoRegisterClassObject
     * - <module>!DllGetClassObject
     *
     * Each entry function creates a return breakpoint if a CLSID should be monitored
     * (is_clsid_allowed). On return, we register the created vtable and place breakpoints
     * on the interface methods, for exampe, IUnknown::QueryInterface or IClassFactory::CreateInstance.
    */

    struct coquery_single_return_breakpoint {
        const CLSID clsid;
        const IID iid;
        const ULONG64 object_address_address;
        const std::wstring create_function_name;
    };

    struct coregister_return_breakpoint {
        const CLSID clsid;
        const IID iid;
        const ULONG64 vtbl_address;
        const std::wstring register_function_name;
    };

    struct function_breakpoint {
        // must be with the module name
        const std::wstring function_name;
    };

    /// Special type of breakpoint that is placed on a method of a COM interface
    struct cobreakpoint {
        const CLSID clsid;
        const IID iid;
        const std::wstring method_name;
        const CALLCONV callconv;
        const std::wstring return_type;
        const method_arg_collection args;
        const cobreakpoint_behavior behavior;
    };

    struct cobreakpoint_return {
        const CLSID clsid;
        const IID iid;
        const std::wstring method_name;
        const std::wstring return_type;
        const method_arg_collection out_args;
        const std::vector<call_context::arg_val> out_arg_values;
        const bool should_stop;
    };

    using breakpoint = std::variant<function_breakpoint, coquery_single_return_breakpoint,
        coregister_return_breakpoint, cobreakpoint, cobreakpoint_return>;

    struct memory_protect {
        DWORD old_protect;
        DWORD new_protect;
    };

    struct breakpoint_data {
        const breakpoint brk;
        const ULONG64 addr;
        const std::optional<memory_protect> mem_protect;
    };

    struct module_info {
        std::wstring name;
        ULONG timestamp;
        ULONG size;
    };

    static wil::com_ptr_t<IDebugClient5> create_IDebugClient() {
        wil::com_ptr_t<IDebugClient5> client;
        THROW_IF_FAILED(::DebugCreate(__uuidof(IDebugClient5), client.put_void()));
        return client;
    }

    const wil::com_ptr<IDebugClient5> _dbgclient;
    const wil::com_ptr<IDebugControl4> _dbgcontrol;
    const wil::com_ptr<IDebugSymbols3> _dbgsymbols;
    const wil::com_ptr<IDebugDataSpaces3> _dbgdataspaces;
    const wil::com_ptr<IDebugSystemObjects> _dbgsystemobjects;
    const dbgeng_logger _logger;
    const HANDLE _process_handle;
    const ULONG _process_id;

    const call_context& _cc;

    const cofilter _filter;

    cometa& _cometa;

    bool _is_paused{};

    std::unordered_map<ULONG, breakpoint_data> _breakpoints{};
    std::unordered_map<ULONG64, ULONG> _breakpoint_addresses{};
    std::unordered_map<std::pair<CLSID, IID>, ULONG64> _cotype_with_vtables{};

    std::variant<module_info, HRESULT> get_module_info(ULONG64 base_address) const;

    std::variant<ULONG64, HRESULT> get_exported_function_addr(ULONG64 module_base_addr, std::string_view function_name) const;

    auto is_clsid_allowed(const CLSID& clsid) {
        if (auto fltr = std::get_if<including_filter>(&_filter); fltr) {
            return fltr->clsids.contains(clsid);
        }
        if (auto fltr = std::get_if<excluding_filter>(&_filter); fltr) {
            return !fltr->clsids.contains(clsid);
        }
        assert(std::holds_alternative<no_filter>(_filter));
        return true;
    }

    bool is_onetime_breakpoint(const breakpoint& brk) {
        return std::holds_alternative<coquery_single_return_breakpoint>(brk) ||
            std::holds_alternative<coregister_return_breakpoint>(brk) ||
            std::holds_alternative<cobreakpoint_return>(brk);
    }

    HRESULT set_breakpoint(const breakpoint& brk, ULONG64 address, PULONG brk_id = nullptr);

    HRESULT unset_breakpoint(decltype(_breakpoints)::iterator& iter);

    void unset_inner_breakpoint(decltype(_breakpoints)::iterator& iter);

    HRESULT modify_breakpoint_flag(ULONG brk_id, ULONG flag, bool enable);

    void log_com_call_success(const CLSID& clsid, const IID& iid, std::wstring_view caller_name);

    void log_com_call_error(const CLSID& clsid, const IID& iid, std::wstring_view caller_name, HRESULT result_code);

    /* Breakpoints handling */
    void handle_coquery_return(const coquery_single_return_breakpoint& brk);

    void handle_coregister_return(const coregister_return_breakpoint& brk);

    bool handle_cobreakpoint(const cobreakpoint& brk);

    bool handle_cobreakpoint_return(const cobreakpoint_return& brk);

    void handle_DllGetClassObject(const function_breakpoint&);

    void handle_CoRegisterClassObject(const function_breakpoint& brk);

    void handle_IUnknown_QueryInterface(const CLSID& clsid);

    void handle_IClassFactory_CreateInstance(const CLSID& clsid);

public:

    // cometa and cc lifetime is controlled by dbgsession - it always survives comonitor
    explicit comonitor(IDebugClient5* dbgclient, cometa& cometa, const call_context& cc, const cofilter& filter);

    comonitor(const comonitor&) = delete;

    comonitor(comonitor&&) = default;

    ~comonitor();

    bool handle_breakpoint(ULONG id);

    void handle_module_load(std::wstring_view module_name, ULONG module_timestamp, ULONG64 module_base_addr);
    void handle_module_unload(ULONG64 base_address);

    HRESULT handle_breakpoint_removed(ULONG id) {
        if (auto found_brk{ _breakpoints.find(id) }; found_brk != std::end(_breakpoints)) {
            unset_inner_breakpoint(found_brk);
            _logger.log_info(std::format(L"Breakpoint {} removed (monitor for #{})", id, _process_id));
            return S_OK;
        } else {
            return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        }
    }

    std::unordered_map<CLSID, std::vector<std::pair<ULONG64, IID>>> list_cotypes() const;

    HRESULT create_cobreakpoint(const CLSID& clsid, const IID& iid, DWORD method_num, cobreakpoint_behavior behavior);

    HRESULT register_vtable(const CLSID& clsid, const IID& iid, ULONG64 vtable_addr, bool save_in_database, bool replace_if_exists);

    const cofilter& get_filter() const { return _filter; }

    void pause() noexcept;

    void resume() noexcept;

    bool is_paused() const noexcept { return _is_paused; }
};

} // namespace comon_ext
