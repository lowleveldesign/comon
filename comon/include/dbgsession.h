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
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <variant>
#include <memory>

#include <Windows.h>
#include <wil/com.h>
#include <wil/result.h>

#include "comon.h"
#include "cometa.h"
#include "comonitor.h"

namespace comon_ext
{

class dbgsession : public DebugBaseEventCallbacksWide
{
private:
    const wil::com_ptr<IDebugClient5> _dbgclient;
    const wil::com_ptr<IDebugControl4> _dbgcontrol;
    const wil::com_ptr<IDebugSymbols3> _dbgsymbols;
    const wil::com_ptr<IDebugSystemObjects> _dbgsystemobjects;
    const dbgeng_logger _logger;

    const std::shared_ptr<cometa> _cometa;

    std::shared_ptr<cofilter> _log_filter;

    wil::com_ptr<IDebugEventCallbacksWide> _prev_callback{};

    // maps Engine Process IDs with monitor instances
    std::unordered_map<ULONG, comonitor> _monitors{};

    static wil::com_ptr_t<IDebugClient5> create_IDebugClient() {
        wil::com_ptr_t<IDebugClient5> client;
        THROW_IF_FAILED(::DebugCreate(__uuidof(IDebugClient5), client.put_void()));
        return client;
    }

    static fs::path get_cometa_db_path() {
        if (auto path{ fs::temp_directory_path() / "cometa.db3" }; fs::exists(path)) {
            if (cometa::is_valid_db(path)) {
                return path;
            } else {
                return "";
            }
        } else {
            return path;
        }
    }

    auto get_active_process_id() const {
        ULONG pid{};
        _dbgsystemobjects->GetCurrentProcessId(&pid);
        return pid;
    }

    comonitor* find_active_monitor() {
        if (auto monitor{ _monitors.find(get_active_process_id()) }; monitor != std::end(_monitors)) {
            return &monitor->second;
        }
        return nullptr;
    }

public:

    dbgsession();

    ~dbgsession() {
        if (_dbgclient) {
            _dbgclient->SetEventCallbacksWide(_prev_callback.get());
        }
    }

    virtual ULONG __stdcall AddRef(void) override { return 1; }

    virtual ULONG __stdcall Release(void) override { return 1; }

    virtual HRESULT __stdcall GetInterestMask(PULONG mask) override {
        *mask = DEBUG_EVENT_EXIT_PROCESS | DEBUG_EVENT_BREAKPOINT |
            DEBUG_EVENT_LOAD_MODULE | DEBUG_EVENT_UNLOAD_MODULE;
        return S_OK;
    }

    virtual HRESULT __stdcall Breakpoint(PDEBUG_BREAKPOINT2 bp) override;

    virtual HRESULT __stdcall LoadModule(ULONG64 image_file_handle, ULONG64 base_offset, ULONG module_size,
        PCWSTR module_name, PCWSTR image_name, ULONG checksum, ULONG timestamp) override;

    virtual HRESULT __stdcall UnloadModule(PCWSTR image_base_name, ULONG64 base_offset) override;

    virtual HRESULT __stdcall ExitProcess(ULONG exit_code) override;

    void attach() {
        if (auto pid{ get_active_process_id() }; _monitors.contains(pid)) {
            _logger.log_info(std::format(L"COM monitor is already enabled for process {0}.", pid));
        } else {
            _monitors.insert({ pid, comonitor { _dbgclient.get(), _cometa, _log_filter } });
            _logger.log_info_dml(std::format(L"<b>COM monitor enabled for process {0}.</b>", pid));
        }
    }

    void detach() {
        if (auto monitor{ _monitors.find(get_active_process_id()) }; monitor != std::end(_monitors)) {
            _monitors.erase(monitor);
        }
    }

    HRESULT create_cobreakpoint(const CLSID& clsid, const IID& iid, DWORD method_num) {
        if (auto monitor{ find_active_monitor() }; monitor) {
            return monitor->create_cobreakpoint(clsid, iid, method_num);
        } else {
            _logger.log_warning(L"COM monitor is not enabled for the current process.");
            return S_OK;
        }
    }

    HRESULT create_cobreakpoint(const CLSID& clsid, const IID& iid, std::wstring_view method_name) {
        if (auto monitor{ find_active_monitor() }; monitor) {
            return monitor->create_cobreakpoint(clsid, iid, method_name);
        } else {
            _logger.log_warning(L"COM monitor is not enabled for the current process.");
            return S_OK;
        }
    }

    cometa& get_metadata() { return *_cometa; }

    const cofilter& get_log_filter() const { return *_log_filter; }

    void set_log_filter(std::shared_ptr<cofilter> log_filter) {
        // FIXME: what happens here?
        _log_filter = log_filter;
        for (auto& [pid, monitor] : _monitors) {
            monitor.set_filter(log_filter);
        }
    }

    HRESULT register_vtable(const CLSID& clsid, const IID& iid, ULONG64 vtable_addr) {
        if (auto monitor{ find_active_monitor() }; monitor) {
            return monitor->register_vtable(clsid, iid, vtable_addr, false);
        } else {
            _logger.log_warning(L"COM monitor is not enabled for the current process.");
            return S_OK;
        }
    }

    const dbgeng_logger& get_logger() const { return _logger; }

    void pause() noexcept;

    void resume() noexcept;

    void list_breakpoints() {
        if (auto monitor{ find_active_monitor() }; monitor) {
            monitor->list_breakpoints();
        } else {
            _logger.log_warning(L"COM monitor is not enabled for the current process.");
        }
    }
};

}

