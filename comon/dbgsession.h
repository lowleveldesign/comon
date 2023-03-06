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
#include <functional>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <stdexcept>

#include <Windows.h>
#include <wil/com.h>
#include <wil/result.h>

#include "cometa.h"
#include "comon.h"
#include "arch.h"
#include "comonitor.h"

namespace comon_ext {

class dbgsession: public DebugBaseEventCallbacksWide {
private:
    const wil::com_ptr<IDebugClient5> _dbgclient;
    const wil::com_ptr<IDebugControl4> _dbgcontrol;
    const wil::com_ptr<IDebugSymbols3> _dbgsymbols;
    const wil::com_ptr<IDebugSystemObjects> _dbgsystemobjects;

    const call_context _cc;

    cometa _cometa;

    wil::com_ptr<IDebugEventCallbacksWide> _prev_callback{};

    // maps Engine Process IDs with monitor instances
    std::unordered_map<ULONG, comonitor> _monitors{};

    static wil::com_ptr_t<IDebugClient5> create_IDebugClient() {
        wil::com_ptr_t<IDebugClient5> client;
        THROW_IF_FAILED(::DebugCreate(__uuidof(IDebugClient5), client.put_void()));
        return client;
    }

    static cometa create_cometa(IDebugControl4* dbgcontrol, const call_context& cc) {
        auto name{ cc.is_64bit() ? "cometa_64.db3" : "cometa_32.db3" };
        if (auto path{ fs::temp_directory_path() / name }; fs::exists(path)) {
            if (cometa::is_valid_db(path)) {
                return cometa{ dbgcontrol, cc.is_wow64(), path, false };
            } else {
                return cometa{ dbgcontrol, cc.is_wow64(), "", true };
            }
        } else {
            return cometa{ dbgcontrol, cc.is_wow64(), path, true };
        }
    }

    auto get_active_process_id() const {
        ULONG pid{};
        _dbgsystemobjects->GetCurrentProcessId(&pid);
        return pid;
    }

public:
    dbgsession();

    ~dbgsession() {
        if (_dbgclient) {
            _dbgclient->SetEventCallbacksWide(_prev_callback.get());
        }
    }

    STDMETHOD_(ULONG, AddRef)() override { return 1; }
    STDMETHOD_(ULONG, Release)() override { return 1; }

    STDMETHOD(GetInterestMask)(PULONG mask) override {
        *mask = DEBUG_EVENT_EXIT_PROCESS | DEBUG_EVENT_BREAKPOINT | DEBUG_EVENT_LOAD_MODULE | DEBUG_EVENT_UNLOAD_MODULE |
            DEBUG_EVENT_CHANGE_ENGINE_STATE;
        return S_OK;
    }

    STDMETHOD(Breakpoint)(PDEBUG_BREAKPOINT2 bp) override;

    STDMETHOD(ChangeEngineState)(ULONG Flags, ULONG64 Argument) override;

    STDMETHOD(LoadModule)
        (ULONG64 image_file_handle, ULONG64 base_offset, ULONG module_size, PCWSTR module_name, PCWSTR image_name, ULONG checksum,
            ULONG timestamp) override;

    STDMETHOD(UnloadModule)(PCWSTR image_base_name, ULONG64 base_offset) override;

    STDMETHOD(ExitProcess)(ULONG exit_code) override;

    comonitor* find_active_monitor() {
        if (auto monitor{ _monitors.find(get_active_process_id()) }; monitor != std::end(_monitors)) {
            return &monitor->second;
        }
        return nullptr;
    }

    void attach(const cofilter& filter) {
        if (auto pid{ get_active_process_id() }; !_monitors.contains(pid)) {
            _monitors.insert({ pid, comonitor{ _dbgclient.get(), _cometa, _cc, filter } });
        }
    }

    void detach() {
        if (auto monitor{ _monitors.find(get_active_process_id()) }; monitor != std::end(_monitors)) {
            _monitors.erase(monitor);
        }
    }

    cometa& get_metadata() { return _cometa; }
};

}
