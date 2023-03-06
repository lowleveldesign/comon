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

#include <filesystem>

#include <DbgEng.h>

#include "dbgsession.h"

using namespace comon_ext;

namespace fs = std::filesystem;

static const std::wstring_view combase_module_name{ L"combase" };

dbgsession::dbgsession()
    : _dbgclient{ create_IDebugClient() }, _dbgcontrol{ _dbgclient.query<IDebugControl4>() },
    _dbgsymbols{ _dbgclient.query<IDebugSymbols3>() }, _dbgsystemobjects{ _dbgclient.query<IDebugSystemObjects>() },
    _cc{ _dbgcontrol.get(), _dbgclient.query<IDebugDataSpaces3>().get(), _dbgclient.query<IDebugRegisters2>().get(), _dbgsymbols.get() },
    _cometa{ create_cometa(_dbgcontrol.get(), _cc) } {

    THROW_IF_FAILED(_dbgclient->GetEventCallbacksWide(_prev_callback.put()));
    THROW_IF_FAILED(_dbgclient->SetEventCallbacksWide(this));
}

HRESULT dbgsession::Breakpoint(PDEBUG_BREAKPOINT2 bp) {
    ULONG id;
    if (SUCCEEDED(bp->GetId(&id))) {
        if (auto monitor{ _monitors.find(get_active_process_id()) }; monitor != std::end(_monitors)) {
            return monitor->second.handle_breakpoint(id) ? DEBUG_STATUS_GO : DEBUG_STATUS_NO_CHANGE;
        }
    }
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP_(HRESULT __stdcall) comon_ext::dbgsession::ChangeEngineState(ULONG flags, ULONG64 argument)
{
    if (flags == DEBUG_CES_BREAKPOINTS) {
        int brk_id = static_cast<ULONG>(argument);
        if (wil::com_ptr_t<IDebugBreakpoint2> breakpoint{}; FAILED(_dbgcontrol->GetBreakpointById2(brk_id, breakpoint.put()))) {
            for (auto& monitor : _monitors) {
                monitor.second.handle_breakpoint_removed(brk_id);
            }
        }
    }
    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT dbgsession::LoadModule([[maybe_unused]] ULONG64 image_file_handle, ULONG64 base_offset, [[maybe_unused]] ULONG module_size,
    [[maybe_unused]] PCWSTR module_name, [[maybe_unused]] PCWSTR image_name, [[maybe_unused]] ULONG checksum,
    ULONG timestamp) {

    if (module_name != nullptr) {
        if (auto monitor{ _monitors.find(get_active_process_id()) }; monitor != std::end(_monitors)) {
            monitor->second.handle_module_load(module_name, timestamp, base_offset);
        }
    }
    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT dbgsession::UnloadModule([[maybe_unused]] PCWSTR image_base_name, ULONG64 image_base_addr) {
    if (auto monitor{ _monitors.find(get_active_process_id()) }; monitor != std::end(_monitors)) {
        monitor->second.handle_module_unload(image_base_addr);
    }
    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT dbgsession::ExitProcess([[maybe_unused]] ULONG exit_code) {
    detach();
    return DEBUG_STATUS_NO_CHANGE;
}
