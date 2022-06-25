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

static const std::wstring_view combase_module_name{L"combase"};

dbgsession::dbgsession()
    : _dbgclient{create_IDebugClient()}, _dbgcontrol{_dbgclient.query<IDebugControl4>()}, _dbgsymbols{_dbgclient.query<IDebugSymbols3>()},
      _dbgsystemobjects{_dbgclient.query<IDebugSystemObjects>()}, _cometa{std::make_shared<cometa>(_dbgcontrol.get(),
                                                                                                   get_cometa_db_path())},
      _logger{_dbgcontrol.get()}, _log_filter{std::make_shared<cofilter>(cofilter::filter_type::Disabled)} {
    THROW_IF_FAILED(_dbgclient->GetEventCallbacksWide(_prev_callback.put()));
    THROW_IF_FAILED(_dbgclient->SetEventCallbacksWide(this));
}

HRESULT __stdcall dbgsession::Breakpoint(PDEBUG_BREAKPOINT2 bp) {
    ULONG id;
    if (SUCCEEDED(bp->GetId(&id))) {
        if (auto monitor{_monitors.find(get_active_process_id())}; monitor != std::end(_monitors)) {
            return monitor->second.handle_breakpoint(id) ? DEBUG_STATUS_GO : DEBUG_STATUS_NO_CHANGE;
        }
    }
    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT __stdcall dbgsession::LoadModule([[maybe_unused]] ULONG64 image_file_handle, ULONG64 base_offset,
                                         [[maybe_unused]] ULONG module_size, [[maybe_unused]] PCWSTR module_name,
                                         [[maybe_unused]] PCWSTR image_name, [[maybe_unused]] ULONG checksum, ULONG timestamp) {

    if (fs::path image_path{image_name}; image_path.has_filename()) {
        if (auto monitor{_monitors.find(get_active_process_id())}; monitor != std::end(_monitors)) {
            monitor->second.handle_module_load(image_path.filename().c_str(), timestamp, base_offset);
        }
    }
    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT __stdcall dbgsession::UnloadModule([[maybe_unused]] PCWSTR image_base_name, ULONG64 image_base_addr) {
    if (auto monitor{_monitors.find(get_active_process_id())}; monitor != std::end(_monitors)) {
        monitor->second.handle_module_unload(image_base_addr);
    }
    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT __stdcall dbgsession::ExitProcess([[maybe_unused]] ULONG exit_code) {
    detach();
    return DEBUG_STATUS_NO_CHANGE;
}

void dbgsession::pause() noexcept {
    if (auto monitor{find_active_monitor()}; monitor) {
        monitor->pause();
    } else {
        _logger.log_warning(L"Comon is not monitoring the current process.");
    }
}

void dbgsession::resume() noexcept {
    if (auto monitor{find_active_monitor()}; monitor) {
        monitor->resume();
    } else {
        _logger.log_warning(L"Comon is not monitoring the current process.");
    }
}
