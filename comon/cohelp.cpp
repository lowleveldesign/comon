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
#include <format>

#include <DbgEng.h>
#include <Windows.h>

#include <wil/com.h>
#include <wil/result.h>

#include "comon.h"

using namespace comon_ext;

extern "C" HRESULT CALLBACK cohelp(IDebugClient *dbgclient, [[maybe_unused]] PCSTR args) {
    wil::com_ptr_t<IDebugControl4> dbgcontrol;
    RETURN_IF_FAILED(dbgclient->QueryInterface(__uuidof(IDebugControl4), dbgcontrol.put_void()));

    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"==============================================================\n");
    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L" comon v%d.%d.%d.%d - Copyright 2022 Sebastian Solnica\n", EXT_MAJOR_VER, EXT_MINOR_VER,
                           EXT_PATCH_VER, EXT_TWEAK_VER);
    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"==============================================================\n\n");

    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, LR"(Available commands:

  !cometa index
      - indexes COM metadata found in the system (registered type libraries, CLSIDs,
        and interfaces). The results are saved to a cometa.db3 file in the user temporary
        folder. They should be automatically loaded on the next run.
  !cometa index <path_to_tlb_or_dll_file>
      - indexes COM metadata from the provided TLB or DLL file. The results are saved
        to a cometa.db3 file in the user temporary folder. They should be automatically
        loaded on the next run.

  !cometa showi <iid>
      - shows information about a given IID (COM interface ID). This command will show
        interface methods (if available) and virtual tables registered for this IID.
  !cometa showc <clsid>
      - shows virtual tables registered for a given CLSID (COM class ID)

  !comon attach
      - starts COM monitor for the active process. If you're debugging a 32-bit WOW64
        process in a 64-bit debugger, make sure you set the effective CPU architecture to x86
        (.effmach x86)
  !comon detach
      - stops COM monitor for the active process.
  !comon pause
      - pauses COM monitoring for the active process.
  !comon resume
      - resumes COM monitoring for the active process.

  !colog
      - shows current log filter settings.
  !colog none
      - do not log QueryInterface calls for any CLSIDs. This command will clear previously
        set filters.
  !colog include <clsid>
      - log QueryInterface calls only for a specific CLSID. You may call this command
        multiple times with various CLSIDs, adding them to the inclusion list. If, before
        calling this command, colog was in EXCLUDING mode, the filter list will be cleared. 
  !colog exclude <clsid>
      - log QueryInterface calls for CLSIDs different than the given CLSID. You may call
        this command multiple times with various CLSIDs, adding them to the exclusion list.
        If, before calling this command, colog was in INCLUDING mode, the filter list will
        be cleared. 
  !colog all
      - log QueryInterface calls for all the CLSIDs. This command will clear previously
        set filters.

  !cobp <clsid> <iid> <method_name>
      - creates a breakpoint on a method (identified by its name) in a given COM
        interface (IID) in a given COM class (CLSID)
  !cobp <clsid> <iid< <method_num>
      - creates a breakpoint on a method (identified by its index) in a given COM
        interface (IID) in a given COM class (CLSID)

  !coadd <clsid> <iid> <vtable_address>
      - manually add a virtual table address to the COM monitor and bind them with
        a given COM interface (IID) and COM class (CLSID)
==============================================================
)");

    return S_OK;
}
