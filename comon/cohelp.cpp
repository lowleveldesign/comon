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

extern "C" HRESULT CALLBACK cohelp(IDebugClient * dbgclient, [[maybe_unused]] PCSTR args) {
    wil::com_ptr_t<IDebugControl4> dbgcontrol;
    RETURN_IF_FAILED(dbgclient->QueryInterface(__uuidof(IDebugControl4), dbgcontrol.put_void()));

    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"==============================================================\n");
    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L" comon v%d.%d.%d.%d - Copyright 2023 Sebastian Solnica\n", EXT_MAJOR_VER, EXT_MINOR_VER,
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
  !cometa showm <module_name>
      - shows virtual tables registered for a given module (DLL or EXE file)

  !comon attach [[-i|-e] {clsid1} {clsid2} ...]
      - starts COM monitor for the active process. If you're debugging a 32-bit WOW64
        process in a 64-bit debugger, make sure you set the effective CPU architecture to x86
        (.effmach x86), use -i to configure an including filter (monitors only the provided CLSIDs)
        or -e to configure an excluding filter (monitors all CLSIDs except for the provided ones)
  !comon detach
      - stops COM monitor for the active process.
  !comon pause
      - pauses COM monitoring for the active process.
  !comon resume
      - resumes COM monitoring for the active process.
  !comon status
      - shows the current monitoring status. It also lists all the virtual tables registered
        for a given process providing their IIDs and CLSIDs

  !cobp [--before|--after|--always|--trace-only] <clsid> <iid> <method_name|method_number>
      - sets a cobreakpoint (COM breakpoint) on a given COM method. When you create a cobreakpoint,
        comon will print the parameter values and return value of the method (if metadata is available).
        Additionally, the cobreakpoint can make the debugger stop before (--before), after (--after), or
        before and after (--always) the method is called. If you only want to see the parameter values,
        use the --trace-only option. To remove a cobreakpoint, use the bc with the cobreakpoint ID.

  !coreg [--force] [--nosave] <clsid> <iid> <vtable_address>
      - manually add a virtual table address to the COM monitor and bind them with
        a given COM interface (IID) and COM class (CLSID). If the --force option is
        provided, the virtual table will be added even if it's already registered. If
        the --nosave option is provided, the virtual table will not be saved to the
        cometa.db3 file.
==============================================================
)");

    return S_OK;
}
