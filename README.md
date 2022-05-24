# comon - a WinDbg extension to trace COM

![comon](https://github.com/lowleveldesign/comon/workflows/build/badge.svg)

**The project homepage is at <https://wtrace.net>.**

**Comon** is a WinDbg extension that can help you trace COM interactions (COM class creations and interface querying). You may use it to investigate various COM issues and better understand application logic. During a debugging session, comon will record virtual table addresses (for the newly created COM objects) and allow you to query them or even set breakpoints on COM interface methods. If COM metadata is available (either in the registry or in a standalone TLB/DLL file), you may load it into comon, and it will automatically decode COM identifiers.

Check [**the documentation**](https://wtrace.net/documentation/comon) to learn more.

![](comon.gif)

## Available commands:

```
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
```

## Building

Comon is built with CMake, using [vcpkg](https://vcpkg.io) as a package manager.

You may use one of the CMake presets to build a specific configuration (the path to vcpkg in CMakePresets.json is set to `c:\vcpkg`), for example:

```
cmake --preset=ninja-x64
cmake --build --preset=ninja-x64-release
```
