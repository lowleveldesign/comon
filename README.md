# comon - a WinDbg extension to trace COM calls

![comon](https://github.com/lowleveldesign/comon/workflows/build/badge.svg)

----------------

:information_source: Maintenance note (14.08.2025)

I no longer update this project. This extension works, but it has some issues, such as:

- it traces only the most comon ways of creating COM objects (`DllGetClassObject`, `CoRegisterClassObject`), so it will miss, for example, objects created in out parameters, or objects created using other COM API functions
- as it relies on breakpoints to collect the COM interactions, it slows down the target application significantly

Therefore, I recommend using comon for debugging relatively small applications or rely on [ETW tracing](https://wtrace.net/guides/com-troubleshooting/#observing-com-interactions-outside-windbg).

----------------

**Table of contents**

<!-- MarkdownTOC -->

- [Introduction](#introduction)
- [Loading the extension and starting the monitor](#loading-the-extension-and-starting-the-monitor)
- [Working with COM metadata](#working-with-com-metadata)
- [Tracing COM interactions](#tracing-com-interactions)
- [Stopping the COM monitor](#stopping-the-com-monitor)
- [Errors and limitations](#errors-and-limitations)
- [Building](#building)

<!-- /MarkdownTOC -->

**Please also check my [COM troubleshooting guide](https://wtrace.net/articles/com-troubleshooting/) to learn more about COM debugging with comon (and not only).**

## Introduction

**Comon** is a WinDbg extension that can help you trace COM interactions (COM class creations and interface querying). You may use it to investigate various COM issues and better understand application logic. During a debugging session, comon will record virtual table addresses (for the newly created COM objects) and allow you to query them or even set breakpoints on COM interface methods. If COM metadata is available (either in the registry or in a standalone TLB/DLL file), you may load it into comon, and it will automatically decode COM identifiers. Let's quickly walk through the comon functionalities.

COM objects used in this tutorial come from [my COM example project](https://github.com/lowleveldesign/protoss-com-example) (more information about it are available in [this blog post](https://lowleveldesign.org/2022/01/17/com-revisited/)).

![](comon.gif)

Available commands:

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
```

## Loading the extension and starting the monitor

To start using comon, you need to load it as any other extension:
```
.load comon
```
If a metadata file is already created (more about metadata later), comon will load it. The next step is to attach comon to the process(es) we want. When debugging a single process, it is a matter of calling **!comon attach**. In multi-process debugging sessions, switch to the target process (for example, `|1s`) and run the **!comon attach** command. Comon always creates one monitor per process, so when you call any **!comon** subcommand, it will execute on the monitor attached to the currently selected process.

If you're debugging a **32-bit process with 64-bit WinDbg (WOW64)**, ensure the effective architecture is correct (`.effmach` should return `x86`).

If you are interested only in specific CLSIDs or want to exclude some CLSIDs, you need to **define filters** when attaching to a process. The attach command contains **--include** and **--exclude** parameters (use either of them) which accept a comma-separated list of CLSIDs. Filtering improves the debugger and debuggee performance as fewer breakpoints are needed to trace COM calls. "COM-heavy" applications like Excel may not even start if we don't set the valid filters.

## Working with COM metadata

We need COM metadata to resolve CLSIDs and IIDs, identifiers of COM classes, and interfaces. The comon output without metadata contains only raw GUIDs and may be hard to read. Comon uses an SQLite database in the user's temporary folder to save information about indexed type libraries and virtual tables.

The primary command to work with metadata is **!cometa**. The subcommand **index** indexes COM registrations in the registry. Those include type libraries (the newest installed version), CLSIDs, and IIDs. The 64-bit version of the extension scans both 64-bit and 32-bit versions of the CLSID and Interfaces keys. If you provide a path to a TLB or DLL file to the **!cometa index** command, it will index it and add found metadata to the database. When indexing a DLL file, it must contain a type library as one of its resources. Type libraries are the best metadata sources, providing type names, methods, and parent types. With complete metadata for a given interface, you can set breakpoints using its method names instead of ordinal numbers.

Comon also provides commands to query the indexed metadata and virtual table addresses. **!cometa showi** displays information about a given IID, and **!cometa showc** exhibits information about a given CLSID. Example output:

```
0:000> !cometa showi {C5F45CBC-4439-418C-A9F9-05AC67525E43}
Found: {C5F45CBC-4439-418C-A9F9-05AC67525E43} (INexus)

Methods:
- [0] HRESULT QueryInterface(void* this, GUID* riid, void** ppvObject)
- [1] ULONG AddRef(void* this)
- [2] ULONG Release(void* this)
- [3] BAD_TYPE CreateUnit(void* this, BAD_TYPE unit_name, BAD_TYPE* ppUnk)

Registered VTables for IID:
- Module: protoss, CLSID: {F5353C58-CFD9-4204-8D92-D274C7578B53} (Nexus), VTable offset: 0x376f8
```

```
0:000> !cometa showc {F5353C58-CFD9-4204-8D92-D274C7578B53}
Found: {F5353C58-CFD9-4204-8D92-D274C7578B53} (Nexus)

Registered VTables for CLSID:
- module: protoss, IID: {00000001-0000-0000-C000-000000000046} (N/A), VTable offset: 0x3694c
- module: protoss, IID: {59644217-3E52-4202-BA49-F473590CC61A} (IGameObject), VTable offset: 0x37710
- module: protoss, IID: {C5F45CBC-4439-418C-A9F9-05AC67525E43} (INexus), VTable offset: 0x376f8
```

If you are looking for virtual tables registered for a given module, try **!cometa showm**.

## Tracing COM interactions

Comon uses breakpoints to trace COM calls, so don't be surprised if you see hundreds of breakpoints in the `bl` command output :) Breakpoints created by comon will have a comment in the command session describing the purpose of a given breakpoint. Apart from the automatic breakpoints, you may also use "special breakpoints" (called **cobreakpoints**) to break on COM method calls. The **!cobp** command creates such breakpoints. Starting from version 2.1, if COM metadata is available, comon will print method parameter values on cobreakpoint hit and monitor the method's return values (both out parameters values and the return code). It does not support all possible COM types but should print at least a memory address in most cases. When you set a cobreakpoint, you may decide if you want to stop the debugger before the method execution (**--before**), after the method finishes (**--after**), before and after execution (**--always**), or never (**--trace-only**). If you don't specify any parameter, the debugger will stop only before the method execution.

The --after cobreakpoints are especially useful when a method creates a new COM object instance. Comon won't know about it (it monitors only the well-known functions, such as `DllGetClassObject`, `IUnknown::QueryInterface`, and `IClassFactory::CreateInstance`), so you need to update its internal database manually. The command to register a new virtual table is **!coreg**.

A sample output from a debugging session with cobreakpoint set on `IGameUnit::CreateUnit` method:

```
0:000> !comon attach
COM monitor enabled for the current process.

0:000> !cobp --always F5353C58-CFD9-4204-8D92-D274C7578B53 C5F45CBC-4439-418C-A9F9-05AC67525E43 CreateUnit
[comon] Breakpoint 15 (address 0x66c61b72) created / updated

0:000> g
ModLoad: 76220000 7629c000   C:\WINDOWS\SysWOW64\ADVAPI32.dll
ModLoad: 75b30000 75bb2000   C:\WINDOWS\SysWOW64\sechost.dll
ModLoad: 66ae0000 66ae9000   C:\WINDOWS\SysWOW64\ktmw32.dll
[comon] 0:000 [protoss!DllGetClassObject] CLSID: {EFF8970E-C50F-45E0-9284-291CE5A6F771} (Probe), IID: {00000001-0000-0000-C000-000000000046} (N/A) -> SUCCESS (0x0)
[comon] 0:000 [protoss!DllGetClassObject] CLSID: {F5353C58-CFD9-4204-8D92-D274C7578B53} (Nexus), IID: {00000001-0000-0000-C000-000000000046} (N/A) -> SUCCESS (0x0)
[comon breakpoint] INexus::CreateUnit (iid: {C5F45CBC-4439-418C-A9F9-05AC67525E43}, clsid: {F5353C58-CFD9-4204-8D92-D274C7578B53})

Parameters:
- this: 0xe034e8 (void*)
- unit_name: 0xe0b7c4 (BSTR) -> "Probe"
- ppUnk: 0x75fbc8 (IUnknown**) -> 0x0 [out]

66c61b72 e979ae0100      jmp     protoss!Nexus::CreateUnit (66c7c9f0)
0:000> g
[comon breakpoint] INexus::CreateUnit (iid: {C5F45CBC-4439-418C-A9F9-05AC67525E43}, clsid: {F5353C58-CFD9-4204-8D92-D274C7578B53}) return
Result: 0x0 (HRESULT)

Out parameters:
- ppUnk: 0x75fbc8 (IUnknown**) -> 0xe0bbd8

eax=00000000 ebx=00a8d000 ecx=0e796c23 edx=00000001 esi=0075fadc edi=0075fbe8
eip=00813df5 esp=0075fadc ebp=0075fbf4 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ProtossComClient!start_from_nexus+0x195:
00813df5 3bf4            cmp     esi,esp
```

## Stopping the COM monitor

To stop comon monitoring of an active process, run the `!comon detach` command. The collected COM metadata will still be available, but comon will no longer log any details about COM calls.

## Errors and limitations

If **comon can't load a database file** with metadata (it always tries cometa.db3 in the user's temporary folder), it will use an in-memory database. Please make sure that there is no other application locking the cometa.db3 file. 

## Building

Comon is built with CMake, using [vcpkg](https://vcpkg.io) as a package manager.

You may use one of the CMake presets to build a specific configuration, for example:

```
cmake --preset=ninja-x64-release
cmake --build --preset=ninja-x64-release
```
