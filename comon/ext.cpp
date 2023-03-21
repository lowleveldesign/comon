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

#include <algorithm>
#include <filesystem>
#include <format>
#include <functional>
#include <memory>
#include <tuple>
#include <vector>
#include <span>
#include <ranges>

#include <DbgEng.h>
#include <wil/com.h>

#include "comon.h"
#include "dbgsession.h"

using namespace comon_ext;

namespace fs = std::filesystem;

namespace {
dbgsession g_dbgsession{};

const wchar_t* monitor_not_enabled_error{ L"COM monitor not enabled for the current process. Run !comon attach to enable it.\n" };

std::vector<std::string> split_args(std::string_view args) {
    char citation_char{ '\0' };
    std::vector<std::string> vargs{};
    std::string token{};

    for (auto c : args) {
        if (citation_char != '\0') {
            if (c == citation_char) {
                if (!token.empty()) {
                    vargs.push_back(token);
                    token.clear();
                }
                citation_char = '\0';
            } else {
                token.push_back(c);
            }
        } else if (c == '"' || c == '\'') {
            citation_char = c;
        } else if (std::isspace(c) || c == ',') {
            if (!token.empty()) {
                vargs.push_back(token);
                token.clear();
            }
        } else {
            token.push_back(c);
        }
    }

    if (!token.empty()) {
        vargs.push_back(token);
    }

    return vargs;
}

void cometa_showi(wil::com_ptr_t<IDebugControl4> dbgcontrol, comon_ext::cometa& cometa, const IID& iid) {
    if (auto cotype{ cometa.resolve_type(iid) }; cotype) {
        dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL,
            std::format(L"Found: {:b} ({})\n\n", iid, cotype->name).c_str());

        if (auto methods{ cometa.get_type_methods(iid) }; methods) {
            dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"Methods:\n");
            for (size_t i = 0; i < methods->size(); i++) {
                auto& method = methods->at(i);
                auto method_args{ cometa.get_type_method_args(method) };
                assert(method_args);

                dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, std::format(L"- [{}] {} {}(", i, method.return_type, method.name).c_str());

                auto arg_iter = method_args->begin();
                if (arg_iter != method_args->end()) {
                    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, std::format(L"{} {}", arg_iter->type, arg_iter->name).c_str());
                    arg_iter++;
                }
                while (arg_iter != method_args->end()) {
                    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, std::format(L", {} {}", arg_iter->type, arg_iter->name).c_str());
                    arg_iter++;
                }
                dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, std::format(L")\n", i, method.return_type, method.name).c_str());
            }
        } else {
            dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"No information about the interface methods :(\n");
        }
    } else {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL,
            std::format(L"Can't find any details on IID: {:b} in the metadata.\n", iid).c_str());
    }

    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"\nRegistered VTables for IID:\n");
    for (auto& [module_name, clsid, vtbl] : cometa.find_vtables_by_iid(iid)) {
        auto clsid_name{ cometa.resolve_class_name(clsid) };
        dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL, std::format(
            L"- Module: <link cmd=\"!cometa showm {0}\">{0}</link>, CLSID: <link cmd=\"!cometa showc {1:b}\">{1:b}</link> ({2}), VTable offset: {3:#x}\n",
            module_name, clsid, clsid_name ? *clsid_name : L"N/A", vtbl).c_str());
    }
    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"\n");
}

void cometa_showc(wil::com_ptr_t<IDebugControl4> dbgcontrol, comon_ext::cometa& cometa, const CLSID& clsid) {
    if (auto coclass{ cometa.resolve_class(clsid) }; coclass) {
        dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL,
            std::format(L"Found: {:b} ({})\n", clsid, coclass->name).c_str());
    } else {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL,
            std::format(L"Can't find any details on CLSID: {:b} in the metadata.\n", clsid).c_str());
    }

    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"\nRegistered VTables for CLSID:\n");
    for (auto& [module_name, iid, vtbl] : cometa.find_vtables_by_clsid(clsid)) {
        auto iid_name{ cometa.resolve_type_name(iid) };
        dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL, std::format(
            L"- module: <link cmd=\"!cometa showm {0}\">{0}</link>, IID: <link cmd=\"!cometa showi {1:b}\">{1:b}</link> ({2}), VTable offset: {3:#x}\n",
            module_name, iid, iid_name ? *iid_name : L"N/A", vtbl).c_str());
    }
    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"\n");
}

void cometa_showm(wil::com_ptr_t<IDebugControl4> dbgcontrol, comon_ext::cometa& cometa, const std::wstring& module_name) {
    if (auto clsids{ cometa.find_clsids_by_module_name(module_name) }; !clsids.empty()) {
        std::ranges::sort(clsids, std::ranges::greater{}, [](auto& v) { return std::get<0>(v); });

        ULONG timestamp{};
        for (auto& [module_timestamp, clsid] : clsids) {
            if (module_timestamp != timestamp) {
                dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL,
                    std::format(L"\nRegistered CLSIDs for module with timestamp {:#x}:\n", timestamp).c_str());
                timestamp = module_timestamp;
            }
            auto clsid_name{ cometa.resolve_class_name(clsid) };
            dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL,
                std::format(L"- CLSID: <link cmd=\"!cometa showc {0:b}\">{0:b}</link> ({1})\n",
                    clsid, clsid_name ? *clsid_name : L"N/A").c_str());
        }
        dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"\n");
    } else {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL,
            std::format(L"Can't find any details on module '{}' in the metadata.\n", module_name).c_str());
    }
}

HRESULT try_finding_active_monitor(IDebugControl4* dbgcontrol, comonitor** monitor) {
    if (auto m{ g_dbgsession.find_active_monitor() }; m) {
        *monitor = m;
        return S_OK;
    } else {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, monitor_not_enabled_error);
        *monitor = nullptr;
        return E_FAIL;
    }
}

HRESULT evaluate_number(IDebugControl4* dbgeng, std::string_view arg, PULONG64 number) {
    try {
        if (arg.starts_with("0x")) {
            *number = std::stoull(arg.data(), nullptr, 16);
        } else if (arg.starts_with("0y")) {
            *number = std::stoull(arg.data() + 2, nullptr, 2);
        } else if (arg.starts_with("0t")) {
            *number = std::stoull(arg.data() + 2, nullptr, 8);
        } else if (arg.starts_with("0n")) {
            *number = std::stoull(arg.data() + 2, nullptr, 10);
        } else {
            ULONG radix{};
            RETURN_IF_FAILED(dbgeng->GetRadix(&radix));
            size_t pos{};
            *number = std::stoull(arg.data(), &pos, radix);
            return pos == arg.size() ? S_OK : E_INVALIDARG;
        }
        return S_OK;
    } catch (std::exception&) {
        return E_INVALIDARG;
    }
}

}

extern "C" HRESULT CALLBACK DebugExtensionInitialize(PULONG version, PULONG flags) {
    *version = DEBUG_EXTENSION_VERSION(EXT_MAJOR_VER, EXT_MINOR_VER);
    *flags = 0;
    return S_OK;
}

extern "C" void CALLBACK DebugExtensionNotify([[maybe_unused]] ULONG notify, [[maybe_unused]] ULONG64 argument) {}

extern "C" void CALLBACK DebugExtensionUninitialize(void) { g_dbgsession.detach(); }

extern "C" HRESULT CALLBACK cometa(IDebugClient * dbgclient, PCSTR args) {
    wil::com_ptr_t<IDebugControl4> dbgcontrol;
    RETURN_IF_FAILED(dbgclient->QueryInterface(__uuidof(IDebugControl4), dbgcontrol.put_void()));

    auto vargs{ split_args(args) };

    if (vargs.size() == 0) {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }

    auto& cometa{ g_dbgsession.get_metadata() };
    if (vargs[0] == "index") {
        return vargs.size() == 1 ? cometa.index() : cometa.index(widen(vargs[1]));
    } else if (vargs[0] == "save") {
        if (vargs.size() != 2) {
            dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
            return E_INVALIDARG;
        }
        return cometa.save(widen(vargs[1]));
    } else if (vargs[0] == "showi") {
        if (vargs.size() != 2) {
            dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
            return E_INVALIDARG;
        }
        if (IID iid{}; SUCCEEDED(try_parse_guid(widen(vargs[1]), iid))) {
            cometa_showi(dbgcontrol, cometa, iid);
            return S_OK;
        } else {
            dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: incorrect format of IID.\n");
            return E_INVALIDARG;
        }
    } else if (vargs[0] == "showc") {
        if (vargs.size() != 2) {
            dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
            return E_INVALIDARG;
        }
        if (CLSID clsid{}; SUCCEEDED(try_parse_guid(widen(vargs[1]), clsid))) {
            cometa_showc(dbgcontrol, cometa, clsid);
            return S_OK;
        } else {
            dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: incorrect format of CLSID.\n");
            return E_INVALIDARG;
        }
    } else if (vargs[0] == "showm") {
        if (vargs.size() != 2) {
            dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
            return E_INVALIDARG;
        }
        cometa_showm(dbgcontrol, cometa, widen(vargs[1]));
        return S_OK;
    } else {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: unknown subcommand. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }
}

extern "C" HRESULT CALLBACK comon(IDebugClient * dbgclient, PCSTR args) {
    wil::com_ptr_t<IDebugControl4> dbgcontrol;
    RETURN_IF_FAILED(dbgclient->QueryInterface(__uuidof(IDebugControl4), dbgcontrol.put_void()));

    auto print_filter = [&dbgcontrol](const cofilter& filter) {
        auto print_clsids = [&dbgcontrol](const std::unordered_set<CLSID>& clsids) {
            for (auto& clsid : clsids) {
                dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, std::format(L"- {:b}\n", clsid).c_str());
            }
        };

        if (auto fltr = std::get_if<including_filter>(&filter); fltr) {
            dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"\nCLSIDs to monitor:\n");
            print_clsids(fltr->clsids);
            return;
        }
        if (auto fltr = std::get_if<excluding_filter>(&filter); fltr) {
            dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"\nCLSIDs to EXCLUDE while monitoring:\n");
            print_clsids(fltr->clsids);
            return;
        }
        assert(std::holds_alternative<no_filter>(filter));
    };

    auto parse_filter = [](std::span<const std::string> args) -> cofilter {
        std::unordered_set<CLSID> clsids{};
        for (auto iter{ std::crbegin(args) }; iter != std::crend(args); iter++) {
            if (*iter == "-i") {
                return including_filter{ clsids };
            }
            if (*iter == "-e") {
                return excluding_filter{ clsids };
            }
            GUID clsid;
            if (SUCCEEDED(try_parse_guid(widen(*iter), clsid))) {
                clsids.insert(clsid);
            }
        }
        if (clsids.size() > 0) {
            return including_filter{ clsids };
        }
        return no_filter{};
    };

    auto vargs{ split_args(args) };
    if (vargs.size() < 1) {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }

    if (vargs[0] == "attach") {
        auto filter = parse_filter(std::span{ vargs }.subspan(1));
        g_dbgsession.attach(filter);
        dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL, L"<b>COM monitor enabled for the current process.</b>\n");
        print_filter(filter);
        return S_OK;
    }

    comonitor* monitor{};
    RETURN_IF_FAILED(try_finding_active_monitor(dbgcontrol.get(), &monitor));

    if (vargs[0] == "attach") {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"COM monitor is already enabled for the current process.");
        return E_FAIL;
    } else if (vargs[0] == "pause") {
        monitor->pause();
    } else if (vargs[0] == "resume") {
        monitor->resume();
    } else if (vargs[0] == "detach") {
        g_dbgsession.detach();
    } else if (vargs[0] == "status") {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, std::format(L"COM monitor is {}\n",
            monitor->is_paused() ? L"PAUSED" : L"RUNNING").c_str());

        auto& cometa{ g_dbgsession.get_metadata() };
        dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"\nCOM types recorded for the current process:\n");
        for (auto& [clsid, vtables] : monitor->list_cotypes()) {
            auto clsid_name{ cometa.resolve_class_name(clsid) };
            dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL,
                std::format(L"\n<col fg=\"srcannot\">CLSID: <b>{:b} ({})</b></col>\n", clsid, clsid_name ? *clsid_name : L"N/A").c_str());
            for (auto& [addr, iid] : vtables) {
                auto iid_name{ cometa.resolve_type_name(iid) };
                dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL,
                    std::format(L"  IID: <b>{:b} ({})</b>, address: {:#x}\n", iid, iid_name ? *iid_name : L"N/A", addr).c_str());
            }
        }
    } else {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }
    return S_OK;
}

extern "C" HRESULT CALLBACK coreg(IDebugClient * dbgclient, PCSTR args) {
    wil::com_ptr_t<IDebugControl4> dbgcontrol;
    RETURN_IF_FAILED(dbgclient->QueryInterface(__uuidof(IDebugControl4), dbgcontrol.put_void()));

    auto vargs{ split_args(args) };

    if (vargs.size() < 3) {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }

    comonitor* monitor{};
    RETURN_IF_FAILED(try_finding_active_monitor(dbgcontrol.get(), &monitor));

    bool save_in_database{ true };
    bool replace_if_exists{};
    int arg_start_index = 0;

    if (vargs[arg_start_index] == "--nosave") {
        arg_start_index++;
        save_in_database = false;
    }

    if (vargs[arg_start_index] == "--force") {
        arg_start_index++;
        replace_if_exists = true;
    }

    if (vargs.size() - arg_start_index < 3) {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }

    CLSID clsid;
    RETURN_IF_FAILED(try_parse_guid(widen(vargs[arg_start_index]), clsid));
    IID iid;
    RETURN_IF_FAILED(try_parse_guid(widen(vargs[arg_start_index + 1]), iid));

    ULONG64 vtable_addr{};
    RETURN_IF_FAILED(evaluate_number(dbgcontrol.get(), vargs[arg_start_index + 2], &vtable_addr));

    return monitor->register_vtable(clsid, iid, vtable_addr, save_in_database, replace_if_exists);
}

extern "C" HRESULT CALLBACK cobp(IDebugClient * dbgclient, PCSTR args) {
    auto parse_behavior = [](const std::string& arg) -> std::optional<cobreakpoint_behavior> {
        if (arg == "--before") {
            return cobreakpoint_behavior::stop_before_call;
        }
        if (arg == "--after") {
            return cobreakpoint_behavior::stop_after_call;
        }
        if (arg == "--always") {
            return cobreakpoint_behavior::always_stop;
        }
        if (arg == "--trace-only") {
            return cobreakpoint_behavior::never_stop;
        }
        return std::nullopt;
    };

    wil::com_ptr_t<IDebugControl4> dbgcontrol;
    RETURN_IF_FAILED(dbgclient->QueryInterface(__uuidof(IDebugControl4), reinterpret_cast<LPVOID*>(dbgcontrol.put())));

    auto vargs{ split_args(args) };

    if (vargs.size() < 3) {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }

    comonitor* monitor{};
    RETURN_IF_FAILED(try_finding_active_monitor(dbgcontrol.get(), &monitor));

    int arg_start = 0;
    cobreakpoint_behavior behavior = cobreakpoint_behavior::stop_before_call;
    if (auto bopt{ parse_behavior(vargs[0]) }; bopt) {
        behavior = *bopt;
        arg_start++;
    }

    CLSID clsid;
    RETURN_IF_FAILED(try_parse_guid(widen(vargs[arg_start]), clsid));
    IID iid;
    RETURN_IF_FAILED(try_parse_guid(widen(vargs[arg_start + 1]), iid));

    ULONG64 method_num{};
    if (FAILED(evaluate_number(dbgcontrol.get(), vargs[arg_start + 2], &method_num))) {
        auto& cometa{ g_dbgsession.get_metadata() };
        if (auto methods{ cometa.get_type_methods(iid) }; methods) {
            auto method_name{ widen(vargs[arg_start + 2]) };
            auto matching_method = [&method_name](const comethod& method) { return method.name == method_name; };
            if (auto res{ std::find_if(std::cbegin(*methods), std::cend(*methods), matching_method) };res != std::end(*methods)) {
                method_num = static_cast<DWORD>(res - std::begin(*methods));
                return monitor->create_cobreakpoint(clsid, iid, static_cast<DWORD>(method_num), behavior);
            } else {
                dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: Could not find a method with the given name in the metadata.\n");
                return E_INVALIDARG;
            }
        } else {
            dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: No methods found for a given type in the metadata.\n");
            return E_INVALIDARG;
        }
    } else {
        return monitor->create_cobreakpoint(clsid, iid, static_cast<DWORD>(method_num), behavior);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        ::DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
