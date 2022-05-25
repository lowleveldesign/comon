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

#include <DbgEng.h>
#include <wil/com.h>

#include "comon.h"
#include "dbgsession.h"

using namespace comon_ext;

namespace fs = std::filesystem;

dbgsession g_dbgsession{};

extern "C" HRESULT CALLBACK DebugExtensionInitialize(PULONG version, PULONG flags) {
    *version = DEBUG_EXTENSION_VERSION(EXT_MAJOR_VER, EXT_MINOR_VER);
    *flags = 0;
    return S_OK;
}

extern "C" void CALLBACK DebugExtensionNotify([[maybe_unused]] ULONG notify, [[maybe_unused]] ULONG64 argument) {}

extern "C" void CALLBACK DebugExtensionUninitialize(void) { g_dbgsession.detach(); }

extern "C" HRESULT CALLBACK cometa(IDebugClient *dbgclient, PCSTR args) {
    wil::com_ptr_t<IDebugControl4> dbgcontrol;
    RETURN_IF_FAILED(dbgclient->QueryInterface(__uuidof(IDebugControl4), reinterpret_cast<LPVOID *>(dbgcontrol.put())));

    auto vargs{split_args(args)};

    if (vargs.size() == 0) {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }

    auto &cometa{g_dbgsession.get_metadata()};
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
            if (auto cotype{cometa.resolve_type(iid)}; cotype) {
                dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL,
                                                 std::format(L"Found: {:b} ({})\n\n", iid, cotype->name).c_str());

                if (auto methods{cometa.get_type_methods(iid)}; methods) {
                    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"Methods:\n");
                    for (size_t i = 0; i < methods->size(); i++) {
                        dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, std::format(L"- [{}] {}\n", i, methods->at(i)).c_str());
                    }
                } else {
                    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"No information about the interface methods :(\n");
                }
            } else {
                dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL,
                                       std::format(L"Could not find any COM type with IID: {:b} in the metadata.\n", iid).c_str());
            }

            dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"\nRegistered VTables for IID:\n");
            for (auto &[module_name, clsid, is_64bit, vtbl] : cometa.find_vtables_by_iid(iid)) {
                auto clsid_name{cometa.resolve_class_name(clsid)};
                dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL,
                                       std::format(L"- Module: {} ({}), CLSID: {:b} ({}), VTable offset: {:#x}\n", module_name,
                                                   is_64bit ? L"64-bit" : L"32-bit", clsid, clsid_name ? *clsid_name : L"N/A", vtbl)
                                           .c_str());
            }
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
            if (auto coclass{cometa.resolve_class(clsid)}; coclass) {
                dbgcontrol->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL,
                                                 std::format(L"Found: {:b} ({})\n", clsid, coclass->name).c_str());
            } else {
                dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL,
                                       std::format(L"Could not find any COM class with CLSID: {:b} in the metadata.\n", clsid).c_str());
            }

            dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"\nRegistered VTables for CLSID:\n");
            for (auto &[module_name, iid, is_64bit, vtbl] : cometa.find_vtables_by_clsid(clsid)) {
                auto iid_name{cometa.resolve_type_name(iid)};
                dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL,
                                       std::format(L"- module: {} ({}), IID: {:b} ({}), VTable offset: {:#x}\n", module_name,
                                                   is_64bit ? L"64-bit" : L"32-bit", iid, iid_name ? *iid_name : L"N/A", vtbl)
                                           .c_str());
            }
            return S_OK;
        } else {
            dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: incorrect format of CLSID.\n");
            return E_INVALIDARG;
        }
    } else {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: unknown subcommand. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }
}

extern "C" HRESULT CALLBACK cobp(IDebugClient *dbgclient, PCSTR args) {
    wil::com_ptr_t<IDebugControl4> dbgcontrol;
    RETURN_IF_FAILED(dbgclient->QueryInterface(__uuidof(IDebugControl4), reinterpret_cast<LPVOID *>(dbgcontrol.put())));

    auto vargs{split_args(args)};

    if (vargs.size() < 3) {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }

    CLSID clsid;
    RETURN_IF_FAILED(try_parse_guid(widen(vargs[0]), clsid));
    IID iid;
    RETURN_IF_FAILED(try_parse_guid(widen(vargs[1]), iid));
    try {
        DWORD method_num{std::stoul(vargs[2])};
        return g_dbgsession.create_cobreakpoint(clsid, iid, method_num);
    } catch (const std::invalid_argument &) {
        // we will try with a method name
        return g_dbgsession.create_cobreakpoint(clsid, iid, widen(vargs[2]));
    }
}

extern "C" HRESULT CALLBACK cobl([[maybe_unused]] IDebugClient *dbgclient, [[maybe_unused]] PCSTR args) {
    g_dbgsession.list_breakpoints();
    return S_OK;
}

extern "C" HRESULT CALLBACK coadd(IDebugClient *dbgclient, PCSTR args) {
    wil::com_ptr_t<IDebugControl4> dbgcontrol;
    RETURN_IF_FAILED(dbgclient->QueryInterface(__uuidof(IDebugControl4), reinterpret_cast<LPVOID *>(dbgcontrol.put())));

    auto vargs{split_args(args)};

    if (vargs.size() < 3) {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }

    CLSID clsid;
    RETURN_IF_FAILED(try_parse_guid(widen(vargs[0]), clsid));
    IID iid;
    RETURN_IF_FAILED(try_parse_guid(widen(vargs[1]), iid));
    try {
        ULONG64 vtable_addr{std::stoull(vargs[2])};
        return g_dbgsession.register_vtable(clsid, iid, vtable_addr);
    } catch (const std::invalid_argument &) {
        // we will try with a method name
        return g_dbgsession.create_cobreakpoint(clsid, iid, widen(vargs[2]));
    }
}

extern "C" HRESULT CALLBACK colog(IDebugClient *dbgclient, PCSTR args) {
    wil::com_ptr_t<IDebugControl4> dbgcontrol;
    RETURN_IF_FAILED(dbgclient->QueryInterface(__uuidof(IDebugControl4), dbgcontrol.put_void()));
    try {
        auto &filter{g_dbgsession.get_log_filter()};

        if (auto vargs{split_args(args)}; vargs.empty()) {
            dbgcontrol->OutputWide(
                DEBUG_OUTPUT_NORMAL,
                std::format(L"COM monitor log filter: {}\n", cofilter::get_filter_type_name(filter.get_filter_type())).c_str());
            if (!filter.get_filtered_clsids().empty()) {
                dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, L"\nCLSIDs:\n");
                for (auto &clsid : filter.get_filtered_clsids()) {
                    dbgcontrol->OutputWide(DEBUG_OUTPUT_NORMAL, std::format(L"- {:b}\n", clsid).c_str());
                }
            }
        } else if (vargs.size() == 2 && (vargs[0] == "include" || vargs[0] == "exclude")) {
            auto new_filter_type = vargs[0] == "include" ? cofilter::filter_type::Including : cofilter::filter_type::Excluding;

            if (filter.get_filter_type() != new_filter_type) {
                dbgcontrol->OutputWide(
                    DEBUG_OUTPUT_NORMAL,
                    std::format(L"COM monitor log filter switched to: {}\n", cofilter::get_filter_type_name(new_filter_type)).c_str());
                g_dbgsession.set_log_filter(
                    std::make_shared<cofilter>(new_filter_type, std::unordered_set<CLSID>{parse_guid(widen(vargs[1]))}));
            } else {
                auto filter_set{filter.get_filtered_clsids()};
                filter_set.insert(parse_guid(widen(vargs[1])));
                g_dbgsession.set_log_filter(std::make_shared<cofilter>(new_filter_type, filter_set));
            }
        } else if (vargs.size() == 1 && vargs[0] == "none") {
            g_dbgsession.set_log_filter(std::make_shared<cofilter>(cofilter::filter_type::Including));
        } else if (vargs.size() == 1 && vargs[0] == "all") {
            g_dbgsession.set_log_filter(std::make_shared<cofilter>(cofilter::filter_type::Disabled));
        } else {
            throw std::invalid_argument{"Invalid arguments. Run !cohelp to check the syntax."};
        }
        return S_OK;
    } catch (const std::exception &ex) {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, std::format(L"Error: {}\n", widen(ex.what())).c_str());
        return E_FAIL;
    }
}

extern "C" HRESULT CALLBACK comon(IDebugClient *dbgclient, PCSTR args) {
    wil::com_ptr_t<IDebugControl4> dbgcontrol;
    RETURN_IF_FAILED(dbgclient->QueryInterface(__uuidof(IDebugControl4), dbgcontrol.put_void()));

    auto vargs{split_args(args)};
    if (vargs.size() != 1) {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }

    if (vargs[0] == "attach") {
        g_dbgsession.attach();
    } else if (vargs[0] == "pause") {
        g_dbgsession.pause();
    } else if (vargs[0] == "resume") {
        g_dbgsession.resume();
    } else if (vargs[0] == "detach") {
        g_dbgsession.detach();
    } else {
        dbgcontrol->OutputWide(DEBUG_OUTPUT_ERROR, L"ERROR: invalid arguments. Run !cohelp to check the syntax.\n");
        return E_INVALIDARG;
    }

    return S_OK;
}
