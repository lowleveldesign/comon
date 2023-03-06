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
#include <string>
#include <array>
#include <cassert>
#include <ranges>
#include <algorithm>
#include <variant>
#include <functional>
#include <memory>

#include <SQLiteCpp/Database.h>
#include <SQLiteCpp/Statement.h>
#include <SQLiteCpp/Transaction.h>

#include <Windows.h>
#include <wil/com.h>
#include <wil/result.h>
#include <wil/resource.h>

#include "comon.h"
#include "cometa.h"

using namespace comon_ext;

namespace ranges = std::ranges;
namespace fs = std::filesystem;

/* *** COM METADATA *** */

// increment whenever the database schema changes
constexpr int schema_version{ 5 };

std::unique_ptr<SQLite::Database> cometa::init_db(const fs::path& path, IDebugControl4* dbgcontrol) {
    dbgeng_logger log{ dbgcontrol };

    if (path.empty()) {
        log.log_info(L"Could not open the metadata database from the dafault location. Switching to a temporary in-memory database.");
    } else {
        log.log_info(std::format(L"Creating a new metadata database at '{}'.", path.c_str()));
    }

    auto db{ std::make_unique<SQLite::Database>(to_utf8(path.c_str()), SQLite::OPEN_CREATE | SQLite::OPEN_READWRITE) };

    db->exec(R"(create table schema_version (version integer not null);)");
    db->exec(std::format("insert into schema_version (version) values({})", schema_version));

    db->exec(R"(create table cotypes (
iid blob primary key, 
type integer not null,
name text not null,
parent_iid blob not null,
methods_available int not null) without rowid)");

    db->exec(R"(create table cotype_methods (
iid blob not null,
ordinal integer not null,
name text not null,
callconv integer not null,
dispid integer null,
return_type text not null,
primary key (iid, ordinal)) without rowid)");

    db->exec(R"(create table cotype_method_args (
iid blob not null,
method_ordinal integer not null,
name text not null,
ordinal integer not null,
type text not null,
flags int not null,
primary key (iid, method_ordinal, ordinal)) without rowid)");

    db->exec(R"(create table coclasses (
clsid blob primary key, 
name text not null
) without rowid)");

    db->exec(R"(create table vtables (
clsid blob not null, 
iid blob not null,
module_name text not null,
module_timestamp integer not null,
vtable integer not null,
primary key (clsid, iid)) without rowid;
create index IX_vtables_iid on vtables (iid);
create index IX_vtables_module_name on vtables (module_name))");

    return db;
}

std::unique_ptr<SQLite::Database> cometa::open_db(const fs::path& path, IDebugControl4* dbgcontrol) {
    dbgeng_logger log{ dbgcontrol };
    log.log_info(std::format(L"Opening an existing metadata database from '{}'.", path.c_str()));

    auto db{ std::make_unique<SQLite::Database>(to_utf8(path.c_str()), SQLite::OPEN_READWRITE) };
    if (SQLite::Statement query{ *db, "select version from schema_version" };
        !query.executeStep() || query.getColumn("version").getInt() != schema_version) {
        log.log_error(L"Incorrect version of the schema detected.", E_FAIL);
        throw std::invalid_argument{ "incorrect database schema" };
    }
    return db;
}


cometa::cometa(IDebugControl4* dbgcontrol, bool is_wow64, const fs::path& db_path, bool create_new):
    _logger{ dbgcontrol }, _is_wow64{ is_wow64 },
    _db{ create_new ? init_db(db_path, dbgcontrol) : open_db(db_path, dbgcontrol) } {

    if (create_new) {
        fill_known_iids();
    }
}

void cometa::fill_known_iids() {
    // we insert all fundamental COM types here to make sure that they are always available

    SQLite::Transaction transaction{ *_db };

    // IUnknown
    insert_cotype(cotype{ __uuidof(IUnknown), L"IUnknown", cotype_kind::Interface, {}, true });

    insert_cotype_method(comethod{ __uuidof(IUnknown), L"QueryInterface", 0, CC_STDCALL, std::nullopt, L"HRESULT" });
    insert_cotype_method_arg(__uuidof(IUnknown), 0, comethod_arg{ L"riid", L"REFIID", IDLFLAG_FIN }, 0);
    insert_cotype_method_arg(__uuidof(IUnknown), 0, comethod_arg{ L"ppvObject", L"void**", IDLFLAG_FOUT }, 1);

    insert_cotype_method(comethod{ __uuidof(IUnknown), L"AddRef", 1, CC_STDCALL, std::nullopt, L"ULONG" });

    insert_cotype_method(comethod{ __uuidof(IUnknown), L"Release", 2, CC_STDCALL, std::nullopt, L"ULONG" });

    // IDispatch
    insert_cotype(cotype{ __uuidof(IDispatch), L"IDispatch", cotype_kind::Interface, __uuidof(IUnknown), true });

    insert_cotype_method(comethod{ __uuidof(IDispatch), L"GetTypeInfoCount", 0, CC_STDCALL, std::nullopt, L"HRESULT" });
    insert_cotype_method_arg(__uuidof(IDispatch), 0, comethod_arg{ L"pctinfo", L"UINT*", IDLFLAG_FOUT }, 0);

    insert_cotype_method(comethod{ __uuidof(IDispatch), L"GetTypeInfo", 1, CC_STDCALL, std::nullopt, L"HRESULT" });
    insert_cotype_method_arg(__uuidof(IDispatch), 1, comethod_arg{ L"iTInfo", L"UINT", IDLFLAG_FIN }, 0);
    insert_cotype_method_arg(__uuidof(IDispatch), 1, comethod_arg{ L"lcid", L"LCID", IDLFLAG_FIN }, 1);
    insert_cotype_method_arg(__uuidof(IDispatch), 1, comethod_arg{ L"ppTInfo", L"ITypeInfo**", IDLFLAG_FOUT }, 2);

    insert_cotype_method(comethod{ __uuidof(IDispatch), L"GetIDsOfNames", 2, CC_STDCALL, std::nullopt, L"HRESULT" });
    insert_cotype_method_arg(__uuidof(IDispatch), 2, comethod_arg{ L"riid", L"REFIID", IDLFLAG_FIN }, 0);
    insert_cotype_method_arg(__uuidof(IDispatch), 2, comethod_arg{ L"rgszNames", L"LPOLESTR*", IDLFLAG_FIN }, 1);
    insert_cotype_method_arg(__uuidof(IDispatch), 2, comethod_arg{ L"cNames", L"UINT", IDLFLAG_FIN }, 2);
    insert_cotype_method_arg(__uuidof(IDispatch), 2, comethod_arg{ L"lcid", L"LCID", IDLFLAG_FIN }, 3);
    insert_cotype_method_arg(__uuidof(IDispatch), 2, comethod_arg{ L"rgDispId", L"DISPID*", IDLFLAG_FOUT }, 4);

    insert_cotype_method(comethod{ __uuidof(IDispatch), L"Invoke", 3, CC_STDCALL, std::nullopt, L"HRESULT" });
    insert_cotype_method_arg(__uuidof(IDispatch), 3, comethod_arg{ L"dispIdMember", L"DISPID", IDLFLAG_FIN }, 0);
    insert_cotype_method_arg(__uuidof(IDispatch), 3, comethod_arg{ L"riid", L"REFIID", IDLFLAG_FIN }, 1);
    insert_cotype_method_arg(__uuidof(IDispatch), 3, comethod_arg{ L"lcid", L"LCID", IDLFLAG_FIN }, 2);
    insert_cotype_method_arg(__uuidof(IDispatch), 3, comethod_arg{ L"wFlags", L"WORD", IDLFLAG_FIN }, 3);
    insert_cotype_method_arg(__uuidof(IDispatch), 3, comethod_arg{ L"pDispParams", L"DISPPARAMS*", IDLFLAG_FIN }, 4);
    insert_cotype_method_arg(__uuidof(IDispatch), 3, comethod_arg{ L"pVarResult", L"VARIANT*", IDLFLAG_FOUT }, 5);
    insert_cotype_method_arg(__uuidof(IDispatch), 3, comethod_arg{ L"pExcepInfo", L"EXCEPINFO*", IDLFLAG_FOUT }, 6);
    insert_cotype_method_arg(__uuidof(IDispatch), 3, comethod_arg{ L"puArgErr", L"UINT*", IDLFLAG_FOUT }, 7);

    transaction.commit();

    _known_iids.insert_range(std::array<IID, 2> { __uuidof(IUnknown), __uuidof(IDispatch) });
}

bool cometa::is_valid_db(const fs::path& path) {
    try {
        auto db{ std::make_unique<SQLite::Database>(to_utf8(path.c_str()), SQLite::OPEN_READWRITE) };
        SQLite::Statement query{ *db, "select version from schema_version" };
        return query.executeStep() && query.getColumn("version").getInt() == schema_version;
    } catch (...) {
        return false;
    }
}

void cometa::insert_cotype(const cotype& typedesc) {
    if (_known_iids.contains(typedesc.iid)) {
        return;
    }

    assert(_db);
    auto name_u8{ to_utf8(typedesc.name) };

    SQLite::Statement stmt{ *_db, R"(insert or replace into cotypes (iid, type, name, parent_iid, methods_available) 
    values (:iid, :type, :name, :parent_iid, :methods_available))" };
    stmt.bindNoCopy(":iid", &typedesc.iid, sizeof(GUID));
    stmt.bind(":type", static_cast<int>(typedesc.type));
    stmt.bindNoCopy(":name", name_u8);
    stmt.bindNoCopy(":parent_iid", &typedesc.parent_iid, sizeof(GUID));
    stmt.bind(":methods_available", static_cast<int>(typedesc.methods_available));

    stmt.exec();
}

void cometa::insert_cotype_method(const comethod& method) {
    if (_known_iids.contains(method.iid)) {
        return;
    }

    assert(_db);

    auto name_u8{ to_utf8(method.name) };
    auto return_type_u8{ to_utf8(method.return_type) };

    SQLite::Statement stmt{ *_db, R"(insert or replace into cotype_methods (iid, ordinal, name, dispid, callconv, return_type)
    values (:iid, :ordinal, :name, :dispid, :callconv, :return_type))" };
    stmt.bindNoCopy(":iid", &method.iid, sizeof(GUID));
    stmt.bind(":ordinal", method.ordinal);
    stmt.bindNoCopy(":name", name_u8);
    if (method.dispid) {
        stmt.bind(":dispid", static_cast<int>(*method.dispid));
    } else {
        stmt.bind(":dispid");
    }
    stmt.bind(":callconv", static_cast<int>(method.callconv));
    stmt.bindNoCopy(":return_type", return_type_u8);

    stmt.exec();
}

void cometa::insert_cotype_method_arg(const GUID& iid, int method_ordinal, const comethod_arg& arg, int arg_ordinal) {
    if (_known_iids.contains(iid)) {
        return;
    }

    assert(_db);

    auto name_u8{ to_utf8(arg.name) };
    auto type_u8{ to_utf8(arg.type) };

    SQLite::Statement stmt{ *_db, R"(insert or replace into cotype_method_args (iid, method_ordinal, ordinal, name, type, flags)
    values (:iid, :method_ordinal, :ordinal, :name, :type, :flags))" };
    stmt.bindNoCopy(":iid", &iid, sizeof(GUID));
    stmt.bind(":method_ordinal", method_ordinal);
    stmt.bind(":ordinal", arg_ordinal);
    stmt.bindNoCopy(":name", name_u8);
    stmt.bindNoCopy(":type", type_u8);
    stmt.bind(":flags", arg.flags);

    stmt.exec();
}

void cometa::insert_coclass(const coclass& classdesc) {
    assert(_db);
    auto name_u8{ to_utf8(classdesc.name) };

    SQLite::Statement stmt{ *_db, "insert or replace into coclasses (clsid, name) values (:clsid, :name)" };
    stmt.bindNoCopy(":clsid", &classdesc.clsid, sizeof(GUID));
    stmt.bindNoCopy(":name", name_u8);

    stmt.exec();
}

std::vector<covtable> cometa::get_module_vtables(const comodule& comodule) {
    assert(_db);
    auto module_name_u8{ to_utf8(comodule.name) };
    SQLite::Statement query{ *_db,
        "select clsid,iid,vtable from vtables where module_name = :module_name and module_timestamp = :module_timestamp" };
    query.bindNoCopy(":module_name", module_name_u8);
    query.bind(":module_timestamp", static_cast<const uint32_t>(comodule.timestamp));

    std::vector<covtable> vtables{};
    while (query.executeStep()) {
        vtables.push_back({
            *(reinterpret_cast<const GUID*>(query.getColumn("clsid").getBlob())),
            *(reinterpret_cast<const GUID*>(query.getColumn("iid").getBlob())),
            static_cast<ULONG>(query.getColumn("vtable").getInt64())
            });
    }
    return vtables;
}

void cometa::save_module_vtable(const comodule& comodule, const covtable& covtable) {
    assert(_db);
    auto module_name_u8{ to_utf8(comodule.name) };

    SQLite::Statement query{ *_db, R"(insert or replace into vtables (clsid, iid, module_name, module_timestamp, vtable) 
        values (:clsid, :iid, :module_name, :module_timestamp, :vtable))" };

    query.bindNoCopy(":clsid", &covtable.clsid, sizeof(GUID));
    query.bindNoCopy(":iid", &covtable.iid, sizeof(GUID));
    query.bindNoCopy(":module_name", module_name_u8);
    query.bind(":module_timestamp", static_cast<const uint32_t>(comodule.timestamp));
    query.bind(":vtable", static_cast<long long>(covtable.address));

    query.exec();
}

HRESULT cometa::index_tlb(std::wstring_view tlb_path) {
    using namespace std::literals;
    assert(_db);

    wil::com_ptr_t<ITypeLib> typelib{};
    RETURN_IF_FAILED(::LoadTypeLibEx(tlb_path.data(), REGKIND_NONE, typelib.put()));

    auto types_len = typelib->GetTypeInfoCount();
    for (UINT i = 0; i < types_len; i++) {
        wil::com_ptr_t<ITypeInfo> typeinfo{};
        RETURN_IF_FAILED(typelib->GetTypeInfo(i, typeinfo.put()));

        wil::unique_bstr name{};
        RETURN_IF_FAILED(typeinfo->GetDocumentation(MEMBERID_NIL, name.put(), nullptr, nullptr, nullptr));

        auto typeattr_res{ typelib::get_typeinfo_attr(typeinfo.get()) };
        if (std::holds_alternative<HRESULT>(typeattr_res)) {
            return std::get<HRESULT>(typeattr_res);
        }

        auto typeattr{ std::move(std::get<typelib::typeattr_t>(typeattr_res)) };
        switch (typeattr->typekind) {
        case TKIND_INTERFACE:
        case TKIND_DISPATCH: {
            auto kind{ typeattr->typekind == TKIND_INTERFACE ? cotype_kind::Interface : cotype_kind::DispInterface };

            auto get_type_name = [typeinfo, kind](const TYPEDESC* tdesc) {
                auto return_type_v{ typelib::get_type_desc(typeinfo.get(), tdesc) };
                return std::holds_alternative<std::wstring>(return_type_v) ? std::get<std::wstring>(return_type_v) :
                    std::wstring{ typelib::bad_type_name };
            };

            auto parent_iid_v{ typelib::get_type_parent_iid(typeinfo.get(), kind, typeattr->cImplTypes) };
            if (std::holds_alternative<HRESULT>(parent_iid_v)) {
                return std::get<HRESULT>(parent_iid_v);
            }
            auto& parent_iid{ std::get<GUID>(parent_iid_v) };

            auto funcdesc_deleter = [typeinfo](FUNCDESC* fd) { typeinfo->ReleaseFuncDesc(fd); };

            SQLite::Transaction transaction{ *_db };

            insert_cotype({ typeattr->guid, name.get(), kind, parent_iid, true });

            // TODO: typeattr->cVars for properties in dispinterfaces

            for (int ordinal = 0; ordinal < typeattr->cFuncs; ) {
                FUNCDESC* p_fd;
                RETURN_IF_FAILED(typeinfo->GetFuncDesc(ordinal, &p_fd));
                typelib::funcdesc_t fd{ p_fd, funcdesc_deleter };

                if (auto names_v{ typelib::get_comethod_names(typeinfo.get(), fd.get()) }; std::holds_alternative<HRESULT>(names_v)) {
                    return std::get<HRESULT>(names_v);
                } else {
                    auto& names = std::get<std::vector<wil::unique_bstr>>(names_v);
                    assert(names.size() > 0);

                    if (ordinal == 0 && names[0].get() == L"QueryInterface"sv) {
                        // skip IUnknown
                        ordinal += 3;
                        continue;
                    }
                    if ((ordinal == 0 || ordinal == 3) && names[0].get() == L"GetTypeInfoCount"sv) {
                        // skip IDispatch
                        ordinal += 4;
                        continue;
                    }

                    std::wstring method_name{ names[0].get() };
                    if (fd->invkind & INVOKE_PROPERTYPUTREF) {
                        method_name.insert(0, L"putref_");
                    } else if (fd->invkind & INVOKE_PROPERTYPUT) {
                        method_name.insert(0, L"put_");
                    } else if (fd->invkind & INVOKE_PROPERTYGET) {
                        method_name.insert(0, L"get_");
                    }
                    std::optional<DISPID> dispid = kind == cotype_kind::DispInterface ? std::make_optional(fd->memid) : std::nullopt;

                    assert((SHORT)names.size() == fd->cParams + 1);
                    for (int arg_ordinal = 0; arg_ordinal < fd->cParams; arg_ordinal++) {
                        auto elem_desc{ fd->lprgelemdescParam + arg_ordinal };
                        comethod_arg arg{
                            std::wstring { names[arg_ordinal + 1].get()},
                            get_type_name(&elem_desc->tdesc),
                            elem_desc->idldesc.wIDLFlags
                        };
                        insert_cotype_method_arg(typeattr->guid, ordinal, arg, arg_ordinal);
                    }

                    auto result_vt{ fd->elemdescFunc.tdesc.vt & 0xFFF };
                    if (kind == cotype_kind::DispInterface && result_vt != VT_HRESULT && result_vt != VT_VOID) {
                        // the return value is passed as an out parameter
                        TYPEDESC tdesc{ .lptdesc = &fd->elemdescFunc.tdesc, .vt = VT_PTR };
                        comethod_arg arg{
                            std::wstring { L"result" },
                            get_type_name(&tdesc),
                            IDLFLAG_FOUT | IDLFLAG_FRETVAL
                        };
                        insert_cotype_method_arg(typeattr->guid, ordinal, arg, fd->cParams);

                        insert_cotype_method({ typeattr->guid, method_name, ordinal, fd->callconv, dispid, typelib::vt_to_string(VT_HRESULT) });
                    } else {
                        insert_cotype_method({ typeattr->guid, method_name, ordinal, fd->callconv, dispid, get_type_name(&fd->elemdescFunc.tdesc) });
                    }

                    // TODO: I'm still missing handling of the optional parameters

                    ordinal += 1;
                }
            }

            transaction.commit();
            break;
        }
        case TKIND_COCLASS: {
            insert_coclass({ typeattr->guid, name.get() });
            break;
        }
        default:
            break;
        }
    }

    return S_OK;
}

HRESULT cometa::save([[maybe_unused]] std::wstring_view dbpath) {
    assert(_db);
    try {
        _db->backup(to_utf8(dbpath).c_str(), SQLite::Database::BackupType::Save);
        return S_OK;
    } catch (const SQLite::Exception& ex) {
        _logger.log_error(std::format(L"Error {} when trying to save COM metadata database: '{}'.",
            ex.getErrorCode(), widen(ex.getErrorStr())), E_FAIL);
        return E_FAIL;
    }
}

HRESULT cometa::index() {
    assert(_db);

    auto index_typelibs = [this]() {
        // HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Wow6432Node\Typelib is linked to HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Typelib
        // so we don't need to query it. However, the typelibs may contain both win32 and win64 folders, for example:
        // 
        // Computer\HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{00000201-0000-0010-8000-00AA006D2EA4}
        // - 2.1
        //   - 0
        //     - win32 -> C:\Program Files (x86)\Common Files\System\ado\msado21.tlb
        //     - win64 -> C:\Program Files\Common Files\System\ado\msado21.tlb
        //   - FLAGS
        _logger.log_info(L"\nIndexing TypeLibraries...");

        wil::unique_hkey typelibs_hkey{};
        RETURN_IF_WIN32_ERROR(::RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\TypeLib", 0, KEY_READ, typelibs_hkey.put()));
        for (const auto& name : registry::get_child_key_names(typelibs_hkey.get())) {
            wil::unique_hkey typelib_hkey{};
            if (auto err{ ::RegOpenKeyEx(typelibs_hkey.get(), name.c_str(), 0, KEY_READ, typelib_hkey.put()) }; err != NO_ERROR) {
                _logger.log_error(name, HRESULT_FROM_WIN32(err));
                continue;
            }

            if (auto ti{ typelib::get_tlbinfo(typelib_hkey.get()) }; std::holds_alternative<HRESULT>(ti)) {
                auto hr = std::get<HRESULT>(ti);
                _logger.log_error(name, hr);
            } else {
                auto& tlbinfo{ std::get<typelib_info>(ti) };
                if (auto hr{ index_tlb(tlbinfo.tlb_path.c_str()) }; SUCCEEDED(hr)) {
                    _logger.log_info_dml(std::format(L"{} ({}) : <col fg=\"srccmnt\">PARSED</col>", name, tlbinfo.name));
                } else {
                    _logger.log_error(std::format(L"{} ({})", name, tlbinfo.name), hr);
                }
            }
        }
        return S_OK;
    };

    auto index_coclasses = [this](bool request_wow6432 = false) {
        _logger.log_info(request_wow6432 ? L"Indexing CLSIDs... (only errors are reported) - 32-bit" :
            L"Indexing CLSIDs... (only errors are reported)");

        auto flags{ request_wow6432 ? KEY_READ | KEY_WOW64_32KEY : KEY_READ };
        wil::unique_hkey clsids_hkey{};
        RETURN_IF_WIN32_ERROR(::RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", 0, flags, clsids_hkey.put()));
        for (const auto& name : registry::get_child_key_names(clsids_hkey.get())) {
            if (name == L"CLSID") {
                // special key name to skip
                continue;
            }

            GUID clsid{};
            if (auto hr{ try_parse_guid(name, clsid) }; FAILED(hr)) {
                _logger.log_error(name, hr);
                continue;
            }

            wil::unique_hkey clsid_hkey{};
            if (auto err{ ::RegOpenKeyEx(clsids_hkey.get(), name.c_str(), 0, KEY_READ, clsid_hkey.put()) }; err != NO_ERROR) {
                auto hr{ HRESULT_FROM_WIN32(err) };
                _logger.log_error(name, hr);
                continue;
            }

            if (auto v{ registry::read_text_value(clsid_hkey.get(), nullptr, nullptr) }; std::holds_alternative<HRESULT>(v)) {
                insert_coclass({ .clsid = clsid, .name = L"" });
            } else {
                insert_coclass({ .clsid = clsid, .name = std::get<std::wstring>(v) });
            }
        }
        return S_OK;
    };

    auto index_interfaces = [this](bool request_wow6432 = false) {
        _logger.log_info(request_wow6432 ? L"Indexing interfaces... (only errors are reported) - 32-bit" :
            L"Indexing interfaces... (only errors are reported)");

        auto flags{ request_wow6432 ? KEY_READ | KEY_WOW64_32KEY : KEY_READ };
        wil::unique_hkey interfaces_hkey{};
        RETURN_IF_WIN32_ERROR(::RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\Interface", 0, flags, interfaces_hkey.put()));
        for (const auto& name : registry::get_child_key_names(interfaces_hkey.get())) {
            GUID iid{};
            if (auto hr{ try_parse_guid(name, iid) }; FAILED(hr)) {
                _logger.log_error(name, hr);
                continue;
            }

            wil::unique_hkey iid_hkey{};
            if (auto err{ ::RegOpenKeyEx(interfaces_hkey.get(), name.c_str(), 0, KEY_READ, iid_hkey.put()) }; err != NO_ERROR) {
                _logger.log_error(name, HRESULT_FROM_WIN32(err));
                continue;
            }

            if (auto v{ registry::read_text_value(iid_hkey.get(), nullptr, nullptr) }; std::holds_alternative<HRESULT>(v)) {
                insert_cotype({ iid, L"", cotype_kind::Interface, __uuidof(IUnknown), false });
            } else {
                insert_cotype({ iid, std::get<std::wstring>(v), cotype_kind::Interface, __uuidof(IUnknown), false });
            }
        }

        invalidate_cache();

        return S_OK;
    };

    // index 32-bit nodes first before indexing 64-bit
    RETURN_IF_FAILED(index_coclasses(_is_wow64));
    RETURN_IF_FAILED(index_interfaces(_is_wow64));

    RETURN_IF_FAILED(index_typelibs());

    return S_OK;
}

std::optional<cotype> cometa::resolve_type(const IID& iid) {
    if (_cotype_cache.contains(iid)) {
        return _cotype_cache.get(iid);
    }

    assert(_db);
    SQLite::Statement query{ *_db, "select * from cotypes where iid = :iid" };
    query.bindNoCopy(":iid", &iid, sizeof(IID));

    auto result{ !query.executeStep() ? std::nullopt :
        std::make_optional(cotype{ iid, from_utf8(query.getColumn("name").getText()),
            static_cast<cotype_kind>(query.getColumn("type").getInt()),
            *(reinterpret_cast<const GUID*>(query.getColumn("parent_iid").getBlob())),
            static_cast<bool>(query.getColumn("methods_available").getInt()) }) };
    _cotype_cache.insert(iid, result);

    return result;
}

std::optional<method_collection> cometa::get_type_methods(const IID& iid) {
    assert(_db);
    auto query_methods = [this](const IID& iid) {
        SQLite::Statement method_query{ *_db, "select * from cotype_methods where iid = :iid order by ordinal" };
        method_query.bindNoCopy(":iid", &iid, sizeof(IID));
        method_collection methods{};
        while (method_query.executeStep()) {
            auto dispid_column{ method_query.getColumn("dispid") };

            methods.push_back({
                .iid = iid,
                .name = from_utf8(method_query.getColumn("name").getText()),
                .ordinal = method_query.getColumn("ordinal").getInt(),
                .callconv = static_cast<CALLCONV>(method_query.getColumn("callconv").getInt()),
                .dispid = !dispid_column.isNull() ? std::optional<DISPID>{ dispid_column.getInt() } : std::nullopt,
                .return_type = from_utf8(method_query.getColumn("return_type").getText()) });
        }
        return methods;
    };

    if (auto type{ resolve_type(iid) }; type && type->methods_available) {
        if (auto methods{ query_methods(iid) }; methods.size() == 0 || methods.at(0).name != L"QueryInterface") {
            // The initial methods must be from the IUnknown interface. We will try to resolve the parent type...
            if (auto parent_methods{ get_type_methods(type->parent_iid) }; parent_methods) {
                std::ranges::copy(std::crbegin(*parent_methods), std::crend(*parent_methods), std::front_inserter(methods));
                return methods;
            } else {
                // we are missing some interface methods - it's safer to show nothing
                return std::nullopt;
            }
        } else {
            return methods;
        }
    }
    return std::nullopt;
}

std::optional<method_arg_collection> cometa::get_type_method_args(const comethod& method) {
    assert(_db);
    if (auto type{ resolve_type(method.iid) }; type && type->methods_available) {
        SQLite::Statement arg_query{ *_db, "select * from cotype_method_args where iid = :iid and method_ordinal = :method_ordinal order by ordinal" };
        arg_query.bindNoCopy(":iid", &method.iid, sizeof(IID));
        arg_query.bind(":method_ordinal", method.ordinal);

        method_arg_collection args{};
        while (arg_query.executeStep()) {
            args.push_back({
                .name = from_utf8(arg_query.getColumn("name").getText()),
                .type = from_utf8(arg_query.getColumn("type").getText()),
                .flags = static_cast<USHORT>(arg_query.getColumn("flags").getUInt()) });
        }
        return args;
    } else {
        return std::nullopt;
    }
}

std::optional<coclass> cometa::resolve_class(const CLSID& clsid) {
    if (_coclass_cache.contains(clsid)) {
        return _coclass_cache.get(clsid);
    }

    assert(_db);
    SQLite::Statement query{ *_db, "select * from coclasses where clsid = :clsid" };
    query.bindNoCopy(":clsid", &clsid, sizeof(CLSID));
    auto result{ !query.executeStep() ? std::nullopt :
        std::make_optional(coclass{ clsid, from_utf8(query.getColumn("name").getText()) })
    };
    return result;
}

std::vector<std::tuple<std::wstring, CLSID, ULONG64>> cometa::find_vtables_by_iid(const IID& iid) {
    SQLite::Statement query{ *_db, "select module_name,clsid,vtable from vtables where iid = :iid" };
    query.bindNoCopy(":iid", &iid, sizeof(IID));

    std::vector<std::tuple<std::wstring, CLSID, ULONG64>> vtables{};
    while (query.executeStep()) {
        vtables.push_back({
            from_utf8(query.getColumn("module_name").getString()),
            *(reinterpret_cast<const GUID*>(query.getColumn("clsid").getBlob())),
            query.getColumn("vtable").getInt64()
            });
    }
    return vtables;
}

std::vector<std::tuple<std::wstring, IID, ULONG64>> cometa::find_vtables_by_clsid(const CLSID& clsid) {
    SQLite::Statement query{ *_db, "select module_name,iid,vtable from vtables_{} where clsid = :clsid" };
    query.bindNoCopy(":clsid", &clsid, sizeof(CLSID));

    std::vector<std::tuple<std::wstring, IID, ULONG64>> vtables{};
    while (query.executeStep()) {
        vtables.push_back({
            from_utf8(query.getColumn("module_name").getString()),
            *(reinterpret_cast<const GUID*>(query.getColumn("iid").getBlob())),
            query.getColumn("vtable").getInt64()
            });
    }
    return vtables;
}

