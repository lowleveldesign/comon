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
namespace views = std::ranges::views;
namespace fs = std::filesystem;

/* *** COM METADATA *** */

// increment whenever the database schema changes
static const int schema_version{ 4 };

class version
{
    std::array<int32_t, 4> _version_nums{};

public:
    version(const std::wstring& version): _version{ version } {
        std::wistringstream wss{ version };
        std::wstring token{};

        for (size_t i = 0; i < _version_nums.size(); i++) {
            std::getline(wss, token, L'.');
            if (!wss.good()) {
                break;
            }
            _version_nums[i] = std::stoi(token, nullptr, 16);
        }
    }

    [[nodiscard]] bool operator==(const version& rhs) const {
        return std::lexicographical_compare_three_way(_version_nums.cbegin(), _version_nums.cend(),
            rhs._version_nums.cbegin(), rhs._version_nums.cend()) == std::strong_ordering::equal;
    }

    std::strong_ordering operator<=>(const version& rhs) const {
        return std::lexicographical_compare_three_way(_version_nums.cbegin(), _version_nums.cend(),
            rhs._version_nums.cbegin(), rhs._version_nums.cend());
    }

    std::wstring _version;
};

namespace registry
{
std::vector<std::wstring> get_child_key_names(HKEY parent_hkey) {
    std::vector<std::wstring> key_names{};

    std::array<wchar_t, 256> key_name{};
    for (DWORD i = 0; ; i++) {
        auto len{ static_cast<DWORD>(key_name.size()) };
        auto enum_result{ ::RegEnumKeyEx(parent_hkey, i, key_name.data(), &len, nullptr, nullptr, nullptr, nullptr) };
        if (enum_result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        assert(enum_result != ERROR_MORE_DATA);
        if (enum_result != NO_ERROR) {
            LOG_WIN32(enum_result);
            break;
        }

        key_names.push_back(std::wstring{ key_name.data(), len });
    }

    return key_names;
}

std::variant<std::wstring, HRESULT> read_text_value(HKEY hkey, const wchar_t* subkey, const wchar_t* value_name) {
    DWORD len = 1024;
    auto buffer{ std::make_unique<wchar_t[]>(len) };

    auto win32err{ ::RegGetValue(hkey, subkey, value_name, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, nullptr, buffer.get(), &len) };
    if (win32err == ERROR_MORE_DATA) {
        buffer = std::make_unique<wchar_t[]>(len);
        win32err = ::RegGetValue(hkey, subkey, value_name, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, nullptr, buffer.get(), &len);
    }

    RETURN_IF_WIN32_ERROR(win32err);

    return std::wstring{ buffer.get() };
}
}

namespace typelib
{
using typeattr_t = std::unique_ptr<TYPEATTR, std::function<void(TYPEATTR*)>>;
using funcdesc_t = std::unique_ptr<FUNCDESC, std::function<void(FUNCDESC*)>>;

std::variant<typelib_info, HRESULT> get_tlbinfo(HKEY typelib_hkey) {
    std::vector<version> versions{};
    ranges::transform(registry::get_child_key_names(typelib_hkey), std::back_inserter(versions),
        [](const std::wstring& v) { return version{ v }; });

    auto latest_version{ ranges::max_element(versions) };
    if (latest_version != std::end(versions)) {
        wil::unique_hkey latest_version_hkey{};
        RETURN_IF_WIN32_ERROR(::RegOpenKeyEx(typelib_hkey, latest_version->_version.c_str(), 0, KEY_READ, latest_version_hkey.put()));
        auto name_kv{ registry::read_text_value(latest_version_hkey.get(), nullptr, nullptr) };
        if (std::holds_alternative<HRESULT>(name_kv)) {
            return std::get<HRESULT>(name_kv);
        }

#if _WIN32
        auto path_kv{ registry::read_text_value(latest_version_hkey.get(), L"0\\win32", nullptr) };
#else
        auto path_kv{ registry::read_text_value(latest_version_hkey.get(), L"0\\win64", nullptr) };
#endif

        if (std::holds_alternative<HRESULT>(path_kv)) {
            return std::get<HRESULT>(path_kv);
        }

        return typelib_info{ std::get<std::wstring>(name_kv), latest_version->_version, std::get<std::wstring>(path_kv) };
    }

    return E_INVALIDARG;
}

std::variant<typeattr_t, HRESULT> get_typeinfo_attr(ITypeInfo* typeinfo) {
    auto typeattr_deleter = [typeinfo](TYPEATTR* ta) { typeinfo->ReleaseTypeAttr(ta); };

    TYPEATTR* p_typeattr;
    RETURN_IF_FAILED(typeinfo->GetTypeAttr(&p_typeattr));

    return typeattr_t{ p_typeattr, typeattr_deleter };
}

std::variant<GUID, HRESULT> get_type_parent_iid(ITypeInfo* typeinfo, WORD parent_type_cnt) {
    if (parent_type_cnt == 0) {
        // special case for the IUnknown interface
        return __uuidof(IUnknown);
    }
    assert(parent_type_cnt == 1);
    HREFTYPE href = NULL;
    RETURN_IF_FAILED(typeinfo->GetRefTypeOfImplType(0, &href));

    wil::com_ptr_t<ITypeInfo> parent_ti{};
    RETURN_IF_FAILED(typeinfo->GetRefTypeInfo(href, parent_ti.put()));

    auto attr_res{ get_typeinfo_attr(parent_ti.get()) };
    if (std::holds_alternative<HRESULT>(attr_res)) {
        return std::get<HRESULT>(attr_res);
    }
    return std::get<typeattr_t>(attr_res)->guid;
};

std::variant<std::vector<std::wstring>, HRESULT> get_type_methods(ITypeInfo* typeinfo, TYPEATTR* typeattr) {
    auto funcdesc_deleter = [typeinfo](FUNCDESC* fd) { typeinfo->ReleaseFuncDesc(fd); };

    std::vector<std::wstring> methods{};
    for (int j = 0; j < typeattr->cFuncs; j++) {
        FUNCDESC* p_fd;
        RETURN_IF_FAILED(typeinfo->GetFuncDesc(j, &p_fd));

        wil::unique_bstr raw_name{};
        funcdesc_t fd{ p_fd, funcdesc_deleter };
        RETURN_IF_FAILED(typeinfo->GetDocumentation(fd->memid, raw_name.put(), nullptr, nullptr, nullptr));

        std::wstring name{ raw_name.get() };
        if (fd->invkind & INVOKE_PROPERTYPUTREF) {
            name.insert(0, L"putref_");
        } else if (fd->invkind & INVOKE_PROPERTYPUT) {
            name.insert(0, L"put_");
        } else if (fd->invkind & INVOKE_PROPERTYGET) {
            name.insert(0, L"get_");
        }

        methods.push_back(name);
    }

    return methods;
}
}

std::unique_ptr<SQLite::Database> cometa::init_db(const fs::path& path, IDebugControl4* dbgcontrol) {
    dbgeng_logger log{ dbgcontrol };

    if (path.empty()) {
        log.log_info(L"Could not open the metadata database from the dafault location. Switching to a temporary database.");
    } else {
        log.log_info(std::format(L"Creating a new metadata database at '{}'.", path.c_str()));
    }

    auto db{ std::make_unique<SQLite::Database>(to_utf8(path.c_str()), SQLite::OPEN_CREATE | SQLite::OPEN_READWRITE) };

    db->exec(R"(create table schema_version (version integer not null);)");
    db->exec(std::format("insert into schema_version values({})", schema_version));

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
primary key (iid, ordinal)) without rowid)");

    db->exec(R"(create table coclasses (
clsid blob primary key, 
name text not null
) without rowid)");

    db->exec(R"(create table modules (
id integer not null,
name text not null,
timestamp integer not null,
bitness integer not null,
primary key (id),
unique (name, timestamp)))");

    db->exec(R"(create table vtables (
module_id integer not null,
clsid blob not null, 
iid blob not null,
vtable integer not null,
primary key (module_id, clsid, iid),
foreign key (module_id) references modules (id))
without rowid;
create index IX_vtables_iid on vtables (iid);
create index IX_vtables_clsid on vtables (clsid);
)");

    return db;
}

std::unique_ptr<SQLite::Database> cometa::open_db(const fs::path& path, IDebugControl4* dbgcontrol) {
    dbgeng_logger log{ dbgcontrol };
    log.log_info(std::format(L"Opening an existing metadata database from '{}'.", path.c_str()));

    auto db{ std::make_unique<SQLite::Database>(to_utf8(path.c_str()), SQLite::OPEN_READWRITE) };
    if (SQLite::Statement query{ *db, "select version from schema_version" };
        !query.executeStep() || query.getColumn("version").getInt() != schema_version) {
        throw std::invalid_argument{ "incorrect database schema" };
    }
    return db;
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
    assert(_db);
    auto u8name{ to_utf8(typedesc.name) };

    SQLite::Statement stmt{ *_db, "insert or ignore into cotypes values (:iid, :type, :name, :parent_iid, :methods_available)" };
    stmt.bindNoCopy(":iid", &typedesc.iid, sizeof(GUID));
    stmt.bind(":type", static_cast<int>(typedesc.type));
    stmt.bindNoCopy(":name", u8name);
    stmt.bindNoCopy(":parent_iid", &typedesc.parent_iid, sizeof(GUID));
    stmt.bind(":methods_available", static_cast<int>(typedesc.methods_available));

    stmt.exec();
}

void cometa::insert_cotype_methods(const GUID& iid, std::vector<std::wstring>methods) {
    assert(_db);
    for (int ordinal = 0; ordinal < static_cast<int>(methods.size()); ordinal++) {
        auto u8mname{ to_utf8(methods[ordinal]) };

        SQLite::Statement stmt{ *_db, "insert or ignore into cotype_methods values (:iid, :ordinal, :name)" };
        stmt.bindNoCopy(":iid", &iid, sizeof(GUID));
        stmt.bind(":ordinal", ordinal);
        stmt.bindNoCopy(":name", u8mname);

        stmt.exec();
    }
}

void cometa::insert_coclass(const coclass& classdesc) {
    assert(_db);
    auto u8name{ to_utf8(classdesc.name) };

    SQLite::Statement stmt{ *_db, "insert or ignore into coclasses values (:clsid, :name)" };
    stmt.bindNoCopy(":clsid", &classdesc.clsid, sizeof(GUID));
    stmt.bindNoCopy(":name", u8name);

    stmt.exec();
}

std::vector<covtable> cometa::get_module_vtables(const comodule& comodule) {
    assert(_db);
    auto u8_module_name{ to_utf8(comodule.name) };

    SQLite::Statement query{ *_db,
R"(select clsid,iid,vtable from vtables where module_id in (
    select id from modules where name = :module_name and timestamp = :module_timestamp and bitness = :bitness))" };
    query.bindNoCopy(":module_name", u8_module_name);
    query.bind(":module_timestamp", static_cast<const uint32_t>(comodule.timestamp));
    query.bind(":bitness", comodule.is_64bit ? 64 : 32);

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
    auto u8_module_name{ to_utf8(comodule.name) };

    auto get_module_id = [this, &u8_module_name, &comodule]() -> std::optional<int64_t> {
        SQLite::Statement query{ *_db,
            "select id from modules where name = :name and timestamp = :timestamp and bitness = :bitness" };
        query.bindNoCopy(":name", u8_module_name);
        query.bind(":timestamp", static_cast<const uint32_t>(comodule.timestamp));
        query.bind(":bitness", comodule.is_64bit ? 64 : 32);

        if (query.executeStep()) {
            return query.getColumn("id").getInt64();
        } else {
            return std::nullopt;
        }
    };

    auto save_module = [this, &u8_module_name, &comodule]() -> std::optional<int64_t> {
        SQLite::Statement query{ *_db, "insert into modules (name, timestamp, bitness) values (:name, :timestamp, :bitness)" };
        query.bindNoCopy(":name", u8_module_name);
        query.bind(":timestamp", static_cast<const uint32_t>(comodule.timestamp));
        query.bind(":bitness", comodule.is_64bit ? 64 : 32);

        if (query.exec() == 1) {
            // module_id is just an alias for rowid
            return _db->getLastInsertRowid();
        } else {
            return std::nullopt;
        }
    };

    auto save_vtable = [this, &covtable](long long module_id) {
        SQLite::Statement query{ *_db,
            "insert or ignore into vtables values (:module_id, :clsid, :iid, :vtable)" };
        query.bind(":module_id", module_id);
        query.bindNoCopy(":clsid", &covtable.clsid, sizeof(GUID));
        query.bindNoCopy(":iid", &covtable.iid, sizeof(GUID));
        query.bind(":vtable", static_cast<long long>(covtable.address));

        query.exec();
    };

    if (auto module_id{ get_module_id() }; module_id) {
        save_vtable(*module_id);
    } else if ((module_id = save_module())) {
        save_vtable(*module_id);
    } else {
        _logger.log_error(std::format(L"Error when saving module data: '{}'", comodule.name), E_FAIL);
    }
}

HRESULT cometa::index_tlb(std::wstring_view tlb_path) {
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
            auto type{ typeattr->typekind == TKIND_INTERFACE ? cotype_type::Interface : cotype_type::DispInterface };

            auto parent_iid_v{ typelib::get_type_parent_iid(typeinfo.get(), typeattr->cImplTypes) };
            if (std::holds_alternative<HRESULT>(parent_iid_v)) {
                return std::get<HRESULT>(parent_iid_v);
            }
            auto& parent_iid{ std::get<GUID>(parent_iid_v) };

            if (auto methods_v{ typelib::get_type_methods(typeinfo.get(), typeattr.get()) }; std::holds_alternative<HRESULT>(methods_v)) {
                insert_cotype({ typeattr->guid, name.get(), type, parent_iid, false });
            } else {
                SQLite::Transaction transaction{ *_db };

                insert_cotype({ typeattr->guid, name.get(), type, parent_iid, true });
                insert_cotype_methods(typeattr->guid, std::get<std::vector<std::wstring>>(methods_v));

                transaction.commit();
            }
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
                insert_cotype({ iid, L"", cotype_type::Interface, __uuidof(IUnknown), false });
            } else {
                insert_cotype({ iid, std::get<std::wstring>(v), cotype_type::Interface, __uuidof(IUnknown), false });
            }
        }
        return S_OK;
    };

    RETURN_IF_FAILED(index_typelibs());

#if _WIN64
    // index 32-bit nodes first before indexing 64-bit
    RETURN_IF_FAILED(index_coclasses(true));
    RETURN_IF_FAILED(index_interfaces(true));
#endif

    RETURN_IF_FAILED(index_coclasses());
    RETURN_IF_FAILED(index_interfaces());

    return S_OK;
}

std::optional<cotype> cometa::resolve_type(const IID& iid) {
    if (iid == __uuidof(IUnknown)) {
        return cotype{ __uuidof(IUnknown), L"IUnknown", cotype_type::Interface, __uuidof(IUnknown) };
    }

    if (_cotype_cache.contains(iid)) {
        return _cotype_cache.get(iid);
    }

    assert(_db);
    SQLite::Statement query{ *_db, "select * from cotypes where iid = :iid" };
    query.bindNoCopy(":iid", &iid, sizeof(IID));

    auto result{ !query.executeStep() ? std::nullopt :
        std::make_optional(cotype { iid, from_utf8(query.getColumn("name").getText()),
            static_cast<cotype_type>(query.getColumn("type").getInt()),
            *(reinterpret_cast<const GUID*>(query.getColumn("parent_iid").getBlob())),
            static_cast<bool>(query.getColumn("methods_available").getInt())}) };
    _cotype_cache.insert(iid, result);

    return result;
}

std::optional<method_collection> cometa::get_type_methods(const IID& iid) {
    if (iid == __uuidof(IUnknown)) {
        return method_collection{ L"QueryInterface", L"AddRef", L"Release" };
    }

    assert(_db);
    auto query_methods = [this](const IID& iid) {
        SQLite::Statement method_query{ *_db, "select name from cotype_methods where iid = :iid order by ordinal" };
        method_query.bindNoCopy(":iid", &iid, sizeof(IID));
        method_collection methods{};
        while (method_query.executeStep()) {
            methods.push_back(from_utf8(method_query.getColumn(0).getText()));
        }
        return methods;
    };

    if (auto type{ resolve_type(iid) }; type && type->methods_available) {
        if (auto methods{ query_methods(iid) }; methods.size() == 0 || methods.at(0) != L"QueryInterface") {
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

std::vector<std::tuple<std::wstring, CLSID, bool, ULONG64>> cometa::find_vtables_by_iid(const IID& iid) {
    SQLite::Statement query{ *_db,
R"(select m.name,m.bitness,v.clsid,v.vtable from vtables v
    inner join modules m on m.id = v.module_id where v.iid = :iid)" };
    query.bindNoCopy(":iid", &iid, sizeof(IID));

    std::vector<std::tuple<std::wstring, CLSID, bool, ULONG64>> vtables{};
    while (query.executeStep()) {
        vtables.push_back({
            from_utf8(query.getColumn("name").getString()),
            *(reinterpret_cast<const GUID*>(query.getColumn("clsid").getBlob())),
            query.getColumn("bitness").getInt() == 64 ? true : false,
            query.getColumn("vtable").getInt64()
            });
    }
    return vtables;
}

std::vector<std::tuple<std::wstring, IID, bool, ULONG64>> cometa::find_vtables_by_clsid(const CLSID& clsid) {
    SQLite::Statement query{ *_db,
R"(select m.name,m.bitness,v.iid,v.vtable from vtables v
    inner join modules m on m.id = v.module_id where v.clsid = :clsid)" };
    query.bindNoCopy(":clsid", &clsid, sizeof(CLSID));

    std::vector<std::tuple<std::wstring, IID, bool, ULONG64>> vtables{};
    while (query.executeStep()) {
        vtables.push_back({
            from_utf8(query.getColumn("name").getString()),
            *(reinterpret_cast<const GUID*>(query.getColumn("iid").getBlob())),
            query.getColumn("bitness").getInt() == 64 ? true : false,
            query.getColumn("vtable").getInt64()
            });
    }
    return vtables;
}

