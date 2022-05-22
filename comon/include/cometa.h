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

#pragma once

#include <format>
#include <optional>
#include <deque>
#include <filesystem>

#include <SQLiteCpp/Database.h>

#include "comon.h"
#include "lfu_cache.h"

namespace fs = std::filesystem;

namespace comon_ext
{

enum class cotype_type
{
    Interface,
    DispInterface
};

using method_collection = std::deque<std::wstring>;

struct covtable
{
    const CLSID clsid;
    const IID iid;
    const ULONG64 address;
};

struct comodule
{
    const std::wstring_view name;
    const ULONG timestamp;
    const bool is_64bit;
};

struct cotype
{
    GUID iid{};
    std::wstring name;
    cotype_type type{};
    GUID parent_iid{};
    bool methods_available{};
};

struct coclass
{
    GUID clsid{};
    std::wstring name;
};

struct typelib_info
{
    std::wstring name;
    std::wstring version;
    std::wstring tlb_path;
};

class cometa
{
    const std::unique_ptr<SQLite::Database> _db;
    const dbgeng_logger _logger;

    lfu_cache<IID, const std::optional<const cotype>> _cotype_cache{ 100 };
    lfu_cache<CLSID, const std::optional<const coclass>> _coclass_cache{ 50 };

    HRESULT index_tlb(std::wstring_view tlb_path);

    void insert_cotype(const cotype& typedesc);
    void insert_cotype_methods(const GUID& iid, std::vector<std::wstring>methods);
    void insert_coclass(const coclass& classdesc);

    static std::unique_ptr<SQLite::Database> init_db(const fs::path& path, IDebugControl4* dbgcontrol);
    static std::unique_ptr<SQLite::Database> open_db(const fs::path& path, IDebugControl4* dbgcontrol);

public:

    static bool is_valid_db(const fs::path& path);

    explicit cometa(IDebugControl4* dbgcontrol, const fs::path& db_path) : _logger{ dbgcontrol },
        _db{ fs::exists(db_path) ? open_db(db_path, dbgcontrol) : init_db(db_path, dbgcontrol) } { }

    HRESULT index();

    HRESULT index(std::wstring_view tlb_path) {
        if (!_db) {
            _logger.log_error(L"no open database", E_FAIL);
            return E_FAIL;
        }

        if (auto hr{ index_tlb(tlb_path) }; SUCCEEDED(hr)) {
            _logger.log_info_dml(std::format(L"'{}' : <col fg=\"srccmnt\" bg=\"wbg\">PARSED</col>", tlb_path));
            return S_OK;
        } else {
            _logger.log_error_dml(std::format(L"'{}'", tlb_path), hr);
            return hr;
        }
    }

    HRESULT save(std::wstring_view dbpath);

    std::optional<std::wstring> resolve_type_name(const IID& iid) {
        if (auto t{ resolve_type(iid) }; t) {
            return t->name;
        }
        return std::nullopt;
    }

    std::optional<cotype> resolve_type(const IID& iid);

    std::optional<coclass> resolve_class(const CLSID& clsid);

    std::vector<std::tuple<std::wstring, CLSID, bool, ULONG64>> find_vtables_by_iid(const IID& iid);

    std::vector<std::tuple<std::wstring, IID, bool, ULONG64>> find_vtables_by_clsid(const CLSID& clsid);

    std::optional<method_collection> get_type_methods(const IID& iid);

    std::optional<std::wstring> resolve_class_name(const CLSID& clsid) {
        if (auto c{ resolve_class(clsid) }; c) {
            return c->name;
        }
        return std::nullopt;
    }

    void save_module_vtable(const comodule& comodule, const covtable& covtable);

    std::vector<covtable> get_module_vtables(const comodule& comodule);
};

}
