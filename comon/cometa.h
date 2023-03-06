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
#include <unordered_set>
#include <filesystem>
#include <variant>
#include <functional>
#include <array>

#include <SQLiteCpp/Database.h>

#include "comon.h"
#include "lfu_cache.h"

namespace fs = std::filesystem;

namespace comon_ext
{

enum class cotype_kind
{
    Interface,
    DispInterface
};

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
    cotype_kind type{};
    GUID parent_iid{};
    bool methods_available{};
};

struct coclass
{
    GUID clsid{};
    std::wstring name;
};

struct comethod
{
    GUID iid{};
    std::wstring name;
    int ordinal;
    CALLCONV callconv;
    std::optional<DISPID> dispid{};
    std::wstring return_type;
};

struct comethod_arg
{
    std::wstring name;
    std::wstring type;
    USHORT flags; // IDLFLAG_NONE, IDLFLAG_FIN, IDLFLAG_FOUT, IDLFLAG_FRETVAL, etc.
};

struct typelib_info
{
    std::wstring name;
    std::wstring version;
    std::wstring tlb_path;
};

using method_collection = std::deque<comethod>;
using method_arg_collection = std::vector<comethod_arg>;

class cometa
{
    const std::unique_ptr<SQLite::Database> _db;
    const dbgeng_logger _logger;
    const bool _is_wow64;

    std::unordered_set<IID> _known_iids{};

    lfu_cache<IID, const std::optional<const cotype>> _cotype_cache{ 100 };
    lfu_cache<CLSID, const std::optional<const coclass>> _coclass_cache{ 50 };

    HRESULT index_tlb(std::wstring_view tlb_path);

    void fill_known_iids();

    void insert_cotype(const cotype& typedesc);
    void insert_cotype_method(const comethod& method);
    void insert_cotype_method_arg(const GUID& iid, int method_ordinal, const comethod_arg& arg, int arg_ordinal);
    void insert_coclass(const coclass& classdesc);

    static std::unique_ptr<SQLite::Database> init_db(const fs::path& path, IDebugControl4* dbgcontrol);
    static std::unique_ptr<SQLite::Database> open_db(const fs::path& path, IDebugControl4* dbgcontrol);

public:

    static bool is_valid_db(const fs::path& path);

    explicit cometa(IDebugControl4* dbgcontrol, bool is_wow64, const fs::path& db_path, bool create_new);

    void invalidate_cache() {
        _cotype_cache.clear();
        _coclass_cache.clear();
    }

    HRESULT index();

    HRESULT index(std::wstring_view tlb_path) {
        if (!_db) {
            _logger.log_error(L"no open database", E_FAIL);
            return E_FAIL;
        }

        if (auto hr{ index_tlb(tlb_path) }; SUCCEEDED(hr)) {
            _logger.log_info_dml(std::format(L"'{}' : <col fg=\"srccmnt\">PARSED</col>", tlb_path));

            invalidate_cache();

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

    std::vector<std::tuple<std::wstring, CLSID, ULONG64>> find_vtables_by_iid(const IID& iid);

    std::vector<std::tuple<std::wstring, IID, ULONG64>> find_vtables_by_clsid(const CLSID& clsid);

    std::optional<method_collection> get_type_methods(const IID& iid);
    std::optional<method_arg_collection> get_type_method_args(const comethod& method);

    std::optional<std::wstring> resolve_class_name(const CLSID& clsid) {
        if (auto c{ resolve_class(clsid) }; c) {
            return c->name;
        }
        return std::nullopt;
    }

    void save_module_vtable(const comodule& comodule, const covtable& covtable);

    std::vector<covtable> get_module_vtables(const comodule& comodule);
};

namespace registry
{
std::vector<std::wstring> get_child_key_names(HKEY parent_hkey);

std::variant<std::wstring, HRESULT> read_text_value(HKEY hkey, const wchar_t* subkey, const wchar_t* value_name);
}

namespace typelib
{

using typeattr_t = std::unique_ptr<TYPEATTR, std::function<void(TYPEATTR*)>>;
using funcdesc_t = std::unique_ptr<FUNCDESC, std::function<void(FUNCDESC*)>>;

constexpr std::wstring_view bad_type_name{ L"BAD_TYPE" };

std::variant<typelib_info, HRESULT> get_tlbinfo(HKEY typelib_hkey);

std::variant<typeattr_t, HRESULT> get_typeinfo_attr(ITypeInfo* typeinfo);

std::variant<GUID, HRESULT> get_type_parent_iid(ITypeInfo* typeinfo, cotype_kind kind, WORD parent_type_cnt);

std::wstring vt_to_string(VARTYPE vt);

std::variant<HRESULT, std::wstring> get_type_desc(ITypeInfo* typeinfo, const TYPEDESC* desc);

std::variant<HRESULT, std::vector<wil::unique_bstr>> get_comethod_names(ITypeInfo* typeinfo, const FUNCDESC* fd);
}

}
