
#include <array>
#include <functional>
#include <ranges>
#include <sstream>
#include <string>
#include <format>
#include <compare>

#include "cometa.h"
#include "arch.h"

namespace ranges = std::ranges;

using namespace comon_ext;

namespace {

class version
{
    std::array<int32_t, 4> _version_nums{};

public:
    version(const std::wstring& version): _version{ version } {
        std::wistringstream wss{ version };
        std::wstring token{};

        for (size_t i = 0; wss.good() && i < _version_nums.size(); i++) {
            std::getline(wss, token, L'.');
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

}

std::vector<std::wstring> registry::get_child_key_names(HKEY parent_hkey) {
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

std::variant<std::wstring, HRESULT> registry::read_text_value(HKEY hkey, const wchar_t* subkey, const wchar_t* value_name) {
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

std::variant<typelib_info, HRESULT> typelib::get_tlbinfo(HKEY typelib_hkey) {
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

#if ARCH_X64
        auto path_kv{ registry::read_text_value(latest_version_hkey.get(), L"0\\win64", nullptr) };
#else
        auto path_kv{ registry::read_text_value(latest_version_hkey.get(), L"0\\win32", nullptr) };
#endif

        if (std::holds_alternative<HRESULT>(path_kv)) {
            return std::get<HRESULT>(path_kv);
        }

        return typelib_info{ std::get<std::wstring>(name_kv), latest_version->_version, std::get<std::wstring>(path_kv) };
    }

    return E_INVALIDARG;
}

static const std::unordered_map<int, std::wstring_view> vt_names = {
    { VT_EMPTY, L"void" }, { VT_NULL, L"null" }, { VT_I2, L"short" }, { VT_I4, L"long" },
    { VT_R4, L"single" }, { VT_R8, L"double" }, { VT_CY, L"CURRENCY" }, { VT_DATE, L"DATE" },
    { VT_BSTR, L"BSTR" }, { VT_DISPATCH, L"IDispatch*" }, { VT_ERROR, L"SCODE" }, { VT_BOOL, L"bool" },
    { VT_VARIANT, L"VARIANT" }, { VT_UNKNOWN, L"IUnknown*" }, { VT_DECIMAL, L"DECIMAL" }, { VT_I1, L"char" },
    { VT_UI1, L"unsigned char" }, { VT_UI2, L"unsigned short" }, { VT_UI4, L"unsigned long" }, { VT_I8, L"int64" },
    { VT_UI8, L"uint64" }, { VT_INT, L"int" }, { VT_UINT, L"unsigned int" }, { VT_VOID, L"void" },
    { VT_HRESULT, L"HRESULT" }, { VT_PTR, L"void*" }, { VT_INT_PTR, L"int*" }, { VT_UINT_PTR, L"unsigned int*" },
    { VT_SAFEARRAY, L"SAFEARRAY" }, { VT_CARRAY, L"CARRAY" }, { VT_USERDEFINED, L"USERDEFINED" },
    { VT_LPSTR, L"LPSTR" }, { VT_LPWSTR, L"LPWSTR" }, { VT_FILETIME, L"FILETIME" },
    { VT_BLOB, L"BLOB" }, { VT_STREAM, L"STREAM" }, { VT_STORAGE, L"STORAGE" }, { VT_STREAMED_OBJECT, L"STREAMED_OBJECT" },
    { VT_STORED_OBJECT, L"STORED_OBJECT" }, { VT_BLOB_OBJECT, L"BLOB_OBJECT" }, { VT_CF, L"CF" }, { VT_CLSID, L"GUID" }
};

std::variant<typelib::typeattr_t, HRESULT> typelib::get_typeinfo_attr(ITypeInfo* typeinfo) {
    auto typeattr_deleter = [typeinfo](TYPEATTR* ta) { typeinfo->ReleaseTypeAttr(ta); };

    TYPEATTR* pypeattr;
    RETURN_IF_FAILED(typeinfo->GetTypeAttr(&pypeattr));

    return typeattr_t{ pypeattr, typeattr_deleter };
}

std::variant<GUID, HRESULT> typelib::get_type_parent_iid(ITypeInfo* typeinfo, cotype_kind kind, WORD parentype_cnt) {
    if (parentype_cnt == 0) {
        return kind == cotype_kind::DispInterface ? __uuidof(IDispatch) : __uuidof(IUnknown);
    }
    assert(parentype_cnt == 1);
    HREFTYPE href = NULL;
    RETURN_IF_FAILED(typeinfo->GetRefTypeOfImplType(0, &href));

    wil::com_ptr<ITypeInfo> parenti{};
    RETURN_IF_FAILED(typeinfo->GetRefTypeInfo(href, parenti.put()));

    auto attr_res{ get_typeinfo_attr(parenti.get()) };
    if (std::holds_alternative<HRESULT>(attr_res)) {
        return std::get<HRESULT>(attr_res);
    }
    return std::get<typeattr_t>(attr_res)->guid;
};

std::variant<HRESULT, std::vector<wil::unique_bstr>> typelib::get_comethod_names(ITypeInfo* typeinfo, const FUNCDESC* fd) {
    // max parameters to a function
    constexpr int max_method_args_number{ 64 };

    if (fd->cParams >= max_method_args_number) {
        return E_INVALIDARG;
    }

    std::array<BSTR, max_method_args_number> names{};

    // This is a comment from the source code of oleview (one of VS samples) - it explains
    // the logic behind the following code.

    // Problem:  If a property has the propput or propputref attributes the
    // 'right hand side' (rhs) is *always* the last parameter and MkTypeLib
    // strips the parameter name.  Thus you will always get 1 less name
    // back from ::GetNames than normal.

    // Thus for the example below
    //  [propput] void Color([in] VARIANT rgb, [in] VARIANT rgb2 );
    // without taking this into consderation the output would be
    //  [propput] void Color([in] VARIANT rgb, [in] VARIANT );
    // when it should be
    //  [propput] void Color([in] VARIANT rgb, [in] VARIANT rhs );

    // Another weirdness comes from a bug (which will never be fixed)
    // where optional parameters on property functions were allowed.
    // Because they were allowed by accident people used them, so they
    // are still allowed.

    UINT names_count{};
    RETURN_IF_FAILED(typeinfo->GetNames(fd->memid, names.data(), static_cast<UINT>(names.size()), &names_count));

    // fix for 'rhs' problem
    if ((SHORT)names_count <= fd->cParams) {
        names[names_count] = ::SysAllocString(L"rhs");
        names_count++;
    }

    std::vector<wil::unique_bstr> result{};
    result.reserve(names_count);
    std::transform(std::begin(names), std::begin(names) + names_count, std::back_inserter(result),
        [](BSTR bstr) { return wil::unique_bstr{ bstr }; });

    return result;
}

std::wstring typelib::vt_to_string(VARTYPE vt)
{
    vt &= ~0xF000;
    if (auto it = vt_names.find(vt); it != std::end(vt_names)) {
        return std::wstring { it->second };
    } else {
        return std::wstring { bad_type_name };
    }
}

std::variant<HRESULT, std::wstring> typelib::get_type_desc(ITypeInfo* typeinfo, const TYPEDESC* desc) {
    std::variant<HRESULT, std::wstring> result;
    if (desc->vt == VT_PTR || (desc->vt & 0x0FFF) == VT_SAFEARRAY) {
        if (auto v{ get_type_desc(typeinfo, desc->lptdesc) }; std::holds_alternative<HRESULT>(v)) {
            result = std::get<HRESULT>(v);
        } else if (desc->vt == VT_PTR) {
            result = std::get<std::wstring>(v) + L"*";
        } else if ((desc->vt & 0x0FFF) == VT_SAFEARRAY) {
            result = L"SAFEARRAY(" + std::get<std::wstring>(v) + L"";
        } else {
            assert(false);
        }
    } else if ((desc->vt & 0x0FFF) == VT_CARRAY) {
        if (auto v{ get_type_desc(typeinfo, &desc->lpadesc->tdescElem) }; std::holds_alternative<HRESULT>(v)) {
            result = std::get<HRESULT>(v);
        } else {
            std::wstring type_desc = std::get<std::wstring>(v);
            for (USHORT n = 0; n < desc->lpadesc->cDims; n++)
            {
                type_desc += std::format(L"[{}]", desc->lpadesc->rgbounds[n].cElements);
            }
            result = type_desc;
        }
    } else if (desc->vt == VT_USERDEFINED) {
        wil::com_ptr_t<ITypeInfo> ref_typeinfo{};
        RETURN_IF_FAILED(typeinfo->GetRefTypeInfo(desc->hreftype, ref_typeinfo.put()));

        wil::unique_bstr name{};
        RETURN_IF_FAILED(ref_typeinfo->GetDocumentation(MEMBERID_NIL, name.put(), nullptr, nullptr, nullptr));
        result = std::wstring{ name.get() };
    } else {
        result = vt_to_string(desc->vt);
    }

    return result;
}
