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

#include <tuple>
#include <utility>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <cassert>
#include <stdexcept>
#include <ranges>
#include <algorithm>

#include <Windows.h>

namespace views = std::ranges::views;

namespace comon_ext
{
template<typename K, typename O>
class lfu_cache
{
    const size_t _capacity;
    std::unordered_map<K, std::pair<O, int32_t>> _cache{};
    std::map<int, std::unordered_set<K>> _cache_freqs{};

    void discard_from_frequency(int32_t freq, const K& key);

    void add_to_frequency(int32_t freq, const K& key);

    K extract_least_frequent();

public:

    lfu_cache(size_t capacity): _capacity{ capacity } {
        if (capacity <= 0) {
            throw std::invalid_argument{ "capacity" };
        }
    }

    bool contains(const K& key) const;

    const O& get(const K& key);

    void insert(const K& key, const O& data);

    void clear() {
        _cache_freqs.clear();
        _cache.clear();
    }
};

template<typename K, typename O>
void lfu_cache<K, O>::discard_from_frequency(int32_t freq, const K& key) {
    assert(_cache_freqs.contains(freq));
    auto& freqs{ _cache_freqs[freq] };
    assert(freqs.contains(key));
    freqs.erase(key);

    if (freqs.empty()) {
        _cache_freqs.erase(freq);
    }
}

template<typename K, typename O>
void lfu_cache<K, O>::add_to_frequency(int32_t freq, const K& key) {
    if (auto freqs_iter{ _cache_freqs.find(freq) }; freqs_iter == std::end(_cache_freqs)) {
        _cache_freqs.emplace(std::make_pair(freq, std::unordered_set<K>{key}));
    } else {
        freqs_iter->second.insert(key);
    }
}

template<typename K, typename O>
K lfu_cache<K, O>::extract_least_frequent() {
    assert(!_cache_freqs.empty());
    auto freqs_iter{ std::begin(_cache_freqs) };

    auto& freqs{ freqs_iter->second };
    assert(!freqs.empty());
    auto key_iter{ std::begin(freqs) };
    auto res{ *key_iter };
    freqs.erase(key_iter);

    if (freqs.empty()) {
        _cache_freqs.erase(freqs_iter);
    }
    return res;
}

template<typename K, typename O>
bool lfu_cache<K, O>::contains(const K& key) const {
    return _cache.contains(key);
}

template<typename K, typename O>
const O& lfu_cache<K, O>::get(const K& key) {
    assert(_cache.contains(key));
    auto& elem{ _cache[key] };

    auto freq{ elem.second };
    auto new_freq{ freq + 1 };

    elem.second = new_freq;
    discard_from_frequency(freq, key);
    add_to_frequency(new_freq, key);

    return elem.first;
}

template<typename K, typename O>
void lfu_cache<K, O>::insert(const K& key, const O& data) {
    if (!_cache.contains(key)) {
        if (_cache.size() >= _capacity) {
            // we need to free some space
            assert(_cache.size() == _capacity);
            _cache.erase(extract_least_frequent());
        }
        _cache.emplace(std::make_pair(key, std::make_pair(data, 1)));
        add_to_frequency(1, key);
    }
}
}
