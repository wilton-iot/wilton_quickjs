/*
 * Copyright 2018, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   quickjs_config.hpp
 * Author: alex
 *
 * Created on October 4, 2020, 9:59 AM
 */

#ifndef WILTON_QUICKJS_CONFIG_HPP
#define WILTON_QUICKJS_CONFIG_HPP

#include <cstdint>

#include "staticlib/json.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

namespace wilton {
namespace quickjs {

class quickjs_config {
public:
    uint32_t memory_limit_bytes = 0;
    uint32_t gc_threshold_bytes = 0;
    uint32_t max_stack_size_bytes = 0;

    quickjs_config(const sl::json::value& env_json) {
        for (const sl::json::field& fi : env_json.as_object()) {
            auto& name = fi.name();
            if (sl::utils::starts_with(name, "QUICKJS_")) {
                if ("QUICKJS_MemoryLimit" == name) {
                    this->memory_limit_bytes = str_as_u32(fi, name);
                } else if ("QUICKJS_GCThreshold" == name) {
                    this->gc_threshold_bytes = str_as_u32(fi, name);
                } else if ("QUICKJS_MaxStackSize" == name) {
                    this->max_stack_size_bytes = str_as_u32(fi, name);
                } else {
                    throw support::exception(TRACEMSG("Unknown 'quickjs_config' field: [" + name + "]"));
                }
            }
        }
    }

    quickjs_config(const quickjs_config& other):
    memory_limit_bytes(other.memory_limit_bytes),
    gc_threshold_bytes(other.gc_threshold_bytes),
    max_stack_size_bytes(other.max_stack_size_bytes) { }

    quickjs_config& operator=(const quickjs_config&  other) {
        this->memory_limit_bytes = other.memory_limit_bytes;
        this->gc_threshold_bytes = other.gc_threshold_bytes;
        this->max_stack_size_bytes = other.max_stack_size_bytes;
        return *this;
    }

    sl::json::value to_json() const {
        return {
            { "memory_limit_bytes", memory_limit_bytes },
            { "gc_threshold_bytes", gc_threshold_bytes },
            { "max_stack_size_bytes", max_stack_size_bytes}
        };
    }

private:
    static uint32_t str_as_u32(const sl::json::field& fi, const std::string& name) {
        auto str = fi.as_string_nonempty_or_throw(name);
        try {
            return sl::utils::parse_uint32(str);
        } catch (std::exception& e) {
            throw support::exception(TRACEMSG(e.what() + 
                    "\nError parsing parameter: [" + name + "], value: [" + str + "]"));
        }
    }

};

} // namespace
}

#endif /* WILTON_QUICKJS_CONFIG_HPP */

