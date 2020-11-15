/*
 * Copyright 2020, alex at staticlibs.net
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
 * File:   quickjs_engine.cpp
 * Author: alex
 * 
 * Created on July 1, 2020, 9:17 PM
 */

#include "quickjs_engine.hpp"

#include <cstring>
#include <atomic>
#include <memory>

#include "quickjs.h"

#include "staticlib/io.hpp"
#include "staticlib/json.hpp"
#include "staticlib/pimpl/forward_macros.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

#include "wilton/wiltoncall.h"

#include "wilton/support/exception.hpp"
#include "wilton/support/logging.hpp"

#include "quickjs_config.hpp"

namespace wilton {
namespace quickjs {

namespace { // anonymous

const std::string st_prefix = "    at ";

// called from initialize
const sl::json::value& wilton_config_json() {
    static sl::json::value json = [] {
        char* conf = nullptr;
        int conf_len = 0;
        auto err = wilton_config(std::addressof(conf), std::addressof(conf_len));
        if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
        auto deferred = sl::support::defer([conf] () STATICLIB_NOEXCEPT {
            wilton_free(conf);
        });
        return sl::json::load({const_cast<const char*>(conf), conf_len});
    }();
    return json;
}

quickjs_config get_config() {
    const auto& vars = wilton_config_json()["environmentVariables"];
    return quickjs_config(vars);
}

void apply_config(JSRuntime* rt, quickjs_config& cfg) {
    if (cfg.memory_limit_bytes > 0) {
        JS_SetMemoryLimit(rt, static_cast<size_t>(cfg.memory_limit_bytes)); 
    }
    if (cfg.gc_threshold_bytes > 0) {
        JS_SetGCThreshold(rt, static_cast<size_t>(cfg.gc_threshold_bytes)); 
    }
    if (cfg.max_stack_size_bytes > 0) {
        JS_SetMaxStackSize(rt, static_cast<size_t>(cfg.max_stack_size_bytes)); 
    }
}

void register_c_func(JSContext* ctx, const std::string& name, JSCFunction fun, int args_count) {
    JSValue jfun = JS_NewCFunction(ctx, fun, name.c_str(), args_count);
    if(!JS_IsFunction(ctx, jfun)) throw support::exception(TRACEMSG(
            "'JS_NewCFunction' error"));
    JSValue global = JS_GetGlobalObject(ctx);
    auto deferred = sl::support::defer([ctx, global]() STATICLIB_NOEXCEPT {
        JS_FreeValue(ctx, global);
    });
    auto res_code = JS_SetPropertyStr(ctx, global, name.c_str(), jfun);
    if(!res_code) throw support::exception(TRACEMSG(
            "'JS_SetPropertyStr' error"));
}

std::string jsval_to_string(JSContext* ctx, JSValue val) STATICLIB_NOEXCEPT {
    size_t len = 0;
    auto cst = JS_ToCStringLen(ctx, std::addressof(len), val);
    if (nullptr == cst || 0 == len) {
        return "";
    }
    auto deferred = sl::support::defer([ctx, cst]() STATICLIB_NOEXCEPT {
        JS_FreeCString(ctx, cst);
    });
    return std::string(cst, len);
}

std::string format_stack_trace(JSContext* ctx) {
    JSValue exc_val = JS_GetException(ctx);
    auto exc_deferred = sl::support::defer([ctx, exc_val]() STATICLIB_NOEXCEPT {
        JS_FreeValue(ctx, exc_val);
    });
    if(JS_IsObject(exc_val)) {
        JSValue msg_val = JS_GetPropertyStr(ctx, exc_val, "message");
        auto msg_deferred = sl::support::defer([ctx, msg_val]() STATICLIB_NOEXCEPT {
            JS_FreeValue(ctx, msg_val);
        });
        if (JS_IsString(msg_val)) {
            auto msg = jsval_to_string(ctx, msg_val);
            JSValue stack_val = JS_GetPropertyStr(ctx, exc_val, "stack");
            auto stack_deferred = sl::support::defer([ctx, stack_val]() STATICLIB_NOEXCEPT {
                JS_FreeValue(ctx, stack_val);
            });
            if (JS_IsString(stack_val)) {
                auto stack = jsval_to_string(ctx, stack_val);
                auto full = msg + "\n" + stack;
                auto vec = sl::utils::split(full, '\n');
                auto res = std::string();
                for (size_t i = 0; i < vec.size(); i++) {
                    auto& line = vec.at(i);
                    if (line.length() > 1 && !(std::string::npos != line.find("wilton-requirejs/require.js:")) &&
                            !(std::string::npos != line.find("wilton-require.js:")) &&
                            !(std::string::npos != line.find("apply (native)"))) {
                        if (i > 1 && !sl::utils::starts_with(line, st_prefix) &&
                                (std::string::npos != line.find("(native)") ||
                                std::string::npos != line.find(".js:"))) {
                            res += st_prefix;
                        }
                        res += line;
                        res.push_back('\n');
                    }
                }
                if (res.length() > 0 && '\n' == res.back()) {
                    res.pop_back();
                }
                return res;
            }
        }
    }
    return jsval_to_string(ctx, exc_val);
}

std::string eval_js(JSContext* ctx, const char* code, size_t code_len, const std::string& path) {
    JSValue res = JS_Eval(ctx, code, code_len, path.c_str(), 0);
    if (JS_IsException(res)) {
        throw support::exception(TRACEMSG(format_stack_trace(ctx)));
    }
    if (JS_IsString(res)) {
        return jsval_to_string(ctx, res);
    }
    return "";
}

JSValue throw_js_error(JSContext* ctx, const std::string& msg) {
    JSValue jmsg = JS_NewStringLen(ctx, msg.c_str(), msg.length());
    JSValue err = JS_NewError(ctx);
    JS_SetPropertyStr(ctx, err, "message", jmsg);
    return JS_Throw(ctx, err);
}

JSValue print_func(JSContext* ctx, JSValueConst /* this_val */,
        int args_count, JSValueConst* arguments) STATICLIB_NOEXCEPT {
    if (args_count > 0) {
        auto val = jsval_to_string(ctx, arguments[0]);
        puts(val.c_str());
    } else {
        puts("");
    }
    return JS_UNDEFINED;
}

JSValue load_func(JSContext* ctx, JSValueConst /* this_val */,
        int args_count, JSValueConst* arguments) STATICLIB_NOEXCEPT {
    auto path = std::string();
    try {
        if (args_count < 1 || !JS_IsString(arguments[0])) {
            throw support::exception(TRACEMSG("Invalid arguments specified"));
        }
        path = jsval_to_string(ctx, arguments[0]);
        // load code
        char* code = nullptr;
        int code_len = 0;
        auto err_load = wilton_load_resource(path.c_str(), static_cast<int>(path.length()),
                std::addressof(code), std::addressof(code_len));
        if (nullptr != err_load) {
            support::throw_wilton_error(err_load, TRACEMSG(err_load));
        }
        auto deferred = sl::support::defer([code] () STATICLIB_NOEXCEPT {
            wilton_free(code);
        });
        auto path_short = support::script_engine_map_detail::shorten_script_path(path);
        wilton::support::log_debug("wilton.engine.quickjs.eval",
                "Evaluating source file, path: [" + path + "] ...");
        eval_js(ctx, code, static_cast<size_t>(code_len), path_short);
        wilton::support::log_debug("wilton.engine.quickjs.eval", "Eval complete");
    } catch (const std::exception& e) {
        auto msg = TRACEMSG(e.what() + "\nError loading script, path: [" + path + "]");
        return throw_js_error(ctx, msg);
    } catch (...) {
        auto msg = TRACEMSG("Error(...) loading script, path: [" + path + "]");
        return throw_js_error(ctx, msg);
    }
    return JS_UNDEFINED;
}

JSValue wiltoncall_func(JSContext* ctx, JSValueConst /* this_val */,
        int args_count, JSValueConst* arguments) STATICLIB_NOEXCEPT {
    if (args_count < 2 || !JS_IsString(arguments[0]) || !JS_IsString(arguments[1])) {
        auto msg = TRACEMSG("Invalid arguments specified");
        return throw_js_error(ctx, msg);
    }
    auto name = jsval_to_string(ctx, arguments[0]);
    auto input = jsval_to_string(ctx, arguments[1]);
    char* out = nullptr;
    int out_len = 0;
    wilton::support::log_debug("wilton.wiltoncall." + name,
            "Performing a call, input length: [" + sl::support::to_string(input.length()) + "] ...");
    auto err = wiltoncall(name.c_str(), static_cast<int> (name.length()),
            input.c_str(), static_cast<int> (input.length()),
            std::addressof(out), std::addressof(out_len));
    wilton::support::log_debug("wilton.wiltoncall." + name,
            "Call complete, result: [" + (nullptr != err ? std::string(err) : "") + "]");
    if (nullptr == err) {
        if (nullptr != out) {
            auto out_deferred = sl::support::defer([out]() STATICLIB_NOEXCEPT {
                wilton_free(out);
            });
            return JS_NewStringLen(ctx, out, static_cast<size_t>(out_len));
        } else {
            return JS_NULL;
        }
    } else {
        auto err_deferred = sl::support::defer([err]() STATICLIB_NOEXCEPT {
            wilton_free(err);
        });
        auto msg = TRACEMSG(err + "\n'wiltoncall' error for name: [" + name + "]");
        return throw_js_error(ctx, msg);
    }
}

std::string module_id(const std::string& path, const std::string& default_val) {
    auto mod_id = std::string(default_val);
    for (auto& fi : wilton_config_json()["requireJs"]["paths"].as_object()) {
        if (sl::utils::starts_with(path, fi.val().as_string())) {
            mod_id = fi.name() + "/" + path.substr(fi.val().as_string().length());
            break;
        }
    }
    return mod_id;
} 

std::string dirname(const std::string& path) {
    auto dir = sl::utils::strip_filename(path);
    if (!dir.empty()) { // remote last slash
        dir.resize(dir.length() - 1);
    }
    return dir;
}

JSValue create_arg_val(JSContext* ctx, const sl::json::value& ar) {
    switch(ar.json_type()) {
    case sl::json::type::nullt:
        return JS_NULL;
    case sl::json::type::string:
        return JS_NewString(ctx, ar.as_string().c_str());
    case sl::json::type::integer:
        return JS_NewInt64(ctx, ar.as_int64());
    case sl::json::type::boolean:
        return JS_NewBool(ctx, ar.as_bool());
    default:
        throw support::exception(TRACEMSG("Invalid callback script argument specified," +
                " type: [" + sl::json::stringify_json_type(ar.json_type()) + "],"
                " only string, integer or boolean arguments can be passed to ES module callbacks"));
    }
}

JSModuleDef* module_loader(JSContext *ctx, const char* module_name, void* /* opaque */) {
    auto path = std::string(module_name);
    if (!(sl::utils::starts_with(path, "file://") || sl::utils::starts_with(path, "zip://"))) {
        auto prefix = wilton_config_json()["requireJs"]["baseUrl"].as_string_nonempty_or_throw("baseUrl");
        path = prefix + "/" + path;
        if (!sl::utils::ends_with(path, ".js")) {
            path.append("/esm.js");
        }
    }
    try {
        // load code
        char* code = nullptr;
        int code_len = 0;
        auto err_load = wilton_load_resource(path.c_str(), static_cast<int>(path.length()),
                std::addressof(code), std::addressof(code_len));
        if (nullptr != err_load) {
            support::throw_wilton_error(err_load, TRACEMSG(err_load));
        }
        auto deferred_code = sl::support::defer([code] () STATICLIB_NOEXCEPT {
            wilton_free(code);
        });

        // compile module code
        wilton::support::log_debug("wilton.engine.quickjs.module_loader",
                "Loading ES module file, path: [" + path + "] ...");
        JSValue func = JS_Eval(ctx, code, code_len, path.c_str(),
                JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
        wilton::support::log_debug("wilton.engine.quickjs.module_loader",
                "Load complete, result: [" + (JS_IsException(func) ? std::string("error") : "") + "]");
        if (JS_IsException(func)) {
            return nullptr;
        }
        auto deferred_func = sl::support::defer([ctx, func] () STATICLIB_NOEXCEPT {
            JS_FreeValue(ctx, func);
        });
        JSModuleDef* mod = static_cast<JSModuleDef*>(JS_VALUE_GET_PTR(func));

        // setup import.meta
        JSValue meta = JS_GetImportMeta(ctx, mod);
        if (JS_IsException(meta)){
            return nullptr; 
        }
        auto deferred_meta = sl::support::defer([ctx, meta] () STATICLIB_NOEXCEPT {
            JS_FreeValue(ctx, meta);
        });
        auto mod_id = module_id(path, module_name);
        auto mod_dir = dirname(path);
        JS_DefinePropertyValueStr(ctx, meta, "id", JS_NewStringLen(ctx, mod_id.c_str(), mod_id.length()), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, meta, "url", JS_NewStringLen(ctx, path.c_str(), path.length()), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, meta, "dir", JS_NewStringLen(ctx, mod_dir.c_str(), mod_dir.length()), JS_PROP_C_W_E);
        JS_DefinePropertyValueStr(ctx, meta, "args", JS_NewArray(ctx), JS_PROP_C_W_E);

        return mod;
    } catch (const std::exception& e) {
        auto msg = TRACEMSG(e.what() + "\nError loading module, path: [" + path + "]");
        throw_js_error(ctx, msg);
        return nullptr;
    } catch (...) {
        auto msg = TRACEMSG("Error(...) loading module, path: [" + path + "]");
        throw_js_error(ctx, msg);
        return nullptr;
    }
}

JSValue run_requirejs_module(JSContext* ctx, sl::io::span<const char> callback_script_json) {
    // extract wilton_run
    JSValue global = JS_GetGlobalObject(ctx);
    auto global_deferred = sl::support::defer([ctx, global]() STATICLIB_NOEXCEPT {
        JS_FreeValue(ctx, global);
    });
    if (!JS_IsObject(global)) throw support::exception(TRACEMSG(
            "Error accessing 'WILTON_run' function: not an object"));
    JSValue wilton_run = JS_GetPropertyStr(ctx, global, "WILTON_run");
    auto wilton_run_deferred = sl::support::defer([ctx, wilton_run]() STATICLIB_NOEXCEPT {
        JS_FreeValue(ctx, wilton_run);
    });
    if (!JS_IsFunction(ctx, wilton_run)) throw support::exception(TRACEMSG(
            "Error accessing 'WILTON_run' function: not a function"));
    // call
    JSValueConst jcb = JS_NewStringLen(ctx, callback_script_json.data(), callback_script_json.size());
    auto cb_deferred = sl::support::defer([ctx, jcb]() STATICLIB_NOEXCEPT {
        JS_FreeValue(ctx, jcb);
    });
    return JS_Call(ctx, wilton_run, global, 1, std::addressof(jcb));
}

JSValueConst run_es_module(JSContext* ctx, const sl::json::value& cb_json_obj) {
    // load code
    auto path = cb_json_obj["esmodule"].as_string_nonempty_or_throw("esmodule");
    char* code = nullptr;
    int code_len = 0;
    auto err_load = wilton_load_resource(path.c_str(), static_cast<int>(path.length()),
            std::addressof(code), std::addressof(code_len));
    if (nullptr != err_load) {
        support::throw_wilton_error(err_load, TRACEMSG(err_load));
    }
    auto deferred = sl::support::defer([code] () STATICLIB_NOEXCEPT {
        wilton_free(code);
    });

    // compile module
    JSValue func = JS_Eval(ctx, code, code_len, path.c_str(), JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    if (JS_IsException(func)) {
        throw support::exception(TRACEMSG(format_stack_trace(ctx)));
    }
    // don't need to free it for some reason, crash otherwise
    //auto deferred_func = sl::support::defer([ctx, func] () STATICLIB_NOEXCEPT {
    //    JS_FreeValue(ctx, func);
    //});
    JSModuleDef* mod = static_cast<JSModuleDef*>(JS_VALUE_GET_PTR(func));

    // setup import.meta
    JSValue meta = JS_GetImportMeta(ctx, mod);
    if (JS_IsException(meta)) {
        throw support::exception(TRACEMSG("'JS_GetImportMeta' error"));
    }
    auto deferred_meta = sl::support::defer([ctx, meta] () STATICLIB_NOEXCEPT {
        JS_FreeValue(ctx, meta);
    });
    auto mod_id = module_id(path, path);
    auto mod_dir = dirname(path);
    JS_DefinePropertyValueStr(ctx, meta, "id", JS_NewStringLen(ctx, mod_id.c_str(), mod_id.length()), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, meta, "url", JS_NewStringLen(ctx, path.c_str(), path.length()), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, meta, "dir", JS_NewStringLen(ctx, mod_dir.c_str(), mod_dir.length()), JS_PROP_C_W_E);
    JSValue args = JS_NewArray(ctx);
    if (JS_IsException(args)) {
        throw support::exception(TRACEMSG("'JS_NewArray' error"));
    }
    auto& args_json = cb_json_obj["args"].as_array();
    for (uint32_t i = 0; i < args_json.size(); i++) {
        JSValue el = create_arg_val(ctx, args_json[i]);
        auto ret = JS_DefinePropertyValueUint32(ctx, args, i, el, JS_PROP_C_W_E);
        if (ret < 0) {
            JS_FreeValue(ctx, args);
            throw support::exception(TRACEMSG("'JS_DefinePropertyValueUint32' error"));
        }
    }
    JS_DefinePropertyValueStr(ctx, meta, "args", args, JS_PROP_C_W_E);

    // run module
    return JS_EvalFunction(ctx, func);
}

} // namespace

class quickjs_engine::impl : public sl::pimpl::object::impl {
    std::unique_ptr<JSRuntime, std::function<void(JSRuntime*)>> jsruntime;
    std::unique_ptr<JSContext, std::function<void(JSContext*)>> jsctx;

public:
    impl(sl::io::span<const char> init_code) :
    jsruntime(JS_NewRuntime(), JS_FreeRuntime),
    jsctx(JS_NewContext(this->jsruntime.get()), JS_FreeContext) {
        auto cfg = get_config();
        wilton::support::log_info("wilton.engine.quickjs.init", std::string() + "Initializing engine instance," +
                " config: [" + cfg.to_json().dumps() + "]");
        auto rt = this->jsruntime.get();
        if (nullptr == rt) {
            throw support::exception(TRACEMSG("'JS_NewRuntime' error"));
        }
        apply_config(rt, cfg);
        auto ctx = this->jsctx.get();
        if (nullptr == ctx) {
            throw support::exception(TRACEMSG("'JS_NewContext' error"));
        }
        register_c_func(ctx, "print", print_func, 1);
        register_c_func(ctx, "WILTON_load", load_func, 1);
        register_c_func(ctx, "WILTON_wiltoncall", wiltoncall_func, 2);
        JS_SetModuleLoaderFunc(rt, nullptr, module_loader, nullptr);
        eval_js(ctx, init_code.data(), init_code.size(), "wilton-require.js");
        wilton::support::log_info("wilton.engine.quickjs.init", "Engine initialization complete");
    }

    support::buffer run_callback_script(quickjs_engine&, sl::io::span<const char> callback_script_json) {
        wilton::support::log_debug("wilton.engine.quickjs.run",
                "Running callback script: [" + std::string(callback_script_json.data(), callback_script_json.size()) + "] ...");
        auto ctx = jsctx.get();
        auto cb_json_obj = sl::json::load(callback_script_json);
        JSValue res = JS_UNDEFINED;
        if (!cb_json_obj["esmodule"].as_string().empty()) {
            res = run_es_module(ctx, cb_json_obj);
        } else {
            res = run_requirejs_module(ctx, callback_script_json);
        }
        auto res_deferred = sl::support::defer([ctx, res]() STATICLIB_NOEXCEPT {
            JS_FreeValue(ctx, res);
        });
        wilton::support::log_debug("wilton.engine.jsc.run",
                "Callback run complete, result: [" + sl::support::to_string_bool(!JS_IsException(res)) + "]");
        if (JS_IsException(res)) {
            throw support::exception(TRACEMSG(format_stack_trace(ctx)));
        }
        if (JS_IsString(res)) {
            auto str = jsval_to_string(ctx, res);
            return support::make_string_buffer(str);
        }
        return support::make_null_buffer();
    } 

    void run_garbage_collector(quickjs_engine&) {
        JS_RunGC(jsruntime.get());
    }

    static void initialize() {
        wilton_config_json();
        auto err = JS_StaticlibInitialize();
        if (0 != err) throw support::exception(TRACEMSG(
                "Error initializing QuickJS shared library, code: [" + sl::support::to_string(err) + "]"));
    }
};

PIMPL_FORWARD_CONSTRUCTOR(quickjs_engine, (sl::io::span<const char>), (), support::exception)
PIMPL_FORWARD_METHOD(quickjs_engine, support::buffer, run_callback_script, (sl::io::span<const char>), (), support::exception)
PIMPL_FORWARD_METHOD(quickjs_engine, void, run_garbage_collector, (), (), support::exception)
PIMPL_FORWARD_METHOD_STATIC(quickjs_engine, void, initialize, (), (), support::exception)


} // namespace
}
