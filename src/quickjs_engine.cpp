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

namespace wilton {
namespace quickjs {

namespace { // anonymous

std::string extract_stacktrace(JSContext* ctx) {
    (void) ctx;
    return "";
}

std::string format_stacktrace(JSContext* ctx) {
    (void) ctx;
    return "";
}

/*
duk_ret_t load_func(JSContext* ctx) {
    auto path = std::string();
    try {
        size_t path_len;
        const char* path_ptr = duk_get_lstring(ctx, 0, std::addressof(path_len));
        if (nullptr == path_ptr) {
            throw support::exception(TRACEMSG("Invalid arguments specified"));
        }
        path = std::string(path_ptr, path_len);
        // load code
        char* code = nullptr;
        int code_len = 0;
        auto err_load = wilton_load_resource(path.c_str(), static_cast<int>(path.length()),
                std::addressof(code), std::addressof(code_len));
        if (nullptr != err_load) {
            support::throw_wilton_error(err_load, TRACEMSG(err_load));
        }
        if (0 == code_len) {
            throw support::exception(TRACEMSG(
                    "\nInvalid empty source code loaded, path: [" + path + "]").c_str());
        }
        wilton::support::log_debug("wilton.engine.quickjs.eval",
                "Evaluating source file, path: [" + path + "] ...");

        // compile source
        auto path_short = support::script_engine_map_detail::shorten_script_path(path);
        wilton::support::log_debug("wilton.engine.quickjs.eval", "loaded file short path: [" + path_short + "]");

        duk_push_lstring(ctx, code, code_len);
        wilton_free(code);
        duk_push_lstring(ctx, path_short.c_str(), path_short.length());
        auto err = duk_pcompile(ctx, DUK_COMPILE_EVAL);
        if (DUK_EXEC_SUCCESS == err) {
            err = duk_pcall(ctx, 0);
        }

        if (DUK_EXEC_SUCCESS != err) {
            std::string msg = format_stacktrace(ctx);
            duk_pop(ctx);
            throw support::exception(TRACEMSG(msg + "\nCall error"));
        } else {
            wilton::support::log_debug("wilton.engine.quickjs.eval", "Eval complete");
            duk_pop(ctx);
            duk_push_true(ctx);
        }

        return 1;
    } catch (const std::exception& e) {
        throw support::exception(TRACEMSG(e.what() + 
                "\nError loading script, path: [" + path + "]").c_str());
    } catch (...) {
        throw support::exception(TRACEMSG(
                "Error(...) loading script, path: [" + path + "]").c_str());
    }
}

duk_ret_t wiltoncall_func(JSContext* ctx) {
    size_t name_len;
    const char* name = duk_get_lstring(ctx, 0, std::addressof(name_len));
    if (nullptr == name) {
        name = "";
        name_len = 0;
    }
    size_t input_len;
    const char* input = duk_get_lstring(ctx, 1, std::addressof(input_len));
    if (nullptr == input) {
        input = "";
        input_len = 0;
    }
    char* out = nullptr;
    int out_len = 0;
    wilton::support::log_debug(std::string("wilton.wiltoncall.") + name,
            "Performing a call, input length: [" + sl::support::to_string(input_len) + "] ...");
    auto err = wiltoncall(name, static_cast<int> (name_len), input, static_cast<int> (input_len),
            std::addressof(out), std::addressof(out_len));
    wilton::support::log_debug(std::string("wilton.wiltoncall.") + name,
            "Call complete, result: [" + (nullptr != err ? std::string(err) : "") + "]");
    if (nullptr == err) {
        if (nullptr != out) {
            duk_push_lstring(ctx, out, out_len);
            wilton_free(out);
        } else {
            duk_push_null(ctx);
        }
        return 1;
    } else {
        auto msg = TRACEMSG(err + "\n'wiltoncall' error for name: [" + name + "]");
        wilton_free(err);
        throw support::exception(msg);
    }
}

void register_c_func(JSContext* ctx, const std::string& name, duk_c_function fun, duk_idx_t argnum) {
    duk_push_global_object(ctx);
    duk_push_c_function(ctx, fun, argnum);
    duk_put_prop_string(ctx, -2, name.c_str());
    duk_pop(ctx);
}

void eval_js(JSContext* ctx, const char* code, size_t code_len) {
    auto err = duk_peval_lstring(ctx, code, code_len);
    if (DUK_EXEC_SUCCESS != err) {
        // cannot happen - c++ exception will be thrown by quickjs
        throw support::exception(TRACEMSG(format_stacktrace(ctx) +
                "\nDuktape engine eval error"));
    }
}
 */

} // namespace

class quickjs_engine::impl : public sl::pimpl::object::impl {
//    std::unique_ptr<JSContext, std::function<void(JSContext*)>> dukctx;

public:
    impl(sl::io::span<const char> init_code) {
        wilton::support::log_info("wilton.engine.quickjs.init", "Initializing engine instance ...");
        /*
        auto ctx = dukctx.get();
        if (nullptr == ctx) throw support::exception(TRACEMSG(
                "Error creating Duktape context"));
        auto def = sl::support::defer([ctx]() STATICLIB_NOEXCEPT {
            pop_stack(ctx);
        });
        register_c_func(ctx, "WILTON_load", load_func, 1);
        register_c_func(ctx, "WILTON_wiltoncall", wiltoncall_func, 2);
        eval_js(ctx, init_code.data(), init_code.size());
        wilton::support::log_info("wilton.engine.quickjs.init", "Engine initialization complete");

        // if debug port specified - run debugging
        if (debug_transport.is_active()) {

            wilton::support::log_debug("wilton.engine.quickjs.init",
                    "port: [" + sl::support::to_string(debug_transport.get_port()) + "]");
            // create transport protocol handler
            debug_transport.duk_trans_socket_init();
            debug_transport.duk_trans_socket_waitconn();
            duk_debugger_attach(ctx,
                    duk_trans_socket_read_cb,
                    duk_trans_socket_write_cb,
                    duk_trans_socket_peek_cb,
                    NULL, // read_flush_cb
                    NULL, // write_flush_cb
                    NULL, // detach handler
                    static_cast<void*> (std::addressof(debug_transport))); // udata
        }
        */
        (void) init_code;
    }

    support::buffer run_callback_script(quickjs_engine&, sl::io::span<const char> callback_script_json) {
        /*
        auto ctx = dukctx.get();
        auto def = sl::support::defer([ctx]() STATICLIB_NOEXCEPT {
            pop_stack(ctx);
        });

        wilton::support::log_debug("wilton.engine.quickjs.run", 
                "Running callback script: [" + std::string(callback_script_json.data(), callback_script_json.size()) + "] ...");
        duk_get_global_string(ctx, "WILTON_run");
        
        duk_push_lstring(ctx, callback_script_json.data(), callback_script_json.size());
        auto err = duk_pcall(ctx, 1);

        wilton::support::log_debug("wilton.engine.quickjs.run",
                "Callback run complete, result: [" + sl::support::to_string_bool(DUK_EXEC_SUCCESS == err) + "]");
        if (DUK_EXEC_SUCCESS != err) {
            throw support::exception(TRACEMSG(format_stacktrace(ctx)));
        }
        if (DUK_TYPE_STRING == duk_get_type(ctx, -1)) {
            size_t len;
            const char* str = duk_get_lstring(ctx, -1, std::addressof(len));            
            return support::make_array_buffer(str, static_cast<int> (len));            
        }
         */
        (void) callback_script_json;
        return support::make_null_buffer();

    } 

    void run_garbage_collector(quickjs_engine&) {
    }
};

PIMPL_FORWARD_CONSTRUCTOR(quickjs_engine, (sl::io::span<const char>), (), support::exception)
PIMPL_FORWARD_METHOD(quickjs_engine, support::buffer, run_callback_script, (sl::io::span<const char>), (), support::exception)
PIMPL_FORWARD_METHOD(quickjs_engine, void, run_garbage_collector, (), (), support::exception)


} // namespace
}
