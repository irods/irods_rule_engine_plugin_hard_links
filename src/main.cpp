#include <irods/irods_plugin_context.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>
#include <irods/irods_get_l1desc.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/rcMisc.h>
#include <irods/rodsError.h>
#include <irods/rodsErrorTable.h>
#include <irods/filesystem.hpp>
#include <irods/irods_logger.hpp>

#include "json.hpp"

#include <string>
#include <string_view>
#include <array>
#include <algorithm>
#include <iterator>
#include <functional>

namespace
{
    // clang-format off
    namespace fs           = irods::experimental::filesystem;

    using log              = irods::experimental::log;
    using json             = nlohmann::json;
    using handler_type     = std::function<irods::error(std::list<boost::any>&, irods::callback&)>;
    using handler_map_type = std::map<std::string_view, handler_type>;
    // clang-format on

    namespace util
    {
        auto get_rei(irods::callback& effect_handler) -> ruleExecInfo_t&
        {
            ruleExecInfo_t* rei{};
            irods::error result{effect_handler("unsafe_ms_ctx", &rei)};

            if (!result.ok()) {
                THROW(result.code(), "failed to get rule execution info");
            }

            return *rei;
        }

        template <typename Function>
        auto sudo(ruleExecInfo_t& rei, Function func) -> decltype(func())
        {
            auto& auth_flag = rei.rsComm->clientUser.authInfo.authFlag;
            const auto old_auth_flag = auth_flag;

            // Elevate privileges.
            auth_flag = LOCAL_PRIV_USER_AUTH;

            // Restore authorization flags on exit.
            irods::at_scope_exit<std::function<void()>> at_scope_exit{
                [&auth_flag, old_auth_flag] { auth_flag = old_auth_flag; }
            };

            return func();
        }

        auto log_exception_message(const char* msg, irods::callback& effect_handler) -> void
        {
            log::rule_engine::error(msg);
            addRErrorMsg(&get_rei(effect_handler).rsComm->rError, RE_RUNTIME_ERROR, msg);
        }

        template <typename T>
        auto get_input_object_ptr(std::list<boost::any>& rule_arguments) -> T*
        {
            return boost::any_cast<T*>(*std::next(std::begin(rule_arguments), 2));
        }
    } // namespace util

    //
    // PEP Handlers
    //

    namespace handler
    {
        class pep_api_data_obj_rename final
        {
        public:
            pep_api_data_obj_rename() = delete;

            static auto pre(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
            {
                try
                {
                    auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(rule_arguments);
                }
                catch (const std::exception& e)
                {
                    util::log_exception_message(e.what(), effect_handler);
                    return ERROR(RE_RUNTIME_ERROR, e.what());
                }

                return CODE(RULE_ENGINE_CONTINUE);
            }

            static auto post(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
            {
                try
                {
                    auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(rule_arguments);
                }
                catch (const std::exception& e)
                {
                    util::log_exception_message(e.what(), effect_handler);
                    return ERROR(RE_RUNTIME_ERROR, e.what());
                }

                return CODE(RULE_ENGINE_CONTINUE);
            }

        private:
        }; // class pep_api_data_obj_rename

        class pep_api_data_obj_unlink final
        {
        public:
            pep_api_data_obj_unlink() = delete;

            static auto pre(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
            {
                try
                {
                    auto* input = util::get_input_object_ptr<dataObjInp_t>(rule_arguments);
                }
                catch (const std::exception& e)
                {
                    util::log_exception_message(e.what(), effect_handler);
                    return ERROR(RE_RUNTIME_ERROR, e.what());
                }

                return CODE(RULE_ENGINE_CONTINUE);
            }

            static auto post(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
            {
                try
                {
                    auto* input = util::get_input_object_ptr<dataObjInp_t>(rule_arguments);
                }
                catch (const std::exception& e)
                {
                    util::log_exception_message(e.what(), effect_handler);
                    return ERROR(RE_RUNTIME_ERROR, e.what());
                }

                return CODE(RULE_ENGINE_CONTINUE);
            }

        private:
        }; // class pep_api_data_obj_unlink
    } // namespace handler

    //
    // Rule Engine Plugin
    //

    const handler_map_type pep_handlers{
        {"pep_api_data_obj_rename_post", handler::pep_api_data_obj_rename::post},
        {"pep_api_data_obj_rename_pre", handler::pep_api_data_obj_rename::pre},
        {"pep_api_data_obj_unlink_post", handler::pep_api_data_obj_unlink::post},
        {"pep_api_data_obj_unlink_pre",  handler::pep_api_data_obj_unlink::pre}
    };

    const handler_map_type commands{
        {"hard_links_count_links", {}},
        {"hard_links_list_data_objects", {}},
        {"hard_links_make_link", {}}
    };

    template <typename ...Args>
    using operation = std::function<irods::error(irods::default_re_ctx&, Args...)>;

    auto rule_exists(irods::default_re_ctx&, const std::string& rule_name, bool& exists) -> irods::error
    {
        exists = std::binary_search(std::begin(pep_handlers), std::end(pep_handlers), rule_name);
        return SUCCESS();
    }

    auto list_rules(irods::default_re_ctx&, std::vector<std::string>& rules) -> irods::error
    {
        std::transform(std::begin(pep_handlers),
                       std::end(pep_handlers),
                       std::back_inserter(rules),
                       [](auto v) { return std::string{v.first}; });

        std::transform(std::begin(commands),
                       std::end(commands),
                       std::back_inserter(rules),
                       [](auto v) { return std::string{v.first}; });

        return SUCCESS();
    }

    auto exec_rule(irods::default_re_ctx&,
                   const std::string& rule_name,
                   std::list<boost::any>& rule_arguments,
                   irods::callback effect_handler) -> irods::error
    {
        if (auto iter = pep_handlers.find(rule_name); std::end(pep_handlers) != iter) {
            return (iter->second)(rule_arguments, effect_handler);
        }

        log::rule_engine::error("Rule not supported [rule => {}]", rule_name);

        return CODE(RULE_ENGINE_CONTINUE);
    }
} // namespace (anonymous)

//
// Plugin Factory
//

using pluggable_rule_engine = irods::pluggable_rule_engine<irods::default_re_ctx>;

extern "C"
pluggable_rule_engine* plugin_factory(const std::string& _instance_name,
                                      const std::string& _context)
{
    // clang-format off
    const auto no_op         = [](auto&&...) { return SUCCESS(); };
    const auto not_supported = [](auto&&...) { return CODE(SYS_NOT_SUPPORTED); };
    // clang-format on

    auto* re = new pluggable_rule_engine{_instance_name, _context};

    re->add_operation("start", operation<const std::string&>{no_op});
    re->add_operation("stop", operation<const std::string&>{no_op});
    re->add_operation("rule_exists", operation<const std::string&, bool&>{rule_exists});
    re->add_operation("list_rules", operation<std::vector<std::string>&>{list_rules});
    re->add_operation("exec_rule", operation<const std::string&, std::list<boost::any>&, irods::callback>{exec_rule});
    re->add_operation("exec_rule_text", operation<const std::string&, msParamArray_t*, const std::string&, irods::callback>{not_supported});
    re->add_operation("exec_rule_expression", operation<const std::string&, msParamArray_t*, irods::callback>{not_supported});

    return re;
}

