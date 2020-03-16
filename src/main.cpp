#include <irods/filesystem/filesystem_error.hpp>
#include <irods/irods_plugin_context.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>
#include <irods/irods_get_l1desc.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_state_table.h>
#include <irods/modDataObjMeta.h>
#include <irods/msParam.h>
#include <irods/objInfo.h>
#include <irods/rcMisc.h>
#include <irods/rodsConnect.h>
#include <irods/rodsError.h>
#include <irods/rodsErrorTable.h>
#include <irods/filesystem.hpp>
#include <irods/irods_logger.hpp>
#include <irods/irods_query.hpp>
#include <irods/rodsType.h>
#include <irods/rsModDataObjMeta.hpp>
#include <irods/rsDataObjUnlink.hpp>
#include <irods/rsDataObjTrim.hpp> // For DEF_MIN_COPY_CNT
#include <irods/rsPhyPathReg.hpp>
#include <irods/irods_resource_manager.hpp>
#include <irods/irods_resource_redirect.hpp>

#include "json.hpp"

#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"

#include <exception>
#include <stdexcept>
#include <string>
#include <string_view>
#include <array>
#include <algorithm>
#include <iterator>
#include <functional>
#include <optional>

extern irods::resource_manager resc_mgr;

namespace
{
    // clang-format off
    namespace fs = irods::experimental::filesystem;

    using log    = irods::experimental::log;
    using json   = nlohmann::json;
    // clang-format on

    struct data_object_info
    {
        std::string physical_path;
        std::string replica_number;
        std::string resource_name;
        std::string resource_id;
    };

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

        auto get_uuid(rsComm_t& conn, const fs::path& p) -> std::optional<std::string>
        {
            const auto gql = fmt::format("select META_DATA_ATTR_VALUE where COLL_NAME = '{}' and "
                                         "DATA_NAME = '{}' and META_DATA_ATTR_NAME = 'irods::hard_link'",
                                         p.parent_path().c_str(),
                                         p.object_name().c_str());

            for (auto&& row : irods::query{&conn, gql}) {
                return row[0];
            }

            return std::nullopt;
        }

        auto get_data_objects(rsComm_t& conn, std::string_view uuid) -> std::vector<fs::path>
        {
            const auto gql = fmt::format("select COLL_NAME, DATA_NAME where META_DATA_ATTR_NAME = 'irods::hard_link' and "
                                         "META_DATA_ATTR_VALUE = '{}'",
                                         uuid);

            std::vector<fs::path> data_objects;

            for (auto&& row : irods::query{&conn, gql}) {
                data_objects.push_back(fs::path{row[0]} / row[1]);
            }

            return data_objects;
        }

        auto get_sibling_data_objects(rsComm_t& conn, const fs::path& p) -> std::vector<fs::path>
        {
            const auto uuid = get_uuid(conn, p);

            if (!uuid) {
                return {};
            }

            auto data_objects = get_data_objects(conn, *uuid);
            auto end = std::end(data_objects);

            data_objects.erase(std::remove(std::begin(data_objects), end, p), end);

            return data_objects;
        }

        auto get_data_object_info(rsComm_t& conn, const fs::path& p) -> std::vector<data_object_info>
        {
            const auto gql = fmt::format("select DATA_PATH, DATA_REPL_NUM, RESC_NAME, RESC_ID where COLL_NAME = '{}' and DATA_NAME = '{}'",
                                         p.parent_path().c_str(),
                                         p.object_name().c_str());

            std::vector<data_object_info> info;

            for (auto&& row : irods::query{&conn, gql}) {
                info.push_back({row[0], row[1], row[2], row[3]});
            }

            return info;
        }

        auto get_links_to_physical_path(rsComm_t& conn, const fs::path& p) -> std::vector<fs::path>
        {
            const auto gql = fmt::format("select COLL_NAME, DATA_NAME where DATA_PATH = '{}' and META_DATA_ATTR_NAME = 'irods::hard_link'", p.c_str());

            std::vector<fs::path> links;

            for (auto&& row : irods::query{&conn, gql}) {
                links.push_back(fs::path{row[0]} / row[1]);
            }

            return links;
        }

        auto get_links_by_resource_id(rsComm_t& conn,
                                      std::string_view uuid,
                                      std::string_view resource_id) -> std::vector<fs::path>
        {
            const auto gql = fmt::format("select COLL_NAME, DATA_NAME "
                                         "where"
                                         " META_DATA_ATTR_VALUE = '{}' and"
                                         " META_DATA_ATTR_UNITS = '{}' and"
                                         " META_DATA_ATTR_NAME = 'irods::hard_link'", uuid, resource_id);

            std::vector<fs::path> links;

            for (auto&& row : irods::query{&conn, gql}) {
                links.push_back(fs::path{row[0]} / row[1]);
            }

            return links;
        }

        auto get_physical_path(rsComm_t& conn, const fs::path& p, int replica_number = 0) -> std::string
        {
            const auto gql = fmt::format("select DATA_PATH, DATA_REPL_NUM where COLL_NAME = '{}' and DATA_NAME = '{}'",
                                         p.parent_path().c_str(),
                                         p.object_name().c_str());

            for (auto&& row : irods::query{&conn, gql}) {
                if (std::stoi(row[1]) == replica_number) {
                    return row[0];
                }
            }

            throw std::runtime_error{fmt::format("Could not retrieve physical path for [{}]", p.c_str())};
        }

        auto get_resource_id(rsComm_t& conn, const fs::path& p, int replica_number = 0) -> std::string
        {
            const auto gql = fmt::format("select RESC_ID, DATA_REPL_NUM where COLL_NAME = '{}' and DATA_NAME = '{}'",
                                         p.parent_path().c_str(),
                                         p.object_name().c_str());

            for (auto&& row : irods::query{&conn, gql}) {
                if (std::stoi(row[1]) == replica_number) {
                    return row[0];
                }
            }

            throw std::runtime_error{fmt::format("Could not retrieve resource id for [path => {}, replica_number = {}]",
                                                 p.c_str(), replica_number)};
        }

        auto get_replica_number(rsComm_t& conn, const fs::path& p, rodsLong_t resource_id) -> int
        {
            const auto gql = fmt::format("select DATA_REPL_NUM where COLL_NAME = '{}' and DATA_NAME = '{}' and RESC_ID = '{}'",
                                         p.parent_path().c_str(),
                                         p.object_name().c_str(),
                                         resource_id);

            for (auto&& row : irods::query{&conn, gql}) {
                return std::stoi(row[0]);
            }

            throw std::runtime_error{fmt::format("Could not retrieve replica number for [path => {}, resource_id => {}]",
                                                 p.c_str(), resource_id)};
        }

        auto set_physical_path(rsComm_t& conn, const fs::path& logical_path, const fs::path& physical_path) -> int
        {
            dataObjInfo_t info{};
            rstrcpy(info.objPath, logical_path.c_str(), MAX_NAME_LEN);

            keyValPair_t reg_params{};
            addKeyVal(&reg_params, FILE_PATH_KW, physical_path.c_str());

            modDataObjMeta_t input{};
            input.dataObjInfo = &info;
            input.regParam = &reg_params;

            return rsModDataObjMeta(&conn, &input);
        }
    } // namespace util

    //
    // PEP Handlers
    //

    namespace handler
    {
        auto pep_api_data_obj_rename_post(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
        {
            try {
                auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(rule_arguments);
                auto& conn = *util::get_rei(effect_handler).rsComm;
                const auto physical_path = util::get_physical_path(conn, input->destDataObjInp.objPath);

                for (auto&& sibling : util::get_sibling_data_objects(conn, input->destDataObjInp.objPath)) {
                    if (const auto ec = util::set_physical_path(conn, sibling, physical_path); ec < 0) {
                        log::rule_engine::error("Could not update physical path of [{}] to [{}]. "
                                                "Use iadmin modrepl to update remaining data objects.",
                                                input->destDataObjInp.objPath,
                                                sibling.c_str());

                        addRErrorMsg(&util::get_rei(effect_handler).rsComm->rError, RE_RUNTIME_ERROR, "");
                    }
                }
            }
            catch (const std::exception& e) {
                util::log_exception_message(e.what(), effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        auto pep_api_data_obj_unlink_pre(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
        {
            try {
                auto* input = util::get_input_object_ptr<dataObjInp_t>(rule_arguments);
                auto& conn = *util::get_rei(effect_handler).rsComm;

                // Unregister the data object.
                // Hard-links do NOT appear in the trash.
                if (const auto uuid = util::get_uuid(conn, input->objPath); uuid && util::get_data_objects(conn, *uuid).size() > 1) {
                    log::rule_engine::trace("Removing hard-link [{}] ...", input->objPath);

                    dataObjInp_t unreg_input{};
                    unreg_input.oprType = UNREG_OPR;
                    rstrcpy(unreg_input.objPath, input->objPath, MAX_NAME_LEN);
                    addKeyVal(&unreg_input.condInput, FORCE_FLAG_KW, "");

                    if (const auto ec = rsDataObjUnlink(&conn, &unreg_input); ec < 0) {
                        log::rule_engine::error("Could not remove hard-link [{}]", input->objPath);
                        return ERROR(ec, "Hard-Link removal error");
                    }

                    log::rule_engine::trace("Successfully removed hard-link [{}]. Skipping operation.", input->objPath);

                    return CODE(RULE_ENGINE_SKIP_OPERATION);
                }

                log::rule_engine::trace("Removing data object ...");
            }
            catch (const std::exception& e) {
                util::log_exception_message(e.what(), effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        auto pep_api_data_obj_trim_pre(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
        {
            try {
                auto* input = util::get_input_object_ptr<dataObjInp_t>(rule_arguments);
                auto& conn = *util::get_rei(effect_handler).rsComm;

                if (const auto uuid = util::get_uuid(conn, input->objPath); uuid) {
                    const auto [replica_number, resource_id] = [&conn, input] {
                        std::string hierarchy;

                        if (const auto* hier = getValByKey(&input->condInput, RESC_HIER_STR_KW); !hier) {
                            // Set a repl keyword so resources can respond accordingly.
                            // TODO Should this be removed after the call to resource_redirect()?
                            addKeyVal(&input->condInput, IN_REPL_KW, "");

                            rodsServerHost_t* host = nullptr;
                            int local = LOCAL_HOST;

                            const auto err = irods::resource_redirect(irods::UNLINK_OPERATION, &conn, input, hierarchy, host, local);

                            if (!err.ok()) {
                                log::rule_engine::error("Could not resolve resource hierarchy [error => {}, error code => {}]",
                                                        err.result(), err.code());
                                THROW(err.code(), err.result());
                            }

                            // We've resolved the redirect and have a host, set the hierarchy string for
                            // subsequent API calls, etc.
                            addKeyVal(&input->condInput, RESC_HIER_STR_KW, hierarchy.data());
                        }
                        else {
                            hierarchy = hier;
                        }

                        rodsLong_t resource_id;

                        if (const auto err = resc_mgr.hier_to_leaf_id(hierarchy, resource_id); !err.ok()) {
                            log::rule_engine::error("Could not get resource id [error => {}, error code => {}]",
                                                    err.result(), err.code());
                        }

                        return std::make_tuple(util::get_replica_number(conn, input->objPath, resource_id),
                                               std::to_string(resource_id));
                    }();

                    auto links = util::get_links_by_resource_id(conn, *uuid, resource_id);

                    const auto number_of_replicas_to_keep = [input] {
                        if (const auto* value = getValByKey(&input->condInput, COPIES_KW); value) {
                            return std::stoi(value);
                        }

                        return DEF_MIN_COPY_CNT;
                    }();

                    if (links.size() > 1 && links.size() > number_of_replicas_to_keep) {
                        log::rule_engine::trace("Removing hard-link [{}] ...", input->objPath);

                        dataObjInp_t unreg_input{};
                        unreg_input.oprType = UNREG_OPR;
                        rstrcpy(unreg_input.objPath, input->objPath, MAX_NAME_LEN);
                        addKeyVal(&unreg_input.condInput, FORCE_FLAG_KW, "");
                        addKeyVal(&unreg_input.condInput, REPL_NUM_KW, std::to_string(replica_number).data());

                        if (const auto ec = rsDataObjUnlink(&conn, &unreg_input); ec < 0) {
                            log::rule_engine::error("Could not remove hard-link [{}]", input->objPath);
                            return ERROR(ec, "Hard-Link removal error");
                        }

                        log::rule_engine::trace("Successfully removed hard-link [{}]. Skipping operation ...", input->objPath);

                        // If the number of links was two before unregistering the replica, then we
                        // now have one link left (which doesn't make sense). Therefore, the server needs
                        // to delete the hard-link metadata attached to the data object.
                        if (links.size() == 2) {
                            for (auto&& l : links) {
                                log::rule_engine::trace("link = {}", l.c_str());
                                fs::server::remove_metadata(conn, l, {"irods::hard_link", *uuid, resource_id});
                            }
                        }

                        return CODE(RULE_ENGINE_SKIP_OPERATION);
                    }
                }
            }
            catch (const fs::filesystem_error& e) {
                util::log_exception_message(e.what(), effect_handler);
                return ERROR(e.code().value(), e.what());
            }
            catch (const irods::exception& e) {
                util::log_exception_message(e.what(), effect_handler);
                return ERROR(e.code(), e.what());
            }
            catch (const std::exception& e) {
                util::log_exception_message(e.what(), effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        auto make_hard_link(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
        {
            try {
                auto args_iter = std::begin(rule_arguments);
                const auto logical_path = boost::any_cast<std::string>(*args_iter);
                const auto replica_number = boost::any_cast<int>(*++args_iter);
                const auto link_name = boost::any_cast<std::string>(*++args_iter);

                auto& conn = *util::get_rei(effect_handler).rsComm;

                if (fs::server::exists(conn, link_name)) {
                    return ERROR(CAT_NAME_EXISTS_AS_DATAOBJ, "The specified link name already exists");
                }

                const auto data_object_info = util::get_data_object_info(conn, logical_path);

                if (data_object_info.empty()) {
                    log::rule_engine::error("Could not gather data object information.");
                    return ERROR(SYS_INTERNAL_ERR, "Could not gather data object information");
                }

                const auto& info = [&replica_number, &data_object_info] {
                    for (auto&& info : data_object_info) {
                        if (std::stoi(info.replica_number) == replica_number) {
                            return info;
                        }
                    }

                    THROW(USER_INVALID_REPLICA_INPUT, "Replica does not exist");
                }();

                // Register the new logical path.
                dataObjInp_t input{};
                addKeyVal(&input.condInput, FILE_PATH_KW, info.physical_path.data());
                addKeyVal(&input.condInput, REPL_NUM_KW, std::to_string(replica_number).data());
                rstrcpy(input.objPath, link_name.data(), MAX_NAME_LEN);

                if (const auto ec = rsPhyPathReg(&conn, &input); ec < 0) {
                    log::rule_engine::error("Could not make hard-link [ec = {}, physical_path = {}, link_name = {}]", ec, info.physical_path, link_name);
                    return ERROR(ec, "Could not register physical path as a data object");
                }

                log::rule_engine::trace("Successfully registered data object [logical_path = {}, physical_path = {}]", logical_path.data(), info.physical_path.data());

                const auto uuid = [&conn, &logical_path] {
                    // If a UUID has already been assigned to the source logical path, then return that.
                    if (const auto uuid = util::get_uuid(conn, logical_path); uuid) {
                        return std::make_tuple(false, *uuid);
                    }

                    // Generate an unused UUID and return it.
                    auto uuid = to_string(boost::uuids::random_generator{}());
                    auto gql = fmt::format("select COUNT(DATA_NAME) where META_DATA_ATTR_NAME = 'irods::hard_link' and META_DATA_ATTR_VALUE = '{}'", uuid);

                    for (auto&& row : irods::query{&conn, gql}) {
                        log::rule_engine::trace("UUID [{}] already in use. Generating new UUID ...", uuid);
                        uuid = to_string(boost::uuids::random_generator{}());
                        gql = fmt::format("select COUNT(DATA_NAME) where META_DATA_ATTR_NAME = 'irods::hard_link' and META_DATA_ATTR_VALUE = '{}'", uuid);
                    }

                    return std::make_tuple(true, uuid);
                }();

                try {
                    fs::server::set_metadata(conn, link_name, {"irods::hard_link", std::get<std::string>(uuid), info.resource_id});

                    if (const auto& [new_uuid, uuid_value] = uuid; new_uuid) {
                        fs::server::set_metadata(conn, logical_path, {"irods::hard_link", uuid_value, info.resource_id});
                    }
                }
                catch (const fs::filesystem_error& e) {
                    log::rule_engine::error("Could not set hard-link metadata [msg = {}, ec = {}]", e.what(), e.code().value());
                    return ERROR(e.code().value(), e.what());
                }
            }
            catch (const irods::exception& e) {
                util::log_exception_message(e.what(), effect_handler);
                return e;
            }
            catch (const std::exception& e) {
                util::log_exception_message(e.what(), effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return SUCCESS();
        }
    } // namespace handler

    //
    // Rule Engine Plugin
    //

    // clang-format off
    using handler_type     = std::function<irods::error(std::list<boost::any>&, irods::callback&)>;
    using handler_map_type = std::map<std::string_view, handler_type>;

    const handler_map_type pep_handlers{
        {"pep_api_data_obj_rename_post", handler::pep_api_data_obj_rename_post},
        {"pep_api_data_obj_unlink_pre",  handler::pep_api_data_obj_unlink_pre},
        {"pep_api_data_obj_trim_pre",    handler::pep_api_data_obj_trim_pre}
    };

    // TODO Could expose these as a new .so. The .so would then be loaded by the new "irods" cli.
    // Then we get things like: irods ln <args>...
    const handler_map_type hard_link_handlers{
        {"hard_links_count_links", {}},
        {"hard_links_list_data_objects", {}},
        {"hard_links_create", handler::make_hard_link}
    };
    // clang-format on

    template <typename ...Args>
    using operation = std::function<irods::error(irods::default_re_ctx&, Args...)>;

    auto rule_exists(irods::default_re_ctx&, const std::string& rule_name, bool& exists) -> irods::error
    {
        exists = pep_handlers.find(rule_name) != std::end(pep_handlers);
        return SUCCESS();
    }

    auto list_rules(irods::default_re_ctx&, std::vector<std::string>& rules) -> irods::error
    {
        std::transform(std::begin(hard_link_handlers),
                       std::end(hard_link_handlers),
                       std::back_inserter(rules),
                       [](auto v) { return std::string{v.first}; });

        std::transform(std::begin(pep_handlers),
                       std::end(pep_handlers),
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

        log::rule_engine::error("Rule not supported [{}]", rule_name);

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto exec_rule_text_impl(std::string_view rule_text, irods::callback effect_handler) -> irods::error
    {
        log::rule_engine::debug({{"rule_text", std::string{rule_text}}});

        // irule <text>
        if (rule_text.find("@external rule {") != std::string::npos) {
            const auto start = rule_text.find_first_of('{') + 1;
            rule_text = rule_text.substr(start, rule_text.rfind(" }") - start);
        }
        // irule -F <script>
        else if (rule_text.find("@external") != std::string::npos) {
            const auto start = rule_text.find_first_of('{');
            rule_text = rule_text.substr(start, rule_text.rfind(" }") - start);
        }

        log::rule_engine::debug({{"rule_text", std::string{rule_text}}});

        try {
            const auto json_args = json::parse(rule_text);

            log::rule_engine::debug({{"function", __func__}, {"json_arguments", json_args.dump()}});

            const auto op = json_args.at("operation").get<std::string>();

            if (const auto iter = hard_link_handlers.find(op); iter != std::end(hard_link_handlers)) {
                std::list<boost::any> args{
                    json_args.at("logical_path").get<std::string>(),
                    json_args.at("replica_number").get<int>(),
                    json_args.at("link_name").get<std::string>()
                };

                return (iter->second)(args, effect_handler);
            }

            return ERROR(INVALID_OPERATION, fmt::format("Invalid operation [{}]", op));
        }
        catch (const json::parse_error& e) {
            // clang-format off
            log::rule_engine::error({{"rule_engine_plugin", "hard_links"},
                                     {"rule_engine_plugin_function", __func__},
                                     {"log_message", e.what()}});
            // clang-format on

            return ERROR(USER_INPUT_FORMAT_ERR, e.what());
        }
        catch (const json::type_error& e) {
            // clang-format off
            log::rule_engine::error({{"rule_engine_plugin", "hard_links"},
                                     {"rule_engine_plugin_function", __func__},
                                     {"log_message", e.what()}});
            // clang-format on

            return ERROR(SYS_INTERNAL_ERR, e.what());
        }
        catch (const std::exception& e) {
            // clang-format off
            log::rule_engine::error({{"rule_engine_plugin", "hard_links"},
                                     {"rule_engine_plugin_function", __func__},
                                     {"log_message", e.what()}});
            // clang-format on

            return ERROR(SYS_INTERNAL_ERR, e.what());
        }
        catch (...) {
            // clang-format off
            log::rule_engine::error({{"rule_engine_plugin", "hard_links"},
                                     {"rule_engine_plugin_function", __func__},
                                     {"log_message", "Unknown error"}});
            // clang-format on

            return ERROR(SYS_UNKNOWN_ERROR, "Unknown error");
        }
    }
} // namespace (anonymous)

//
// Plugin Factory
//

using pluggable_rule_engine = irods::pluggable_rule_engine<irods::default_re_ctx>;

extern "C"
auto plugin_factory(const std::string& _instance_name,
                    const std::string& _context) -> pluggable_rule_engine*
{
    const auto no_op = [](auto&&...) { return SUCCESS(); };

    const auto exec_rule_text_wrapper = [](irods::default_re_ctx&,
                                           const std::string& rule_text,
                                           msParamArray_t*,
                                           const std::string&,
                                           irods::callback effect_handler)
    {
        return exec_rule_text_impl(rule_text, effect_handler);
    };

    const auto exec_rule_expression_wrapper = [](irods::default_re_ctx&,
                                                 const std::string& rule_text,
                                                 msParamArray_t* ms_params,
                                                 irods::callback effect_handler)
    {
        return exec_rule_text_impl(rule_text, effect_handler);
    };

    auto* re = new pluggable_rule_engine{_instance_name, _context};

    re->add_operation("start", operation<const std::string&>{no_op});
    re->add_operation("stop", operation<const std::string&>{no_op});
    re->add_operation("rule_exists", operation<const std::string&, bool&>{rule_exists});
    re->add_operation("list_rules", operation<std::vector<std::string>&>{list_rules});
    re->add_operation("exec_rule", operation<const std::string&, std::list<boost::any>&, irods::callback>{exec_rule});
    re->add_operation("exec_rule_text", operation<const std::string&, msParamArray_t*, const std::string&, irods::callback>{exec_rule_text_wrapper});
    re->add_operation("exec_rule_expression", operation<const std::string&, msParamArray_t*, irods::callback>{exec_rule_expression_wrapper});

    return re;
}

