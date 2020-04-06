#include <irods/irods_plugin_context.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>
#include <irods/irods_state_table.h>
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
#include <irods/scoped_privileged_client.hpp>

#include "json.hpp"
#include "fmt/format.h"

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
            const auto gql = fmt::format("select META_DATA_ATTR_VALUE "
                                         "where"
                                         " META_DATA_ATTR_NAME = 'irods::hard_link' and"
                                         " COLL_NAME = '{}' and"
                                         " DATA_NAME = '{}'",
                                         p.parent_path().c_str(),
                                         p.object_name().c_str());

            for (auto&& row : irods::query{&conn, gql}) {
                return row[0];
            }

            return std::nullopt;
        }

        auto get_existing_or_generate_uuid(rsComm_t& conn, const fs::path& logical_path) -> std::tuple<bool, std::string>
        {
            // If a UUID has already been assigned to the source logical path, then return that.
            if (const auto uuid = util::get_uuid(conn, logical_path); uuid) {
                return std::make_tuple(false, *uuid);
            }

            // Generate an unused UUID and return it.

            auto uuid = to_string(boost::uuids::random_generator{}());
            const auto* query = "select count(DATA_NAME) "
                                "where"
                                " META_DATA_ATTR_NAME = 'irods::hard_link' and"
                                " META_DATA_ATTR_VALUE = '{}'";

            for (auto&& row : irods::query{&conn, fmt::format(query, uuid)}) {
                uuid = to_string(boost::uuids::random_generator{}());
            }

            return std::make_tuple(true, uuid);
        }

        auto get_data_objects(rsComm_t& conn, std::string_view uuid) -> std::vector<fs::path>
        {
            const auto gql = fmt::format("select COLL_NAME, DATA_NAME "
                                         "where"
                                         " META_DATA_ATTR_NAME = 'irods::hard_link' and"
                                         " META_DATA_ATTR_VALUE = '{}'",
                                         uuid);

            std::vector<fs::path> data_objects;

            for (auto&& row : irods::query{&conn, gql}) {
                data_objects.push_back(fs::path{row[0]} / row[1]);
            }

            return data_objects;
        }

        auto get_data_object_info(rsComm_t& conn, const fs::path& p) -> std::vector<data_object_info>
        {
            const auto gql = fmt::format("select DATA_PATH, DATA_REPL_NUM, RESC_NAME, RESC_ID "
                                         "where COLL_NAME = '{}' and DATA_NAME = '{}'",
                                         p.parent_path().c_str(),
                                         p.object_name().c_str());

            std::vector<data_object_info> info;

            for (auto&& row : irods::query{&conn, gql}) {
                info.push_back({row[0], row[1], row[2], row[3]});
            }

            return info;
        }

        auto get_links_by_resource_id(rsComm_t& conn,
                                      std::string_view uuid,
                                      std::string_view resource_id) -> std::vector<fs::path>
        {
            const auto gql = fmt::format("select COLL_NAME, DATA_NAME "
                                         "where"
                                         " META_DATA_ATTR_NAME = 'irods::hard_link' and"
                                         " META_DATA_ATTR_VALUE = '{}' and"
                                         " META_DATA_ATTR_UNITS = '{}'", uuid, resource_id);

            std::vector<fs::path> links;

            for (auto&& row : irods::query{&conn, gql}) {
                links.push_back(fs::path{row[0]} / row[1]);
            }

            return links;
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

            throw std::runtime_error{fmt::format("Could not retrieve replica number for [path = {}, resource_id = {}]",
                                                 p.c_str(), resource_id)};
        }

        auto get_replica_number_and_resource_id(rsComm_t& conn, dataObjInp_t& input) -> std::tuple<int, std::string>
        {
            std::string hierarchy;

            if (const auto* hier = getValByKey(&input.condInput, RESC_HIER_STR_KW); !hier) {
                // Set a repl keyword so resources can respond accordingly.
                addKeyVal(&input.condInput, IN_REPL_KW, "");

                rodsServerHost_t* host = nullptr;
                int local = LOCAL_HOST;

                const auto err = irods::resource_redirect(irods::UNLINK_OPERATION, &conn, &input, hierarchy, host, local);

                if (!err.ok()) {
                    log::rule_engine::error("Could not resolve resource hierarchy [error = {}, error code = {}]",
                                            err.result(), err.code());
                    THROW(err.code(), err.result());
                }

                // We've resolved the redirect and have a host, set the hierarchy string for
                // subsequent API calls, etc.
                addKeyVal(&input.condInput, RESC_HIER_STR_KW, hierarchy.data());
            }
            else {
                hierarchy = hier;
            }

            rodsLong_t resource_id;

            if (const auto err = resc_mgr.hier_to_leaf_id(hierarchy, resource_id); !err.ok()) {
                log::rule_engine::error("Could not get resource id [error = {}, error code = {}]",
                                        err.result(), err.code());
                THROW(err.code(), err.result());
            }

            return std::make_tuple(util::get_replica_number(conn, input.objPath, resource_id),
                                   std::to_string(resource_id));
        }

        auto get_number_of_replicas_to_keep(const dataObjInp_t& input) -> int
        {
            if (const auto* value = getValByKey(&input.condInput, COPIES_KW); value) {
                return std::stoi(value);
            }

            return DEF_MIN_COPY_CNT;
        }

        auto set_logical_path(rsComm_t& conn, const fs::path& logical_path, const fs::path& new_logical_path) -> int
        {
            dataObjInfo_t info{};
            rstrcpy(info.objPath, logical_path.c_str(), MAX_NAME_LEN);

            keyValPair_t reg_params{};
            addKeyVal(&reg_params, ALL_KW, ""); // Update all replicas!

            // Update the data name if the names are different.
            if (const auto object_name = new_logical_path.object_name(); logical_path.object_name() != object_name) {
                addKeyVal(&reg_params, DATA_NAME_KW, object_name.c_str());
            }

            // Update the collection id if the parent paths are different.
            // (i.e. the data object is moving between collections)
            if (const auto collection = new_logical_path.parent_path(); logical_path.parent_path() != collection) {
                if (!fs::server::is_collection(conn, collection)) {
                    log::rule_engine::error("Path is not a collection or does not exist [path = {}]", collection.c_str());
                    return OBJ_PATH_DOES_NOT_EXIST;
                }

                std::string collection_id;

                for (auto&& row : irods::query{&conn, fmt::format("select COLL_ID where COLL_NAME = '{}'", collection.c_str())}) {
                    collection_id = row[0];
                }

                if (collection_id.empty()) {
                    log::rule_engine::error("Could not get collection id for [path = {}]", collection.c_str());
                    return SYS_INTERNAL_ERR;
                }

                addKeyVal(&reg_params, COLL_ID_KW, collection_id.c_str());
            }

            modDataObjMeta_t input{};
            input.dataObjInfo = &info;
            input.regParam = &reg_params;

            irods::experimental::scoped_privileged_client spc{conn};

            return rsModDataObjMeta(&conn, &input);
        }
    } // namespace util

    //
    // PEP Handlers
    //

    namespace handler
    {
        auto pep_api_data_obj_rename_pre(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
        {
            try {
                auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(rule_arguments);
                auto& conn = *util::get_rei(effect_handler).rsComm;
                const fs::path src_path = input->srcDataObjInp.objPath;

                // If the path is part of a hard link group, then update the logical path and
                // skip the actual rename operation. Else, do nothing and continue to the next REP.
                if (util::get_uuid(conn, src_path)) {
                    const fs::path dst_path = input->destDataObjInp.objPath;

                    if (const auto ec = util::set_logical_path(conn, src_path, dst_path); ec < 0) {
                        const auto msg = fmt::format("Could not set the logical path of [{}] to [{}]. "
                                                     "Use iadmin modrepl to update data object.",
                                                     src_path.c_str(),
                                                     dst_path.c_str());
                        log::rule_engine::error(msg);
                        addRErrorMsg(&util::get_rei(effect_handler).rsComm->rError, ec, msg.data());
                    }

                    return CODE(RULE_ENGINE_SKIP_OPERATION);
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
                // Hard links do NOT appear in the trash.
                if (const auto uuid = util::get_uuid(conn, input->objPath); uuid && util::get_data_objects(conn, *uuid).size() > 1) {
                    dataObjInp_t unreg_input{};
                    unreg_input.oprType = UNREG_OPR;
                    rstrcpy(unreg_input.objPath, input->objPath, MAX_NAME_LEN);
                    addKeyVal(&unreg_input.condInput, FORCE_FLAG_KW, "");

                    if (const auto ec = rsDataObjUnlink(&conn, &unreg_input); ec < 0) {
                        log::rule_engine::error("Could not remove hard link [{}]", input->objPath);
                        return ERROR(ec, "Hard Link removal error");
                    }

                    return CODE(RULE_ENGINE_SKIP_OPERATION);
                }
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
                    const auto [replica_number, resource_id] = util::get_replica_number_and_resource_id(conn, *input);
                    const auto number_of_replicas_to_keep = util::get_number_of_replicas_to_keep(*input);
                    const auto links = util::get_links_by_resource_id(conn, *uuid, resource_id);

                    if (links.size() > 1 && links.size() > number_of_replicas_to_keep) {
                        dataObjInp_t unreg_input{};
                        unreg_input.oprType = UNREG_OPR;
                        rstrcpy(unreg_input.objPath, input->objPath, MAX_NAME_LEN);
                        addKeyVal(&unreg_input.condInput, FORCE_FLAG_KW, "");
                        addKeyVal(&unreg_input.condInput, REPL_NUM_KW, std::to_string(replica_number).data());

                        if (const auto ec = rsDataObjUnlink(&conn, &unreg_input); ec < 0) {
                            log::rule_engine::error("Could not remove hard link [{}]", input->objPath);
                            return ERROR(ec, "Hard Link removal error");
                        }

                        // If the number of links was two before unregistering the replica, then we
                        // now have one link left (which doesn't make sense). Therefore, the server needs
                        // to delete the hard link metadata attached to the data object.
                        if (links.size() == 2) {
                            for (auto&& l : links) {
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
                const auto& logical_path = *boost::any_cast<std::string*>(*args_iter);
                const auto& replica_number = *boost::any_cast<std::string*>(*++args_iter);
                const auto& link_name = *boost::any_cast<std::string*>(*++args_iter);

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
                        if (info.replica_number == replica_number) {
                            return info;
                        }
                    }

                    THROW(USER_INVALID_REPLICA_INPUT, "Replica does not exist");
                }();

                // Register the new logical path.
                {
                    dataObjInp_t input{};
                    addKeyVal(&input.condInput, FILE_PATH_KW, info.physical_path.data());
                    addKeyVal(&input.condInput, REPL_NUM_KW, replica_number.data());
                    rstrcpy(input.objPath, link_name.data(), MAX_NAME_LEN);

                    // Vanilla iRODS only allows administrators to register data objects.
                    // Elevate privileges so that all users can create hard links.
                    irods::experimental::scoped_privileged_client spc{conn};

                    if (const auto ec = rsPhyPathReg(&conn, &input); ec < 0) {
                        log::rule_engine::error("Could not make hard link [error code = {}, physical_path = {}, link_name = {}]",
                                                ec, info.physical_path, link_name);
                        return ERROR(ec, "Could not register physical path as a data object");
                    }
                }

                const auto [generated_new_uuid, uuid] = util::get_existing_or_generate_uuid(conn, logical_path);

                try {
                    // Set hard link metadata on new the data object (the hard linked data object).
                    fs::server::set_metadata(conn, link_name, {"irods::hard_link", uuid, info.resource_id});

                    // Set hard link metadata on source data object if the uuid is new.
                    if (generated_new_uuid) {
                        fs::server::set_metadata(conn, logical_path, {"irods::hard_link", uuid, info.resource_id});
                    }

                    // Copy permissions to the hard link.
                    const auto status = fs::server::status(conn, logical_path);
                    for (auto&& e : status.permissions()) {
                        fs::server::permissions(conn, link_name, e.name, e.prms);
                    }
                }
                catch (const fs::filesystem_error& e) {
                    log::rule_engine::error("{} [error code = {}]", e.what(), e.code().value());
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
        {"pep_api_data_obj_rename_pre",  handler::pep_api_data_obj_rename_pre},
        {"pep_api_data_obj_unlink_pre",  handler::pep_api_data_obj_unlink_pre},
        {"pep_api_data_obj_trim_pre",    handler::pep_api_data_obj_trim_pre}
    };

    // TODO Could expose these as a new .so. The .so would then be loaded by the new "irods" cli.
    // Then we get things like: irods ln <args>...
    const handler_map_type hard_link_handlers{
        {"hard_link_create",  handler::make_hard_link},
        {"hard_links_create", handler::make_hard_link}
    };
    // clang-format on

    template <typename ...Args>
    using operation = std::function<irods::error(irods::default_re_ctx&, Args...)>;

    auto rule_exists(irods::default_re_ctx&, const std::string& rule_name, bool& exists) -> irods::error
    {
        exists = (pep_handlers.find(rule_name) != std::end(pep_handlers) ||
                  hard_link_handlers.find(rule_name) != std::end(hard_link_handlers));

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

        if (auto iter = hard_link_handlers.find(rule_name); std::end(hard_link_handlers) != iter) {
            return (iter->second)(rule_arguments, effect_handler);
        }

        log::rule_engine::error("Rule not supported in rule engine plugin [{}]", rule_name);

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
                auto logical_path = json_args.at("logical_path").get<std::string>();
                auto replica_number = json_args.at("replica_number").get<std::string>();
                auto link_name = json_args.at("link_name").get<std::string>();

                std::list<boost::any> args{&logical_path, &replica_number, &link_name};

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

