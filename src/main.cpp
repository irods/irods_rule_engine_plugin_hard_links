#include <irods/irods_plugin_context.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>
#include <irods/irods_resource_constants.hpp>
#include <irods/irods_state_table.h>
#include <irods/msParam.h>
#include <irods/objInfo.h>
#include <irods/rcMisc.h>
#include <irods/rodsConnect.h>
#include <irods/rodsError.h>
#include <irods/rodsErrorTable.h>
#include <irods/filesystem.hpp>
#include <irods/irods_query.hpp>
#include <irods/rodsType.h>
#include <irods/rsModDataObjMeta.hpp>
#include <irods/rsDataObjUnlink.hpp>
#include <irods/rsPhyPathReg.hpp>
#include <irods/irods_resource_manager.hpp>
#include <irods/irods_resource_redirect.hpp>
#include <irods/scoped_privileged_client.hpp>
#include <irods/irods_rs_comm_query.hpp>
#include <irods/specColl.hpp>
#include <irods/dataObjOpr.hpp>
#include <irods/irods_linked_list_iterator.hpp>
#include <irods/key_value_proxy.hpp>
#include <irods/irods_server_api_call.hpp>
#include <irods/rodsLog.h>

#include "boost/filesystem/path.hpp"
#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"
#include "fmt/format.h"
#include "json.hpp"

#include <exception>
#include <stdexcept>
#include <string>
#include <string_view>
#include <array>
#include <algorithm>
#include <iterator>
#include <functional>
#include <optional>
#include <chrono>

extern irods::resource_manager resc_mgr;

namespace
{
    // clang-format off
    namespace fs = irods::experimental::filesystem;

    using json   = nlohmann::json;
    // clang-format on

    struct hard_link
    {
        std::string uuid;
        std::string resource_id;
    };

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

        auto log_exception(const irods::exception& e) -> void
        {
            rodsLog(LOG_ERROR, "%s [error_code=%d]", e.what(), e.code());
        }

        auto make_hard_link_avu(std::string_view uuid, std::string_view resource_id) -> fs::metadata
        {
            return {"irods::hard_link", uuid.data(), resource_id.data()};
        }

        template <typename T>
        auto get_input_object_ptr(std::list<boost::any>& rule_arguments) -> T*
        {
            return boost::any_cast<T*>(*std::next(std::begin(rule_arguments), 2));
        }

        auto get_hard_links(rsComm_t& conn, const fs::path& p) -> std::vector<hard_link>
        {
            const auto gql = fmt::format("select META_DATA_ATTR_VALUE, META_DATA_ATTR_UNITS "
                                         "where"
                                         " META_DATA_ATTR_NAME = 'irods::hard_link' and"
                                         " COLL_NAME = '{}' and"
                                         " DATA_NAME = '{}'",
                                         p.parent_path().c_str(),
                                         p.object_name().c_str());

            std::vector<hard_link> data;

            for (auto&& row : irods::query{&conn, gql}) {
                data.push_back({row[0], row[1]});
            }

            return data;
        }

        auto get_hard_link_members(rsComm_t& conn,
                                   std::string_view uuid,
                                   std::string_view resource_id) -> std::vector<fs::path>
        {
            const auto gql = fmt::format("select COLL_NAME, DATA_NAME "
                                         "where"
                                         " META_DATA_ATTR_NAME = 'irods::hard_link' and"
                                         " META_DATA_ATTR_VALUE = '{}' and"
                                         " META_DATA_ATTR_UNITS = '{}'", uuid, resource_id);

            std::vector<fs::path> members;

            for (auto&& row : irods::query{&conn, gql}) {
                members.push_back(fs::path{row[0]} / row[1]);
            }

            return members;
        }

        auto get_replicas(rsComm_t& conn, const fs::path& p) -> std::vector<data_object_info>
        {
            const auto gql = fmt::format("select DATA_PATH, DATA_REPL_NUM, RESC_NAME, RESC_ID "
                                         "where COLL_NAME = '{}' and DATA_NAME = '{}'",
                                         p.parent_path().c_str(),
                                         p.object_name().c_str());

            std::vector<data_object_info> replicas;

            for (auto&& row : irods::query{&conn, gql}) {
                replicas.push_back({row[0], row[1], row[2], row[3]});
            }

            return replicas;
        }

        auto register_replica(rsComm_t& conn,
                              const data_object_info& replica_info,
                              std::string_view link_name) -> int
        {
            dataObjInp_t input{};
            addKeyVal(&input.condInput, FILE_PATH_KW, replica_info.physical_path.data());
            addKeyVal(&input.condInput, REPL_NUM_KW, replica_info.replica_number.data());
            addKeyVal(&input.condInput, DEST_RESC_NAME_KW, replica_info.resource_name.data());
            rstrcpy(input.objPath, link_name.data(), MAX_NAME_LEN);

            // Vanilla iRODS only allows administrators to register data objects.
            // Elevate privileges so that all users can create hard links.
            irods::experimental::scoped_privileged_client spc{conn};

            return rsPhyPathReg(&conn, &input);
        };

        auto unregister_replica(rsComm_t& conn,
                                const fs::path& logical_path,
                                const std::optional<std::string_view>& replica_number = std::nullopt) -> int
        {
            dataObjInp_t unreg_input{};
            unreg_input.oprType = UNREG_OPR;
            rstrcpy(unreg_input.objPath, logical_path.c_str(), MAX_NAME_LEN);
            addKeyVal(&unreg_input.condInput, FORCE_FLAG_KW, "");

            if (replica_number) {
                addKeyVal(&unreg_input.condInput, REPL_NUM_KW, replica_number->data());
            }

            return rsDataObjUnlink(&conn, &unreg_input);
        }

        auto unlink_replica(rsComm_t& conn,
                            const fs::path& logical_path,
                            const std::optional<std::string_view>& replica_number = std::nullopt) -> int
        {
            dataObjInp_t unreg_input{};
            rstrcpy(unreg_input.objPath, logical_path.c_str(), MAX_NAME_LEN);
            addKeyVal(&unreg_input.condInput, FORCE_FLAG_KW, "");

            if (replica_number) {
                addKeyVal(&unreg_input.condInput, REPL_NUM_KW, replica_number->data());
            }

            return rsDataObjUnlink(&conn, &unreg_input);
        }

        auto set_logical_path(rsComm_t& conn, const fs::path& logical_path, const fs::path& new_logical_path) -> int
        {
            dataObjInfo_t info{};
            rstrcpy(info.objPath, logical_path.c_str(), MAX_NAME_LEN);

            keyValPair_t reg_params{};
            addKeyVal(&reg_params, ALL_KW, "");

            // Update the data name if the names are different.
            if (const auto object_name = new_logical_path.object_name(); logical_path.object_name() != object_name) {
                addKeyVal(&reg_params, DATA_NAME_KW, object_name.c_str());
            }

            // Update the collection id if the parent paths are different.
            // (i.e. the data object is moving between collections)
            if (const auto collection = new_logical_path.parent_path(); logical_path.parent_path() != collection) {
                if (!fs::server::is_collection(conn, collection)) {
                    rodsLog(LOG_ERROR, "Path is not a collection or does not exist [path=%s]", collection.c_str());
                    return OBJ_PATH_DOES_NOT_EXIST;
                }

                std::string collection_id;

                for (auto&& row : irods::query{&conn, fmt::format("select COLL_ID where COLL_NAME = '{}'", collection.c_str())}) {
                    collection_id = row[0];
                }

                if (collection_id.empty()) {
                    rodsLog(LOG_ERROR, "Could not get collection id [collection=%s]", collection.c_str());
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

        auto set_replica_info(rsComm_t& conn,
                              const fs::path& logical_path,
                              const std::string_view replica_number,
                              const std::string_view new_resource_id,
                              const std::string_view new_resource_name,
                              const boost::filesystem::path& new_physical_path) -> int
        {
            dataObjInfo_t info{};
            rstrcpy(info.objPath, logical_path.c_str(), MAX_NAME_LEN);

            keyValPair_t reg_params{};
            addKeyVal(&reg_params, REPL_NUM_KW, replica_number.data());
            addKeyVal(&reg_params, RESC_ID_KW, new_resource_id.data());
            addKeyVal(&reg_params, RESC_NAME_KW, new_resource_name.data());
            addKeyVal(&reg_params, FILE_PATH_KW, new_physical_path.c_str());

            modDataObjMeta_t input{};
            input.dataObjInfo = &info;
            input.regParam = &reg_params;

            irods::experimental::scoped_privileged_client spc{conn};

            return rsModDataObjMeta(&conn, &input);
        }

        auto find_hard_link(const std::vector<hard_link>& hl_info, std::string_view resource_id) noexcept
            -> std::optional<std::reference_wrapper<const hard_link>>
        {
            const auto end = std::end(hl_info);
            const auto iter = std::find_if(std::begin(hl_info), end, [resource_id](const auto& e) noexcept {
                return e.resource_id == resource_id;
            });

            if (iter != end) {
                return std::ref(*iter);
            }

            return std::nullopt;
        }

        auto generate_new_uuid(rsComm_t& conn, std::string_view resource_id) -> std::string
        {
            auto uuid = to_string(boost::uuids::random_generator{}());

            const auto* query = "select DATA_NAME "
                                "where"
                                " META_DATA_ATTR_NAME = 'irods::hard_link' and"
                                " META_DATA_ATTR_VALUE = '{}' and"
                                " META_DATA_ATTR_UNITS = '{}'";

            while (true) {
                if (irods::query{&conn, fmt::format(query, uuid, resource_id)}.size() == 0) {
                    break;
                }

                uuid = to_string(boost::uuids::random_generator{}());
            }

            return uuid;
        }

        auto resolve_resource_hierarchy(rsComm_t& conn,
                                        dataObjInp_t& input,
                                        irods::experimental::key_value_proxy& kvp) -> irods::error
        {
            if (!kvp.contains(RESC_HIER_STR_KW)) {
                // Set the repl keyword so resources can respond accordingly.
                kvp.insert_or_assign({IN_REPL_KW, ""});

                std::string hier;
                int local = LOCAL_HOST;
                rodsServerHost_t* host = nullptr;

                const auto e = irods::resource_redirect(irods::UNLINK_OPERATION, &conn, &input, hier, host, local);

                if (!e.ok()) {
                    rodsLog(LOG_ERROR, "Could not resolve resource hierarchy [data_object=%s]", input.objPath);
                    return e;
                }

                kvp.insert_or_assign({DEST_RESC_HIER_STR_KW, hier});
            }

            return SUCCESS();
        }

        auto replace_hard_link_metadata(rsComm_t& conn,
                                        const fs::path& logical_path,
                                        const hard_link& hard_link,
                                        std::string_view new_resource_id) -> void
        {
            rodsLog(LOG_DEBUG, "Updating hard link info [data_object=%s]", logical_path.c_str());

            try {
                auto md = util::make_hard_link_avu(hard_link.uuid, hard_link.resource_id);
                fs::server::remove_metadata(conn, logical_path, md);

                md.units = new_resource_id;
                fs::server::add_metadata(conn, logical_path, md);
            }
            catch (const fs::filesystem_error& e) {
                rodsLog(LOG_ERROR, "Could not replace hard link metadata. [error_code=%d, error_message=%s, data_object=%s]",
                                   e.code().value(), e.what(), logical_path.c_str());
            }
        }

        auto get_access_permission(const rsComm_t& conn, const irods::experimental::key_value_proxy& kvp) -> char*
        {
            if (kvp.contains(ADMIN_KW)) {
                if (!irods::is_privileged_client(conn)) {
                    THROW(CAT_INSUFFICIENT_PRIVILEGE_LEVEL, "Insufficient privilege level");
                }
            }
            else {
                return ACCESS_DELETE_OBJECT;
            }

            return nullptr;
        }

        auto resolve_resource(std::string_view resource_name) -> irods::resource_ptr
        {
            irods::resource_ptr p;

            if (const auto e = resc_mgr.resolve(resource_name.data(), p); !e.ok()) {
                const auto msg = fmt::format("Could not resolve resource name to a resource id [resource_name={}]", resource_name);
                THROW(CAT_INVALID_RESOURCE_NAME, msg);
            }

            return p;
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
                if (!util::get_hard_links(conn, src_path).empty()) {
                    const fs::path dst_path = input->destDataObjInp.objPath;

                    if (const auto ec = util::set_logical_path(conn, src_path, dst_path); ec < 0) {
                        const auto msg = fmt::format("Could not update logical path. Use iadmin modrepl to update the "
                                                     "data object. [from={}, to={}]",
                                                     src_path.c_str(),
                                                     dst_path.c_str());
                        rodsLog(LOG_ERROR, msg.data());
                        addRErrorMsg(&util::get_rei(effect_handler).rsComm->rError, ec, msg.data());
                    }

                    return CODE(RULE_ENGINE_SKIP_OPERATION);
                }
            }
            catch (const irods::exception& e) {
                util::log_exception(e);
                return e;
            }
            catch (const std::exception& e) {
                return ERROR(SYS_INTERNAL_ERR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        auto pep_api_data_obj_unlink_pre(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
        {
            try {
                auto* input = util::get_input_object_ptr<dataObjInp_t>(rule_arguments);
                auto& conn = *util::get_rei(effect_handler).rsComm;

                // Determine which sibling hard link members needs to have their hard link metadata
                // updated to reflect the fact that the specified data object will be deleted. Some
                // replicas may be deleted while others remain because they are being referenced by
                // other data objects.

                const auto hl_info = util::get_hard_links(conn, input->objPath);

                if (hl_info.empty()) {
                    return CODE(RULE_ENGINE_CONTINUE);
                }

                // At this point, the data object to delete could be a member of multiple hard link groups.
                // We must now partition the set of replicas into ones that will be deleted and ones that
                // will be unregistered.

                for (auto&& replica : util::get_replicas(conn, input->objPath)) {
                    rodsLog(LOG_DEBUG, "Handling replica [resource_id=%s, replica_number=%s, physical_path=%s]",
                                       replica.resource_id.data(), replica.replica_number.data(), replica.physical_path.data());

                    // If the replica is hard linked, then unregister the replica and remove the hard link
                    // metadata from the data object that is being deleted.
                    if (const auto object = util::find_hard_link(hl_info, replica.resource_id); object) {
                        const hard_link& info = object.value();

                        rodsLog(LOG_DEBUG, "Replica is hard linked. Unregistering replica ... "
                                           "[replica_number=%s, physical_path=%s, UUID=%s, resource_id=%s]",
                                           replica.replica_number.data(), replica.physical_path.data(), info.uuid.data(), info.resource_id.data());

                        if (const auto ec = util::unregister_replica(conn, input->objPath, replica.replica_number); ec < 0) {
                            rodsLog(LOG_ERROR, "Could not unregister replica [data_object=%s, replica_number=%s]",
                                               input->objPath, replica.replica_number.data());
                            return ERROR(ec, "Could not unregister replica");
                        }

                        try {
                            const auto md = util::make_hard_link_avu(info.uuid, info.resource_id);

                            if (fs::server::exists(conn, input->objPath)) {
                                fs::server::remove_metadata(conn, input->objPath, md);
                            }

                            if (const auto members = util::get_hard_link_members(conn, info.uuid, info.resource_id);
                                members.size() == 1)
                            {
                                fs::server::remove_metadata(conn, members[0], md);
                            }
                        }
                        catch (const fs::filesystem_error& e) {
                            rodsLog(LOG_ERROR, "Could not remove hard link metadata "
                                               "[error_code=%d, error_message=%s, data_object=%s, replica_number=%s, UUID=%s, resource_id=%s]",
                                               e.code().value(), e.what(), input->objPath, replica.replica_number.data(), info.uuid.data(), info.resource_id.data());
                            // TODO Should this be a hard stop?
                            return ERROR(e.code().value(), e.what());
                        }
                    }
                    // If the replica is not hard linked, then simply unlink it.
                    else {
                        rodsLog(LOG_DEBUG, "Replica is NOT hard linked. Deleting replica ... [replica_number=%s, physical_path=%s]",
                                           replica.replica_number.data(), replica.physical_path.data());

                        if (const auto ec = util::unlink_replica(conn, input->objPath, replica.replica_number); ec < 0) {
                            rodsLog(LOG_ERROR, "Could not unlink replica [error_code=%d, data_object=%s, replica_number=%s]",
                                               ec, input->objPath, replica.replica_number.data());
                            return ERROR(ec, fmt::format("Could not unlink replica [data_object={}, replica_number={}",
                                                         input->objPath, replica.replica_number));
                        }
                    }
                }

                return CODE(RULE_ENGINE_SKIP_OPERATION);
            }
            catch (const irods::exception& e) {
                util::log_exception(e);
                return e;
            }
            catch (const std::exception& e) {
                return ERROR(SYS_INTERNAL_ERR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        auto pep_api_data_obj_trim_pre(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
        {
            try {
                auto* input = util::get_input_object_ptr<dataObjInp_t>(rule_arguments);
                auto& conn = *util::get_rei(effect_handler).rsComm;
                const auto hl_info = util::get_hard_links(conn, input->objPath);
                
                if (hl_info.empty()) {
                    rodsLog(LOG_DEBUG, "Data object is not part of a hard link group [data_object=%s].", input->objPath);
                    return CODE(RULE_ENGINE_CONTINUE);
                }

                irods::experimental::key_value_proxy kvp{input->condInput};

                // TODO Add deprecation message for itrim -N (4-2-stable only)!

                if (kvp.contains(RESC_NAME_KW) && // -S
                    kvp.contains(REPL_NUM_KW))    // -n
                {
                    return ERROR(USER_INCOMPATIBLE_PARAMS, "Incompatible parameters: source resource name and replica number");
                }

                specCollCache_t* specCollCache = nullptr;
                resolveLinkedPath(&conn, input->objPath, &specCollCache, &input->condInput);

                rodsServerHost_t* rodsServerHost = nullptr;
                
                if (const int ec = getAndConnRemoteZone(&conn, input, &rodsServerHost, REMOTE_OPEN); ec < 0) {
                    return ERROR(ec, "Redirect error");
                }
                else if (ec == REMOTE_HOST) {
                    const auto ec = irods::server_api_call(DATA_OBJ_TRIM_AN, &conn, input);
                    
                    if (ec) {
                        return ERROR(ec, "Redirect error");
                    }

                    return CODE(ec);
                }

                if (const auto e = util::resolve_resource_hierarchy(conn, *input, kvp); !e.ok()) {
                    return e;
                }

                dataObjInfo_t* dataObjInfoHead = nullptr;

                if (const auto ec = getDataObjInfo(&conn, input, &dataObjInfoHead, util::get_access_permission(conn, kvp), 1); ec < 0) {
                    return ERROR(ec, "Could not get data object information");
                }

                if (const auto ec = resolveInfoForTrim(&dataObjInfoHead, &input->condInput); ec < 0) {
                    return ERROR(ec, "Could not resolve which data objects to trim");
                }

                std::chrono::minutes minimum_age_in_minutes{0};

                if (const auto iter = kvp.find(AGE_KW); iter != std::end(kvp)) {
                    const std::string& value = *iter;
                    minimum_age_in_minutes = std::chrono::minutes{std::atoi(value.data())};
                }

                const auto replica_meets_age_requirement = [&minimum_age_in_minutes](auto&& timestamp_in_seconds)
                {
                    using clock_type = std::chrono::system_clock;
                    const clock_type::time_point last_modified{std::chrono::seconds{std::atoi(timestamp_in_seconds)}};
                    return clock_type::now() - last_modified >= minimum_age_in_minutes;
                };

                const auto is_dry_run = kvp.contains(DRYRUN_KW);

                rodsLog(LOG_ERROR, "Iterating over each replica and checking if it should be trimmed ...");

                for (auto&& info : dataObjInfoHead) {
                    rodsLog(LOG_DEBUG, "Replica to trim [data_object=%s, replica_number=%d, physical_path=%s]",
                                       input->objPath, info.replNum, info.filePath);

                    if (is_dry_run) {
                        rodsLog(LOG_DEBUG, "This is a dry run. Skipping ...");
                        continue;
                    }

                    if (!replica_meets_age_requirement(info.dataModify)) {
                        rodsLog(LOG_DEBUG, "Replica does not meet the minimum age requirement. Skipping ...");
                        continue;
                    }

                    const auto resource_id = std::to_string(info.rescId);

                    rodsLog(LOG_DEBUG, "Checking if replica is hard linked ...");

                    if (const auto object = util::find_hard_link(hl_info, resource_id); object) {
                        const hard_link& hl = object.value();

                        rodsLog(LOG_DEBUG, "Hard link info [UUID=%s, resource_id=%s]", hl.uuid.data(), hl.resource_id.data());
                        rodsLog(LOG_DEBUG, "Unregistering replica ...");

                        if (const auto ec = util::unregister_replica(conn, input->objPath, std::to_string(info.replNum)); ec < 0) {
                            rodsLog(LOG_ERROR, "Could not unregister replica [data_object=%s, replica_number=%d]", input->objPath, info.replNum);
                            return ERROR(ec, "Could not unregister replica");
                        }

                        try {
                            const auto md = util::make_hard_link_avu(hl.uuid, hl.resource_id);

                            // Because trimming a data object never deletes it, we must always remove any hard link
                            // metadata associated with it.
                            fs::server::remove_metadata(conn, input->objPath, md);

                            // Remove any hard link metadata that represents a hard link group of size one.
                            // Hard links groups always have at least two data objects in them.
                            if (const auto members = util::get_hard_link_members(conn, hl.uuid, hl.resource_id);
                                members.size() == 1)
                            {
                                fs::server::remove_metadata(conn, members[0], md);
                            }
                        }
                        catch (const fs::filesystem_error& e) {
                            rodsLog(LOG_ERROR, "Could not remove hard link metadata "
                                               "[error_code=%d, error_message=%s, data_object=%s, replica_number=%d, UUID=%s, resource_id=%s]",
                                               e.code().value(), e.what(), input->objPath, info.replNum, hl.uuid.data(), hl.resource_id.data());
                            return ERROR(e.code().value(), e.what());
                        }
                    }
                    else {
                        rodsLog(LOG_DEBUG, "Unlinking replica ...");

                        // The replica is not part of a hard link group, so delete it.
                        // The else-block is not making sense to me. It is basically saying that if the
                        // first replica is successfully deleted, remember that success code and do not allow
                        // any failures to be returned back to the client.
                        if (const auto ec = dataObjUnlinkS(&conn, input, &info); ec < 0) {
                            rodsLog(LOG_ERROR, "Could not unlink replica [error_code=%d, data_object=%s, replica_number=%d]",
                                               ec, input->objPath, info.replNum);
                            return ERROR(ec, "Could not unlink replica");
                        }
                    }
                }

                freeAllDataObjInfo(dataObjInfoHead);

                return CODE(RULE_ENGINE_SKIP_OPERATION);
            }
            catch (const irods::exception& e) {
                util::log_exception(e);
                return e;
            }
            catch (const std::exception& e) {
                return ERROR(SYS_INTERNAL_ERR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        static auto pep_api_data_obj_phymv_post(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
        {
            try {
                auto* input = util::get_input_object_ptr<dataObjInp_t>(rule_arguments);
                auto& conn = *util::get_rei(effect_handler).rsComm;

                if (!fs::server::is_data_object(conn, input->objPath)) {
                    return CODE(RULE_ENGINE_CONTINUE);
                }

                const auto hl_info = util::get_hard_links(conn, input->objPath);

                irods::experimental::key_value_proxy kvp{input->condInput};

                auto src_resc = util::resolve_resource(static_cast<const std::string&>(kvp.at(RESC_NAME_KW)));
                rodsLong_t src_resc_id;
                src_resc->get_property(irods::RESOURCE_ID, src_resc_id);
                rodsLog(LOG_DEBUG, "Source resource id = {}", src_resc_id);

                auto dst_resc = util::resolve_resource(static_cast<const std::string&>(kvp.at(DEST_RESC_NAME_KW)));
                rodsLong_t dst_resc_id;
                dst_resc->get_property(irods::RESOURCE_ID, dst_resc_id);
                rodsLog(LOG_DEBUG, "Destination resource id = %d", dst_resc_id);

                std::string dst_resource_name;
                dst_resc->get_property(irods::RESOURCE_NAME, dst_resource_name);
                rodsLog(LOG_DEBUG, "Destination resource name = %s", dst_resource_name.data());

                const auto src_resource_id = std::to_string(src_resc_id);

                if (auto object = util::find_hard_link(hl_info, src_resource_id); object) {
                    const hard_link& hl = object.value();

                    rodsLog(LOG_DEBUG, "Found hard link information [UUID=%s, resource_id=%s]", hl.uuid.data(), hl.resource_id.data());

                    // Retrieve the physical path of the data object that was recently updated.
                    const auto dst_resource_id = std::to_string(dst_resc_id);
                    const auto new_physical_path = [&] {
                        for (auto&& info : util::get_replicas(conn, input->objPath)) {
                            if (info.resource_id == dst_resource_id) {
                                return info.physical_path;
                            }
                        }

                        THROW(SYS_INTERNAL_ERR, "Could not find replica information by resource id");
                    }();

                    util::replace_hard_link_metadata(conn, input->objPath, hl, dst_resource_id);

                    auto members = util::get_hard_link_members(conn, hl.uuid, hl.resource_id);

                    {
                        auto end = std::end(members);
                        auto pred = [input](const auto& e) { return e == input->objPath; };
                        members.erase(std::remove_if(std::begin(members), end, pred), end);
                    }

                    // Update the hard link information for each data object in the hard link group.
                    // It is possible that some data objects in the hard link group have multiple replicas.
                    // In this case, we must find the replica that is part of the hard link group and
                    // update it. This should only update a single replica's physical path.
                    for (auto&& path : members) {
                        util::replace_hard_link_metadata(conn, path, hl, dst_resource_id);

                        const auto replicas = util::get_replicas(conn, path);
                        const auto end = std::end(replicas);
                        const auto iter = std::find_if(std::begin(replicas), end, [&src_resource_id](const auto& r) {
                            rodsLog(LOG_DEBUG, "Replica info [replica_number=%s, resource_id=%s, physical_path=%s]",
                                               r.replica_number.data(), r.resource_id.data(), r.physical_path.data());
                            return r.resource_id == src_resource_id;
                        });

                        if (iter == end) {
                            return ERROR(SYS_INTERNAL_ERR, "Could not find replica information by resource id");
                        }

                        const auto ec = util::set_replica_info(conn,
                                                               path,
                                                               iter->replica_number,
                                                               dst_resource_id,
                                                               dst_resource_name,
                                                               new_physical_path);

                        if (ec < 0) {
                            rodsLog(LOG_ERROR, "Could not update the physical path [error_code=%d, data_object=%s, replica_number=%s]",
                                               ec, path.c_str(), iter->replica_number.data());
                        }
                    }
                }
            }
            catch (const irods::exception& e) {
                util::log_exception(e);
                return e;
            }
            catch (const std::exception& e) {
                return ERROR(SYS_INTERNAL_ERR, e.what());
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

                // Verify that the link name is not already in use.
                if (const auto s = fs::server::status(conn, link_name); fs::server::exists(s)) {
                    if (fs::server::is_collection(s)) {
                        return ERROR(CAT_NAME_EXISTS_AS_COLLECTION, "The specified link name already exists");
                    }

                    if (fs::server::is_data_object(s)) {
                        return ERROR(CAT_NAME_EXISTS_AS_DATAOBJ, "The specified link name already exists");
                    }

                    return ERROR(CAT_INVALID_ARGUMENT, "The specified link name already exists");
                }

                // Get the data object information for the requested replica.
                const auto& info = [&conn, &logical_path, &replica_number] {
                    const auto info = util::get_replicas(conn, logical_path);

                    if (info.empty()) {
                        THROW(SYS_INTERNAL_ERR, "Could not gather data object information");
                    }

                    const auto end = std::end(info);
                    const auto iter = std::find_if(std::begin(info), end, [&replica_number](const auto& e) {
                        return e.replica_number == replica_number;
                    });

                    if (iter != end) {
                        return *iter;
                    }

                    THROW(USER_INVALID_REPLICA_INPUT, "Replica does not exist");
                }();

                // Register the replica with a new logical path.
                if (const auto ec = util::register_replica(conn, info, link_name); ec < 0) {
                    rodsLog(LOG_ERROR, "Could not make hard link [error_code=%d, physical_path=%s, link_name=%s]",
                                       ec, info.physical_path.data(), link_name.data());
                    return ERROR(ec, "Could not register physical path as a data object");
                }

                bool already_hard_linked = false;
                std::string uuid;

                // Check if the replica is already hard linked.
                if (auto hl_info = util::get_hard_links(conn, logical_path); !hl_info.empty()) {
                    if (const auto object = util::find_hard_link(hl_info, info.resource_id); object) {
                        already_hard_linked = true;
                        const hard_link& hl = object.value();
                        uuid = std::move(hl.uuid);
                        rodsLog(LOG_DEBUG, "Replica already hard linked [replica_number=%s, UUID=%s, resource_id=%s]",
                                           replica_number.data(), uuid.data(), hl.resource_id.data());
                    }
                }

                if (!already_hard_linked) {
                    uuid = util::generate_new_uuid(conn, info.resource_id);
                    rodsLog(LOG_DEBUG, "Generated new hard link [UUID=%s, resource_id=%s]", uuid.data(), info.resource_id.data());
                }

                try {
                    const auto md = util::make_hard_link_avu(uuid, info.resource_id);

                    // Set hard link metadata on the new data object (the hard linked data object).
                    fs::server::add_metadata(conn, link_name, md);

                    // Set hard link metadata on the source data object if it the replica was not
                    // already hard linked.
                    if (!already_hard_linked) {
                        fs::server::add_metadata(conn, logical_path, md);
                    }

                    // Copy permissions to the hard link.
                    const auto status = fs::server::status(conn, logical_path);
                    for (auto&& e : status.permissions()) {
                        fs::server::permissions(conn, link_name, e.name, e.prms);
                    }
                }
                catch (const fs::filesystem_error& e) {
                    rodsLog(LOG_ERROR, "%s [error_code = %d]", e.what(), e.code().value());
                    return ERROR(e.code().value(), e.what());
                }
            }
            catch (const irods::exception& e) {
                util::log_exception(e);
                return e;
            }
            catch (const std::exception& e) {
                return ERROR(SYS_INTERNAL_ERR, e.what());
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
        {"pep_api_data_obj_trim_pre",    handler::pep_api_data_obj_trim_pre},
        {"pep_api_data_obj_phymv_post",  handler::pep_api_data_obj_phymv_post}
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
        try {
            if (auto iter = pep_handlers.find(rule_name); std::end(pep_handlers) != iter) {
                return (iter->second)(rule_arguments, effect_handler);
            }

            if (auto iter = hard_link_handlers.find(rule_name); std::end(hard_link_handlers) != iter) {
                return (iter->second)(rule_arguments, effect_handler);
            }
        }
        catch (...) {
            rodsLog(LOG_ERROR, "Hard Links rule engine plugin encountered an unknown error");
            return ERROR(SYS_UNKNOWN_ERROR, "Hard Links rule engine plugin encountered an unknown error");
        }

        rodsLog(LOG_ERROR, "[hard_links] Rule not supported in rule engine plugin [rule=%s]", rule_name.data());

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto exec_rule_text_impl(std::string_view rule_text, irods::callback effect_handler) -> irods::error
    {
        rodsLog(LOG_DEBUG, "[hard_links] rule text = %s", rule_text.data());

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

        rodsLog(LOG_DEBUG, "[hard_links] rule text = %s", std::string{rule_text}.data());

        try {
            const auto json_args = json::parse(rule_text);

            rodsLog(LOG_DEBUG, "[hard_links] json input = %s", json_args.dump().data());

            const auto op = json_args.at("operation").get<std::string>();

            if (const auto iter = hard_link_handlers.find(op); iter != std::end(hard_link_handlers)) {
                auto logical_path = json_args.at("logical_path").get<std::string>();
                auto replica_number = json_args.at("replica_number").get<std::string>();
                auto link_name = json_args.at("link_name").get<std::string>();

                std::list<boost::any> args{&logical_path, &replica_number, &link_name};

                return (iter->second)(args, effect_handler);
            }

            return ERROR(INVALID_OPERATION, fmt::format("Invalid operation [operation={}]", op));
        }
        catch (const json::exception& e) {
            rodsLog(LOG_ERROR, "[hard_links] %s", e.what());
            return ERROR(USER_INPUT_FORMAT_ERR, e.what());
        }
        catch (const std::exception& e) {
            rodsLog(LOG_ERROR, "[hard_links] %s", e.what());
            return ERROR(SYS_INTERNAL_ERR, e.what());
        }
        catch (...) {
            rodsLog(LOG_ERROR, "[hard_links] rule engine plugin encountered an unknown error");
            return ERROR(SYS_UNKNOWN_ERROR, "[hard_links] rule engine plugin encountered an unknown error");
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

