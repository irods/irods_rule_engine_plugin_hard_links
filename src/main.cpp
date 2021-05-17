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
#include <irods/irods_logger.hpp>
#include <irods/irods_query.hpp>
#include <irods/rodsType.h>
#include <irods/rsModDataObjMeta.hpp>
#include <irods/rsDataObjUnlink.hpp>
#include <irods/rsPhyPathReg.hpp>
#include <irods/dataObjTrim.h>
#include <irods/rsDataObjTrim.hpp>
#include <irods/irods_resource_manager.hpp>
#include <irods/irods_resource_redirect.hpp>
#include <irods/scoped_privileged_client.hpp>
#include <irods/irods_rs_comm_query.hpp>
#include <irods/specColl.hpp>
#include <irods/dataObjOpr.hpp>
#include <irods/irods_linked_list_iterator.hpp>
#include <irods/key_value_proxy.hpp>
#include <irods/irods_server_api_call.hpp>

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
    namespace ix = irods::experimental;
    namespace fs = irods::experimental::filesystem;

    using log    = irods::experimental::log;
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
            log::rule_engine::error("{} [error_code={}]", e.what(), e.code());
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
            ix::scoped_privileged_client spc{conn};

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

            // Vanilla iRODS only allows administrators to register data objects.
            // Elevate privileges so that all users can create hard links.
            ix::scoped_privileged_client spc{conn};

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
                    log::rule_engine::error("Path is not a collection or does not exist [path={}]", collection.c_str());
                    return OBJ_PATH_DOES_NOT_EXIST;
                }

                std::string collection_id;

                for (auto&& row : irods::query{&conn, fmt::format("select COLL_ID where COLL_NAME = '{}'", collection.c_str())}) {
                    collection_id = row[0];
                }

                if (collection_id.empty()) {
                    log::rule_engine::error("Could not get collection id [collection={}]", collection.c_str());
                    return SYS_INTERNAL_ERR;
                }

                addKeyVal(&reg_params, COLL_ID_KW, collection_id.c_str());
            }

            modDataObjMeta_t input{};
            input.dataObjInfo = &info;
            input.regParam = &reg_params;

            ix::scoped_privileged_client spc{conn};

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

            try {
                info.replNum = std::stoi(replica_number.data());
            }
            catch (...) {
                rodsLog(LOG_ERROR, "Could not convert replica number string to integer [path=%s, replica_number=%s]",
                        logical_path.c_str(), replica_number.data());
                return SYS_INTERNAL_ERR;
            }

            keyValPair_t reg_params{};
            addKeyVal(&reg_params, RESC_ID_KW, new_resource_id.data());
            addKeyVal(&reg_params, RESC_NAME_KW, new_resource_name.data());
            addKeyVal(&reg_params, FILE_PATH_KW, new_physical_path.c_str());

            modDataObjMeta_t input{};
            input.dataObjInfo = &info;
            input.regParam = &reg_params;

            ix::scoped_privileged_client spc{conn};

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

        auto replace_hard_link_metadata(rsComm_t& conn,
                                        const fs::path& logical_path,
                                        const hard_link& hard_link,
                                        std::string_view new_resource_id) -> void
        {
            log::rule_engine::debug("Updating hard link info [data_object={}]", logical_path.c_str());

            try {
                auto md = util::make_hard_link_avu(hard_link.uuid, hard_link.resource_id);
                fs::server::remove_metadata(conn, logical_path, md);

                md.units = new_resource_id;
                fs::server::add_metadata(conn, logical_path, md);
            }
            catch (const fs::filesystem_error& e) {
                log::rule_engine::error("Could not replace hard link metadata. [error_code={}, error_message={}, data_object={}]",
                                        e.code().value(), e.what(), logical_path.c_str());
            }
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

        auto convert_physical_object_to_dataObjInfo_t(const irods::physical_object& _obj) -> dataObjInfo_t
        {
            dataObjInfo_t info{};

            info.dataSize = _obj.size();
            info.dataId = _obj.id();
            info.collId = _obj.coll_id();
            info.replNum = _obj.repl_num();
            info.replStatus = _obj.replica_status();
            info.dataMapId = _obj.map_id();
            info.rescId = _obj.resc_id();

            rstrcpy(info.objPath, _obj.name().c_str(), sizeof(info.objPath));
            rstrcpy(info.version, _obj.version().c_str(), sizeof(info.version));
            rstrcpy(info.dataType, _obj.type_name().c_str(), sizeof(info.dataType));
            rstrcpy(info.rescName, _obj.resc_name().c_str(), sizeof(info.rescName));
            rstrcpy(info.filePath, _obj.path().c_str(), sizeof(info.filePath));
            rstrcpy(info.dataOwnerName, _obj.owner_name().c_str(), sizeof(info.dataOwnerName));
            rstrcpy(info.dataOwnerZone, _obj.owner_zone().c_str(), sizeof(info.dataOwnerZone));
            rstrcpy(info.statusString, _obj.status().c_str(), sizeof(info.statusString));
            rstrcpy(info.chksum, _obj.checksum().c_str(), sizeof(info.chksum));
            rstrcpy(info.dataExpiry, _obj.expiry_ts().c_str(), sizeof(info.dataExpiry));
            rstrcpy(info.dataMode, _obj.mode().c_str(), sizeof(info.dataMode));
            rstrcpy(info.dataComments, _obj.r_comment().c_str(), sizeof(info.dataComments));
            rstrcpy(info.dataCreate, _obj.create_ts().c_str(), sizeof(info.dataCreate));
            rstrcpy(info.dataModify, _obj.modify_ts().c_str(), sizeof(info.dataModify));
            rstrcpy(info.rescHier, _obj.resc_hier().c_str(), sizeof(info.rescHier));

            return info;
        }

        auto get_minimum_age_in_minutes(const ix::key_value_proxy<keyValPair_t>& _kvp) -> std::chrono::minutes
        {
            if (const auto iter = _kvp.find(AGE_KW); iter != std::end(_kvp)) {
                if (const auto v = std::atoi((*iter).value().data()); v > 0) {
                    return std::chrono::minutes{v};
                }
            }

            return std::chrono::minutes{0};;
        }

        auto get_minimum_replica_count(const ix::key_value_proxy<keyValPair_t>& _kvp) -> std::size_t
        {
            if (const auto iter = _kvp.find(COPIES_KW); iter != std::end(_kvp)) {
                try {
                    if (const auto value = std::stoull((*iter).value().data()); value > 0) {
                        return value;
                    }
                }
                catch (...) {}
            }

            return DEF_MIN_COPY_CNT;
        }

        auto get_replica_list(rsComm_t& _conn, dataObjInp_t& _input) -> std::vector<irods::physical_object>
        {
            ix::key_value_proxy kvp{_input.condInput};

            if (!kvp.contains(RESC_HIER_STR_KW)) {
                auto result = irods::resolve_resource_hierarchy(irods::UNLINK_OPERATION, &_conn, _input);
                auto file_obj = std::get<irods::file_object_ptr>(result);
                return file_obj->replicas();
            }

            irods::file_object_ptr file_obj{new irods::file_object{}};
            irods::error fac_err = irods::file_object_factory(&_conn, &_input, file_obj);

            if (!fac_err.ok()) {
                THROW(fac_err.code(), "file_object_factory failed");
            }

            return file_obj->replicas();
        }

        auto get_list_of_replicas_to_trim(dataObjInp_t& _input, const std::vector<irods::physical_object>& _replicas)
            -> std::vector<irods::physical_object>
        {
            std::vector<irods::physical_object> trim_list;

            const auto good_replica_count = std::count_if(std::begin(_replicas), std::end(_replicas), [](const auto& repl) {
                return (repl.replica_status() & 0x0F) == GOOD_REPLICA;
            });

            ix::key_value_proxy kvp{_input.condInput};
            const auto minimum_replica_count = get_minimum_replica_count(kvp);

            using clock_type = std::chrono::system_clock;

            const auto replica_meets_age_requirement =
                [min_age = util::get_minimum_age_in_minutes(kvp), now = clock_type::now()](std::string_view _timestamp_in_secs)
                {
                    const clock_type::time_point last_modified{std::chrono::seconds{std::atoi(_timestamp_in_secs.data())}};
                    return now - last_modified >= min_age;
                };

            // If a specific replica number is specified, only trim that one!
            if (const auto iter = kvp.find(REPL_NUM_KW); iter != std::end(kvp)) {
                try {
                    const auto end = std::end(_replicas);
                    const auto repl = std::find_if(std::begin(_replicas), end,
                        [n = std::stoi((*iter).value().data())](const auto& _r) {
                            return n == _r.repl_num();
                        });

                    if (repl == end) {
                        THROW(SYS_REPLICA_DOES_NOT_EXIST, "Target replica does not exist");
                    }

                    if (!replica_meets_age_requirement(repl->modify_ts())) {
                        THROW(USER_INCOMPATIBLE_PARAMS, "Target replica is not old enough for removal");
                    }

                    if (good_replica_count <= minimum_replica_count && (repl->replica_status() & 0x0F) == GOOD_REPLICA) {
                        THROW(USER_INCOMPATIBLE_PARAMS, "Cannot remove the last good replica");
                    }

                    trim_list.push_back(*repl);

                    return trim_list;
                }
                catch (const std::invalid_argument& e) {
                    log::rule_engine::error(e.what());
                    THROW(USER_INVALID_REPLICA_INPUT, "Invalid replica number requested");
                }
                catch (const std::out_of_range& e) {
                    log::rule_engine::error(e.what());
                    THROW(USER_INVALID_REPLICA_INPUT, "Invalid replica number requested");
                }
            }

            const auto resc_name = kvp.contains(RESC_NAME_KW) ? kvp[RESC_NAME_KW].value() : "";
            const auto matches_target_resource = [&resc_name](const irods::physical_object& _obj) {
                return irods::hierarchy_parser{_obj.resc_hier()}.first_resc() == resc_name;
            };

            // Walk list and add stale replicas to the list.
            for (const auto& obj : _replicas) {
                if ((obj.replica_status() & 0x0F) == STALE_REPLICA) {
                    if (!replica_meets_age_requirement(obj.modify_ts()) || (!resc_name.empty() && !matches_target_resource(obj))) {
                        continue;
                    }

                    trim_list.push_back(obj);
                }
            }

            if (good_replica_count <= minimum_replica_count) {
                return trim_list;
            }

            // If we have not reached the minimum count, walk list again and add good replicas.
            std::size_t good_replicas_to_be_trimmed = 0;

            for (const auto& obj : _replicas) {
                if ((obj.replica_status() & 0x0F) == GOOD_REPLICA) {
                    if (!replica_meets_age_requirement(obj.modify_ts()) || (!resc_name.empty() && !matches_target_resource(obj))) {
                        continue;
                    }

                    if (good_replica_count - good_replicas_to_be_trimmed <= minimum_replica_count) {
                        return trim_list;
                    }

                    trim_list.push_back(obj);
                    ++good_replicas_to_be_trimmed;
                }
            }

            return trim_list;
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
                        log::rule_engine::error(msg);
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
                    log::rule_engine::debug("Handling replica [resource_id={}, replica_number={}, physical_path={}]",
                                            replica.resource_id, replica.replica_number, replica.physical_path);

                    // If the replica is hard linked, then unregister the replica and remove the hard link
                    // metadata from the data object that is being deleted.
                    if (const auto object = util::find_hard_link(hl_info, replica.resource_id); object) {
                        const hard_link& info = object.value();

                        log::rule_engine::debug("Replica is hard linked. Unregistering replica ... "
                                                "[replica_number={}, physical_path={}, UUID={}, resource_id={}]",
                                                replica.replica_number, replica.physical_path, info.uuid, info.resource_id);

                        if (const auto ec = util::unregister_replica(conn, input->objPath, replica.replica_number); ec < 0) {
                            log::rule_engine::error("Could not remove hard link [{}]", input->objPath);
                            return ERROR(ec, "Hard Link removal error");
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
                            log::rule_engine::error("Could not remove hard link metadata "
                                                    "[error_code={}, error_message={}, data_object={}, replica_number={}, UUID={}, resource_id={}]",
                                                    e.code().value(), e.what(), input->objPath, replica.replica_number, info.uuid, info.resource_id);
                            // TODO Should this be a hard stop?
                            return ERROR(e.code().value(), e.what());
                        }
                    }
                    // If the replica is not hard linked, then simply unlink it.
                    else {
                        log::rule_engine::debug("Replica is NOT hard linked. Deleting replica ... [replica_number={}, physical_path={}]",
                                                replica.replica_number, replica.physical_path);

                        if (const auto ec = util::unlink_replica(conn, input->objPath, replica.replica_number); ec < 0) {
                            log::rule_engine::error("Could not unlink replica [error_code={}, data_object={}, replica_number={}]",
                                                    ec, input->objPath, replica.replica_number);
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
                    log::rule_engine::debug("Data object is not part of a hard link group [data_object={}].", input->objPath);
                    return CODE(RULE_ENGINE_CONTINUE);
                }

                ix::key_value_proxy kvp{input->condInput};

                // TODO Add deprecation message for itrim -N (4-2-stable only)!

                if (kvp.contains(RESC_NAME_KW) && // -S
                    kvp.contains(REPL_NUM_KW))    // -n
                {
                    return ERROR(USER_INCOMPATIBLE_PARAMS, "Incompatible parameters: source resource name and replica number");
                }

                specCollCache_t* specCollCache = nullptr;
                resolveLinkedPath(&conn, input->objPath, &specCollCache, &input->condInput);

                rodsServerHost_t* rodsServerHost = nullptr;
                
                if (const auto ec = getAndConnRemoteZone(&conn, input, &rodsServerHost, REMOTE_OPEN); ec < 0) {
                    return ERROR(ec, "Redirect error");
                }
                else if (ec == REMOTE_HOST) {
                    const auto ec = rcDataObjTrim(rodsServerHost->conn, input);
                    
                    if (ec < 0) {
                        return ERROR(ec, "Redirect error");
                    }

                    return CODE(ec);
                }

                int error_code = 0;
                std::string replica_number;

                // Temporarily remove REPL_NUM_KW to ensure we are returned all replicas in the list.
                if (kvp.contains(REPL_NUM_KW)) {
                    replica_number = kvp[REPL_NUM_KW].value().data();
                    kvp.erase(REPL_NUM_KW);
                }

                const auto repl_list = util::get_replica_list(conn, *input);

                if (!replica_number.empty()) {
                    kvp[REPL_NUM_KW] = replica_number;
                }

                const auto is_dry_run = kvp.contains(DRYRUN_KW);

                for (auto&& obj : util::get_list_of_replicas_to_trim(*input, repl_list)) {
                    log::rule_engine::debug("Replica to trim [data_object={}, replica_number={}, physical_path={}]",
                                            input->objPath, obj.repl_num(), obj.path());

                    if (is_dry_run) {
                        log::rule_engine::debug("This is a dry run. Skipping ...");
                        error_code = 1;
                        continue;
                    }

                    log::rule_engine::debug("Checking if replica is hard linked ...");

                    if (const auto object = util::find_hard_link(hl_info, std::to_string(obj.resc_id())); object) {
                        const hard_link& hl = object.value();

                        log::rule_engine::debug("Unregistering replica. [UUID={}, resource_id={}]", hl.uuid, hl.resource_id);

                        if (const auto ec = util::unregister_replica(conn, input->objPath, std::to_string(obj.repl_num())); ec < 0) {
                            log::rule_engine::error("Could not unregister replica [data_object={}, replica_number={}]",
                                                    input->objPath, obj.repl_num());
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
                            log::rule_engine::error("Could not remove hard link metadata "
                                                    "[error_code={}, error_message={}, data_object={}, replica_number={}, UUID={}, resource_id={}]",
                                                    e.code().value(), e.what(), input->objPath, obj.repl_num(), hl.uuid, hl.resource_id);
                            return ERROR(e.code().value(), e.what());
                        }
                    }
                    else {
                        log::rule_engine::debug("Unlinking replica ...");

                        auto dobj_info = util::convert_physical_object_to_dataObjInfo_t(obj);

                        // The replica is not part of a hard link group, so delete it.
                        // The else-block is not making sense to me. It is basically saying that if the first
                        // replica is successfully deleted, remember that success code and do not allow any failures
                        // to be returned back to the client.
                        if (const auto ec = dataObjUnlinkS(&conn, input, &dobj_info); ec < 0) {
                            log::rule_engine::error("Could not unlink replica [error_code={}, data_object={}, replica_number={}]",
                                                    ec, input->objPath, dobj_info.replNum);

                            if (error_code == 0) {
                                error_code = ec;
                            }
                        }
                        else {
                            error_code = 1;
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

        auto pep_api_data_obj_phymv_post(std::list<boost::any>& rule_arguments, irods::callback& effect_handler) -> irods::error
        {
            try {
                auto* input = util::get_input_object_ptr<dataObjInp_t>(rule_arguments);
                auto& conn = *util::get_rei(effect_handler).rsComm;

                if (!fs::server::is_data_object(conn, input->objPath)) {
                    return CODE(RULE_ENGINE_CONTINUE);
                }

                const auto hl_info = util::get_hard_links(conn, input->objPath);

                ix::key_value_proxy kvp{input->condInput};

                auto src_resc = util::resolve_resource(kvp.at(RESC_NAME_KW).value());
                rodsLong_t src_resc_id;
                src_resc->get_property(irods::RESOURCE_ID, src_resc_id);
                log::rule_engine::debug("Source resource id = {}", src_resc_id);

                auto dst_resc = util::resolve_resource(kvp.at(DEST_RESC_NAME_KW).value());
                rodsLong_t dst_resc_id;
                dst_resc->get_property(irods::RESOURCE_ID, dst_resc_id);
                log::rule_engine::debug("Destination resource id = {}", dst_resc_id);

                std::string dst_resource_name;
                dst_resc->get_property(irods::RESOURCE_NAME, dst_resource_name);
                log::rule_engine::debug("Destination resource name = {}", dst_resource_name);

                const auto src_resource_id = std::to_string(src_resc_id);

                if (auto object = util::find_hard_link(hl_info, src_resource_id); object) {
                    const hard_link& hl = object.value();

                    log::rule_engine::debug("Found hard link information [UUID={}, resource_id={}]", hl.uuid, hl.resource_id);

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
                            log::rule_engine::debug("Replica info [replica_number={}, resource_id={}, physical_path={}]",
                                                    r.replica_number, r.resource_id, r.physical_path);
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
                            log::rule_engine::error("Could not update the physical path [error_code={}, data_object={}, replica_number={}]",
                                                    ec, path.c_str(), iter->replica_number);
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
                    log::rule_engine::error("Could not make hard link [error_code={}, physical_path={}, link_name={}]",
                                            ec, info.physical_path, link_name);
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
                        log::rule_engine::debug("Replica already hard linked [replica_number={}, UUID={}, resource_id={}]",
                                                replica_number, uuid, hl.resource_id);
                    }
                }

                if (!already_hard_linked) {
                    uuid = util::generate_new_uuid(conn, info.resource_id);
                    log::rule_engine::debug("Generated new hard link [UUID={}, resource_id={}]", uuid, info.resource_id);
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
                    log::rule_engine::error("{} [error_code={}]", e.what(), e.code().value());
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
            log::rule_engine::error("Hard Links rule engine plugin encountered an unknown error");
            return ERROR(SYS_UNKNOWN_ERROR, "Hard Links rule engine plugin encountered an unknown error");
        }

        log::rule_engine::debug("Rule not supported in rule engine plugin [{}]", rule_name);

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto exec_rule_text_impl(std::string_view rule_text, irods::callback effect_handler) -> irods::error
    {
        log::rule_engine::debug("rule text = {}", rule_text);

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

        log::rule_engine::debug("rule text = {}", std::string{rule_text});

        try {
            const auto json_args = json::parse(rule_text);

            log::rule_engine::debug("json input = {}", json_args.dump());

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
            log::rule_engine::error(e.what());
            return ERROR(USER_INPUT_FORMAT_ERR, e.what());
        }
        catch (const std::exception& e) {
            log::rule_engine::error(e.what());
            return ERROR(SYS_INTERNAL_ERR, e.what());
        }
        catch (...) {
            log::rule_engine::error("Hard Links rule engine plugin encountered an unknown error");
            return ERROR(SYS_UNKNOWN_ERROR, "Hard Links rule engine plugin encountered an unknown error");
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

