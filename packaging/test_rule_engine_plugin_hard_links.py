from __future__ import print_function

import os
import sys
import shutil
import json
import socket

from time import sleep

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

from . import session
from .. import test
from .. import lib
from .. import paths
from ..configuration import IrodsConfig

class Test_Rule_Engine_Plugin_Hard_Links(session.make_sessions_mixin([('otherrods', 'rods')], []), unittest.TestCase):

    def setUp(self):
        super(Test_Rule_Engine_Plugin_Hard_Links, self).setUp()
        self.admin = self.admin_sessions[0]

    def tearDown(self):
        super(Test_Rule_Engine_Plugin_Hard_Links, self).tearDown()

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_irm(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_hard_links_rule_engine_plugin(config)

            # Put a file: foo
            data_object = 'foo'
            file_path = os.path.join(self.admin.local_session_dir, data_object)
            lib.make_file(file_path, 1024, 'arbitrary')
            self.admin.assert_icommand(['iput', file_path])
            data_object = os.path.join(self.admin.session_collection, data_object)

            # Create two hard-links to the data object previously put into iRODS.
            hard_link_a = os.path.join(self.admin.session_collection, 'foo.0')
            self.make_hard_link(data_object, 0, hard_link_a)

            hard_link_b = os.path.join(self.admin.session_collection, 'foo.1')
            self.make_hard_link(data_object, 0, hard_link_b)

            # Verify that all data objects have the same metadata AVUs.
            # Verify that the physical path is the same for each data object.
            uuid = self.get_uuid(data_object)
            resource_id = self.get_resource_id(data_object)
            physical_path = self.get_physical_path(data_object)
            for path in [data_object, hard_link_a, hard_link_b]:
                self.admin.assert_icommand(['ils', '-L', path], 'STDOUT', [physical_path])
                self.admin.assert_icommand(['imeta', 'ls', '-d', path], 'STDOUT', [
                    'attribute: irods::hard_link',
                    'value: {0}'.format(uuid),
                    'units: {0}'.format(resource_id)
                ])

            # Remove all data objects starting with the hard-links.
            count = 3
            for path in [hard_link_b, hard_link_a, data_object]:
                print('HARD LINK COUNT = ' + str(self.hard_link_count(uuid, resource_id)))
                self.assertTrue(self.hard_link_count(uuid, resource_id) == count)
                self.admin.assert_icommand(['irm', '-f', path])
                count -= 1

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_itrim(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_hard_links_rule_engine_plugin(config)

            # Put a file: foo
            data_object = 'foo'
            file_path = os.path.join(self.admin.local_session_dir, data_object)
            lib.make_file(file_path, 1024, 'arbitrary')
            self.admin.assert_icommand(['iput', file_path])
            data_object = os.path.join(self.admin.session_collection, data_object)

            # Create two hard-links to the data object previously put into iRODS.
            hard_link_a = os.path.join(self.admin.session_collection, 'foo.0')
            self.make_hard_link(data_object, 0, hard_link_a)

            hard_link_b = os.path.join(self.admin.session_collection, 'foo.1')
            self.make_hard_link(data_object, 0, hard_link_b)

            # Create new resource.
            vault_name = 'other_resc_vault'
            vault_directory = os.path.join(self.admin.local_session_dir, vault_name)
            os.mkdir(vault_directory)
            vault = socket.gethostname() + ':' + vault_directory
            other_resc = 'otherResc'
            self.admin.assert_icommand(['iadmin', 'mkresc', other_resc, 'unixfilesystem', vault])

            # Replicate the hard-link to the new resource.
            self.admin.assert_icommand(['irepl', '-R', other_resc, hard_link_a])

            # There should now be two physical copies under iRODS. One under the default resource
            # and another under 'otherResc'. Each logical path shares the same UUID. The replica under
            # 'otherResc' has a different units value, in this case, 'otherResc'.

            # Verify that all data objects have the same metadata AVUs.
            # Verify that the physical path is the same for each data object.
            uuid = self.get_uuid(data_object)
            resource_id = self.get_resource_id(data_object)
            physical_path = self.get_physical_path(data_object)
            for path in [data_object, hard_link_a, hard_link_b]:
                self.admin.assert_icommand(['ils', '-L', path], 'STDOUT', [physical_path])
                self.admin.assert_icommand(['imeta', 'ls', '-d', path], 'STDOUT', [
                    'attribute: irods::hard_link',
                    'value: {0}'.format(uuid),
                    'units: {0}'.format(resource_id)
                ])

            # Verify that the replica on 'otherResc' has different metadata.
            other_resource_id = self.get_resource_id(hard_link_a, replica_number=1)
            self.assertTrue(uuid == self.get_uuid(hard_link_a, replica_number=1))
            self.assertFalse(resource_id == other_resource_id)
            self.assertFalse(physical_path == self.get_physical_path(hard_link_a, replica_number=1))

            # Verify the hard-link counts.
            self.assertTrue(hard_link_count(self, uuid, resource_id) == 3)
            self.assertTrue(hard_link_count(self, uuid, other_resource_id) == 1)

            # Trim the replica that is shared between three logical paths.
            self.admin.assert_icommand(['itrim', '-N1', '-n0', hard_link_b])
            self.assertTrue(hard_link_count(self, uuid, resource_id) == 2)
            self.assertTrue(hard_link_count(self, uuid, other_resource_id) == 2)

            # Trim the replica that is shared between two logical paths.
            # This will cause all hard-link metadata to be removed because there are zero replicas
            # being shared between logical paths.
            self.admin.assert_icommand(['itrim', '-N1', '-n0', hard_link_a])
            self.assertTrue(hard_link_count(self, uuid, resource_id) == 0)
            self.assertTrue(hard_link_count(self, uuid, other_resource_id) == 0)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_imv(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_hard_links_rule_engine_plugin(config)

    def enable_hard_links_rule_engine_plugin(self, config):
        config.server_config['plugin_configuration']['rule_engines'].insert(0, {
            'instance_name': 'irods_rule_engine_plugin-hard_links-instance',
            'plugin_name': 'irods_rule_engine_plugin-hard_links',
            'plugin_specific_configuration': {}
        })
        lib.update_json_file_from_dict(config.server_config_path, config.server_config)

    def make_hard_link(self, logical_path, replica_number, link_name):
        hard_link_op = json.dumps({
            'operation': 'hard_links_make_link',
            'logical_path': logical_path,
            'replica_number': replica_number,
            'link_name': link_name
        })
        self.admin.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-hard_links-instance', hard_link_op, 'null', 'ruleExecOut'])

    def get_uuid(self, data_object, replica_number=0):
        gql = "select META_DATA_ATTR_VALUE where COLL_NAME = '{0}' and DATA_NAME = '{1}' and META_DATA_ATTR_NAME = 'irods::hard_link' and DATA_REPL_NUM = '{2}'"
        coll_name = os.path.dirname(data_object)
        data_name = os.path.basename(data_object)
        utf8_query_result_string, ec, rc = self.admin.run_icommand(['iquest', '%s', gql.format(coll_name, data_name, replica_number)])
        return str(utf8_query_result_string)

    def get_resource_id(self, data_object, replica_number=0):
        gql = "select RESC_ID where COLL_NAME = '{0}' and DATA_NAME = '{1}' and META_DATA_ATTR_NAME = 'irods::hard_link' and DATA_REPL_NUM = '{2}'"
        coll_name = os.path.dirname(data_object)
        data_name = os.path.basename(data_object)
        utf8_query_result_string, ec, rc = self.admin.run_icommand(['iquest', '%s', gql.format(coll_name, data_name, replica_number)])
        return str(utf8_query_result_string)

    def get_physical_path(self, data_object, replica_number=0):
        gql = "select DATA_PATH where COLL_NAME = '{0}' and DATA_NAME = '{1}' and META_DATA_ATTR_NAME = 'irods::hard_link' and DATA_REPL_NUM = '{2}'"
        coll_name = os.path.dirname(data_object)
        data_name = os.path.basename(data_object)
        utf8_query_result_string, ec, rc = self.admin.run_icommand(['iquest', '%s', gql.format(coll_name, data_name, replica_number)])
        return str(utf8_query_result_string)

    def hard_link_count(self, uuid, resource_id):
        gql = "select COUNT(DATA_NAME) where META_DATA_ATTR_NAME = 'irods::hard_link' and META_DATA_ATTR_VALUE = '{0}' and RESC_ID = '{1}'"
        utf8_query_result_string, ec, rc = self.admin.run_icommand(['iquest', '%s', gql.format(uuid, resource_id)])
        return int(str(utf8_query_result_string))

