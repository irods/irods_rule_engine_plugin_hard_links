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

admins = [('otherrods', 'rods')]
users  = [('alice', 'rods')]

class Test_Rule_Engine_Plugin_Hard_Links(session.make_sessions_mixin(admins, users), unittest.TestCase):

    def setUp(self):
        super(Test_Rule_Engine_Plugin_Hard_Links, self).setUp()
        self.admin = self.admin_sessions[0]
        self.user = self.user_sessions[0]

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

            # Create two hard links to the data object previously put into iRODS.
            hard_link_a = os.path.join(self.admin.session_collection, 'foo.0')
            self.make_hard_link(data_object, '0', hard_link_a)

            hard_link_b = os.path.join(self.admin.session_collection, 'foo.1')
            self.make_hard_link(data_object, '0', hard_link_b)

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

            # Remove all data objects starting with the hard links.
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

            # Create two hard links to the data object previously put into iRODS.
            hard_link_a = os.path.join(self.admin.session_collection, 'foo.0')
            self.make_hard_link(data_object, '0', hard_link_a)

            hard_link_b = os.path.join(self.admin.session_collection, 'foo.1')
            self.make_hard_link(data_object, '0', hard_link_b)

            # Create new resource.
            vault_name = 'other_resc_vault'
            vault_directory = os.path.join(self.admin.local_session_dir, vault_name)
            os.mkdir(vault_directory)
            vault = socket.gethostname() + ':' + vault_directory
            other_resc = 'otherResc'
            self.admin.assert_icommand(['iadmin', 'mkresc', other_resc, 'unixfilesystem', vault], 'STDOUT', [other_resc])

            # Replicate the hard link to the new resource.
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

            # Verify the hard link counts.
            self.assertTrue(self.hard_link_count(uuid, resource_id) == 3)
            self.assertTrue(self.hard_link_count(uuid, other_resource_id) == 1)

            # Trim the replica that is shared between three logical paths.
            self.admin.assert_icommand(['itrim', '-N1', '-S', self.admin.default_resource, hard_link_b], 'STDOUT', ['trimmed'])
            self.assertTrue(self.hard_link_count(uuid, resource_id) == 2)
            self.assertTrue(self.hard_link_count(uuid, other_resource_id) == 1)

            # Trim the replica that is shared between two logical paths.
            # This will cause all hard link metadata to be removed because there are zero replicas
            # being shared between logical paths.
            self.admin.assert_icommand(['itrim', '-N1', '-S', self.admin.default_resource, hard_link_a], 'STDOUT', ['trimmed'])
            self.assertTrue(self.hard_link_count(uuid, resource_id) == 0)
            self.assertTrue(self.hard_link_count(uuid, other_resource_id) == 0)

            # Verify that the metadata has been removed.
            for path in [data_object, hard_link_a]:
                self.admin.assert_icommand(['imeta', 'ls', '-d', path], 'STDOUT', ['None'])

            # Clean-up.
            self.admin.assert_icommand(['irm', '-f', data_object, hard_link_a])
            self.admin.assert_icommand(['iadmin', 'rmresc', other_resc])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_imv(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_hard_links_rule_engine_plugin(config)

            # Put a file: foo
            # Capture the physical path for verification.
            data_object = 'foo'
            file_path = os.path.join(self.admin.local_session_dir, data_object)
            lib.make_file(file_path, 1024, 'arbitrary')
            self.admin.assert_icommand(['iput', file_path])
            data_object = os.path.join(self.admin.session_collection, data_object)
            data_object_physical_path = self.get_physical_path(data_object)
            self.admin.assert_icommand(['ils', '-L', data_object], 'STDOUT', [data_object_physical_path])

            # Create a hard link to the data object previously put into iRODS.
            # Capture the physical path for verification.
            hard_link = os.path.join(self.admin.session_collection, 'foo.0')
            self.make_hard_link(data_object, '0', hard_link)
            hard_link_physical_path = self.get_physical_path(data_object)
            self.admin.assert_icommand(['ils', '-L', hard_link], 'STDOUT', [hard_link_physical_path])

            # Create new resource.
            vault_name = 'other_resc_vault'
            vault_directory = os.path.join(self.admin.local_session_dir, vault_name)
            os.mkdir(vault_directory)
            vault = socket.gethostname() + ':' + vault_directory
            other_resc = 'otherResc'
            self.admin.assert_icommand(['iadmin', 'mkresc', other_resc, 'unixfilesystem', vault], 'STDOUT', [other_resc])

            # Replicate the data object to the new resource.
            # Capture the physical path for verification.
            self.admin.assert_icommand(['irepl', '-R', other_resc, data_object])
            replica_physical_path = self.get_physical_path(data_object, replica_number=1)
            self.admin.assert_icommand(['ils', '-L', data_object], 'STDOUT', [replica_physical_path])

            # Rename the original data object and show that only the logical path changed.
            # Hard Links never modify the physical path of any data objects.
            new_name = 'bar'
            self.admin.assert_icommand(['imv', data_object, new_name])
            data_object = new_name
            self.admin.assert_icommand(['ils', '-L', data_object], 'STDOUT', [data_object_physical_path, replica_physical_path])
            self.admin.assert_icommand(['ils', '-L', hard_link], 'STDOUT', [data_object_physical_path])

            # Rename the hard link and verify that all data objects point to the same replica.
            new_name = 'baz'
            self.admin.assert_icommand(['imv', hard_link, new_name])
            hard_link = new_name
            self.admin.assert_icommand(['ils', '-L', hard_link], 'STDOUT', [data_object_physical_path])
            self.admin.assert_icommand(['ils', '-L', data_object], 'STDOUT', [data_object_physical_path, replica_physical_path])

            # Move the original data object to a new collection and show that only the logical
            # paths are updated. The physical paths do not change even when moving data objects to
            # different collections.
            collection = 'col.d'
            self.admin.assert_icommand(['imkdir', collection])
            new_name = os.path.join(collection, data_object)
            self.admin.assert_icommand(['imv', data_object, new_name])
            data_object = new_name
            self.admin.assert_icommand(['ils', '-L', data_object], 'STDOUT', [data_object_physical_path, replica_physical_path])
            self.admin.assert_icommand(['ils', '-L', hard_link], 'STDOUT', [data_object_physical_path])

            # Clean-up.
            self.admin.assert_icommand(['irm', '-rf', data_object, hard_link])
            self.admin.assert_icommand(['iadmin', 'rmresc', other_resc])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_moving_data_object_without_hard_links_invokes_existing_behavior(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_hard_links_rule_engine_plugin(config)

            # Put a file: foo
            # Capture the physical path for verification.
            data_object = 'foo'
            file_path = os.path.join(self.admin.local_session_dir, data_object)
            lib.make_file(file_path, 1024, 'arbitrary')
            self.admin.assert_icommand(['iput', file_path])
            data_object = os.path.join(self.admin.session_collection, data_object)
            data_object_physical_path = self.get_physical_path(data_object)

            # Create a new collection.
            collection = os.path.join(self.admin.session_collection, 'test.d')
            self.admin.assert_icommand(['imkdir', collection])

            # Moving the data object under the new collection will cause the physical path to change.
            # This is the default behavior for a unixfilesystem resource.
            new_name = os.path.join(collection, os.path.basename(data_object))
            self.admin.assert_icommand(['imv', data_object, new_name])
            data_object = new_name
            new_data_object_physical_path = self.get_physical_path(data_object)
            self.assertTrue(new_data_object_physical_path != data_object_physical_path)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_renaming_hard_links_maintains_permissions(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_hard_links_rule_engine_plugin(config)

            # Put a file: foo
            data_object = os.path.join(self.admin.session_collection, 'foo')
            contents = 'Did it work!?'
            self.admin.assert_icommand(['istream', 'write', data_object], input=contents)
            self.admin.assert_icommand(['istream', 'read', data_object], 'STDOUT', [contents])

            # Give user permission to read the data object.
            self.admin.assert_icommand(['ichmod', 'read', self.user.username, self.admin.session_collection, data_object])
            expected_permissions = [self.make_perm_string(self.admin, 'own'), self.make_perm_string(self.user, 'read object')]
            self.admin.assert_icommand(['ils', '-A', self.admin.session_collection], 'STDOUT', expected_permissions)
            self.admin.assert_icommand(['ils', '-A', data_object], 'STDOUT', expected_permissions)
            self.user.assert_icommand(['istream', 'read', data_object], 'STDOUT', [contents])

            # Create a hard link to the data object previously put into iRODS.
            # Capture the physical path for verification.
            hard_link = os.path.join(self.admin.session_collection, 'foo.0')
            self.make_hard_link(data_object, '0', hard_link)

            # Simulate the behavior of WinSCP when opening a data object via Vim through NFSRODS.
            # 1. Rename the hard link to the data object's name.
            new_name = data_object + '.old'
            self.admin.assert_icommand(['imv', data_object, new_name])
            self.admin.assert_icommand(['imv', hard_link, data_object])
            # 2. Remove the original data object.
            hard_link = data_object
            data_object = new_name
            self.admin.assert_icommand(['irm', '-f', data_object])
            # 3. Verify that the permissions have been maintained.
            data_object = hard_link
            self.admin.assert_icommand(['ils', '-A', data_object], 'STDOUT', expected_permissions)
            self.admin.assert_icommand(['istream', 'read', data_object], 'STDOUT', [contents])
            self.user.assert_icommand(['istream', 'read', data_object], 'STDOUT', [contents])

    def enable_hard_links_rule_engine_plugin(self, config):
        config.server_config['plugin_configuration']['rule_engines'].insert(0, {
            'instance_name': 'irods_rule_engine_plugin-hard_links-instance',
            'plugin_name': 'irods_rule_engine_plugin-hard_links',
            'plugin_specific_configuration': {}
        })
        lib.update_json_file_from_dict(config.server_config_path, config.server_config)

    def make_hard_link(self, logical_path, replica_number, link_name):
        hard_link_op = json.dumps({
            'operation': 'hard_links_create',
            'logical_path': logical_path,
            'replica_number': replica_number,
            'link_name': link_name
        })
        self.admin.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-hard_links-instance', hard_link_op, 'null', 'ruleExecOut'])

    def make_perm_string(self, user, permission):
        return user.username + '#' + user.zone_name + ':' + permission

    def get_uuid(self, data_object, replica_number=0):
        gql = "select META_DATA_ATTR_VALUE where COLL_NAME = '{0}' and DATA_NAME = '{1}' and META_DATA_ATTR_NAME = 'irods::hard_link' and DATA_REPL_NUM = '{2}'"
        coll_name = os.path.dirname(data_object)
        data_name = os.path.basename(data_object)
        utf8_query_result_string, ec, rc = self.admin.run_icommand(['iquest', '%s', gql.format(coll_name, data_name, replica_number)])
        return str(utf8_query_result_string).strip()

    def get_resource_id(self, data_object, replica_number=0):
        gql = "select RESC_ID where COLL_NAME = '{0}' and DATA_NAME = '{1}' and DATA_REPL_NUM = '{2}'"
        coll_name = os.path.dirname(data_object)
        data_name = os.path.basename(data_object)
        utf8_query_result_string, ec, rc = self.admin.run_icommand(['iquest', '%s', gql.format(coll_name, data_name, replica_number)])
        return str(utf8_query_result_string).strip()

    def get_physical_path(self, data_object, replica_number=0):
        gql = "select DATA_PATH where COLL_NAME = '{0}' and DATA_NAME = '{1}' and DATA_REPL_NUM = '{2}'"
        coll_name = os.path.dirname(data_object)
        data_name = os.path.basename(data_object)
        utf8_query_result_string, ec, rc = self.admin.run_icommand(['iquest', '%s', gql.format(coll_name, data_name, replica_number)])
        return str(utf8_query_result_string).strip()

    def hard_link_count(self, uuid, resource_id):
        gql = "select COUNT(DATA_NAME) where META_DATA_ATTR_NAME = 'irods::hard_link' and META_DATA_ATTR_VALUE = '{0}' and RESC_ID = '{1}'"
        utf8_query_result_string, ec, rc = self.admin.run_icommand(['iquest', '%s', gql.format(uuid, resource_id)])
        return int(str(utf8_query_result_string).strip())

