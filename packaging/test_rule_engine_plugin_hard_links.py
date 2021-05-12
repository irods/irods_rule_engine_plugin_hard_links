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
    def test_creating_a_hard_link_updates_the_mtime_of_the_parent_collection__issue_17(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_hard_links_rule_engine_plugin(config)

            # Create a new data object.
            data_object = os.path.join(self.user.session_collection, 'foo')
            self.user.assert_icommand(['istream', 'write', data_object], input='the data')

            # Capture the current mtime of the parent collection.
            old_mtime = self.get_collection_mtime(self.user.session_collection)

            # Create a hard link.
            hard_link = os.path.join(self.user.session_collection, 'foo.0')
            self.make_hard_link(data_object, '0', hard_link, self.user)

            # Verify that the hard link information is correct.
            hl_info = self.get_hard_link_info(data_object)[0]
            for path in [data_object, hard_link]:
                self.user.assert_icommand(['ils', '-L', path], 'STDOUT', [hl_info['physical_path']])
                self.user.assert_icommand(['imeta', 'ls', '-d', path], 'STDOUT', [
                    'attribute: irods::hard_link',
                    'value: {0}'.format(hl_info['uuid']),
                    'units: {0}'.format(hl_info['resource_id'])
                ])

            # Show that the mtime has changed.
            self.assertNotEqual(old_mtime, self.get_collection_mtime(self.user.session_collection))

            # Clean up.
            self.user.assert_icommand(['irm', '-f', hard_link], 'STDOUT', ['deprecated'])
            self.user.assert_icommand(['irm', '-f', data_object])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_rodsuser_can_remove_hard_linked_replica__issue_28(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_hard_links_rule_engine_plugin(config)

            # Create a new data object.
            data_object = os.path.join(self.user.session_collection, 'foo')
            self.user.assert_icommand(['istream', 'write', data_object], input='the data')

            # Create a hard link.
            hard_link = os.path.join(self.user.session_collection, 'foo.0')
            self.make_hard_link(data_object, '0', hard_link, self.user)

            # Verify that the hard link information is correct.
            hl_info = self.get_hard_link_info(data_object)[0]
            for path in [data_object, hard_link]:
                self.user.assert_icommand(['ils', '-L', path], 'STDOUT', [hl_info['physical_path']])
                self.user.assert_icommand(['imeta', 'ls', '-d', path], 'STDOUT', [
                    'attribute: irods::hard_link',
                    'value: {0}'.format(hl_info['uuid']),
                    'units: {0}'.format(hl_info['resource_id'])
                ])

            # Remove the hard link and show that the hard link metadata has been removed
            # from the original data object as well.
            self.user.assert_icommand(['irm', '-f', hard_link], 'STDOUT', ['deprecated'])
            self.user.assert_icommand(['imeta', 'ls', '-d', data_object], 'STDOUT', ['None'])

            # Remove the original data object.
            self.user.assert_icommand(['irm', '-f', data_object])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_iphymv(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_hard_links_rule_engine_plugin(config)

            # Put a file: foo
            data_object = 'foo'
            file_path = os.path.join(self.admin.local_session_dir, data_object)
            lib.make_file(file_path, 1024, 'arbitrary')
            self.admin.assert_icommand(['iput', file_path])
            data_object = os.path.join(self.admin.session_collection, data_object)

            # Create a hard link to the data object previously put into iRODS.
            hard_link_a = os.path.join(self.admin.session_collection, 'foo.0')
            self.make_hard_link(data_object, '0', hard_link_a)

            # Verify that the hard link information is correct.
            hl_info = self.get_hard_link_info(data_object)[0]
            for path in [data_object, hard_link_a]:
                self.admin.assert_icommand(['ils', '-L', path], 'STDOUT', [hl_info['physical_path']])
                self.admin.assert_icommand(['imeta', 'ls', '-d', path], 'STDOUT', [
                    'attribute: irods::hard_link',
                    'value: {0}'.format(hl_info['uuid']),
                    'units: {0}'.format(hl_info['resource_id'])
                ])

            # Create two new resources. This will be used to verify that the correct replica
            # is being updated following invocation of iphymv.
            resc_0 = 'resc_0'
            self.create_resource(resc_0);

            resc_1 = 'resc_1'
            self.create_resource(resc_1);

            try:
                # Replicate the data object to the new resource.
                self.admin.assert_icommand(['irepl', '-R', resc_0, data_object])

                # Create a hard link to the newly created replica.
                hard_link_b = os.path.join(self.admin.session_collection, 'foo.1')
                self.make_hard_link(data_object, '1', hard_link_b)

                # Verify that the hard link information is correct.
                hl_info = self.get_hard_link_info(hard_link_b)[0]
                for path in [data_object, hard_link_b]:
                    self.admin.assert_icommand(['ils', '-L', path], 'STDOUT', [hl_info['physical_path']])
                    self.admin.assert_icommand(['imeta', 'ls', '-d', path], 'STDOUT', [
                        'attribute: irods::hard_link',
                        'value: {0}'.format(hl_info['uuid']),
                        'units: {0}'.format(hl_info['resource_id'])
                    ])

                # Capture the current replica information. This will be used to verify that moving
                # the physical object to a new resource also updates the hard link information
                # for all data objects in the hard link group.
                original_resource_id_for_replica_0 = self.get_resource_id(hard_link_a)
                original_resource_id_for_replica_1 = self.get_resource_id(hard_link_b)

                original_resource_name_for_replica_0 = self.get_resource_name(hard_link_a)
                original_resource_name_for_replica_1 = self.get_resource_name(hard_link_b)

                # Trigger the real test!
                self.admin.assert_icommand(['iphymv', '-S', resc_0, '-R', resc_1, data_object])

                # Verify that the hard link information was updated correctly.
                # This includes the following values:
                # - resource id
                # - resource name
                # - physical path
                # - hard link information
                resource_id_for_replica_1 = self.get_resource_id(data_object, 1)
                self.assertTrue(original_resource_id_for_replica_1 != resource_id_for_replica_1)
                self.assertTrue(original_resource_id_for_replica_1 != self.get_resource_id(hard_link_b))
                self.assertTrue(original_resource_id_for_replica_0 == self.get_resource_id(hard_link_a))

                resource_name_for_replica_1 = self.get_resource_name(data_object, 1)
                self.assertTrue(original_resource_name_for_replica_1 != resource_name_for_replica_1)
                self.assertTrue(original_resource_name_for_replica_1 != self.get_resource_name(hard_link_b))
                self.assertTrue(original_resource_name_for_replica_0 == self.get_resource_name(hard_link_a))

                # Verify that the hard link information is correct.
                hl_info = self.get_hard_link_info(hard_link_b)[0]
                for path in [data_object, hard_link_b]:
                    self.admin.assert_icommand(['ils', '-L', path], 'STDOUT', [hl_info['physical_path']])
                    self.admin.assert_icommand(['imeta', 'ls', '-d', path], 'STDOUT', [
                        'attribute: irods::hard_link',
                        'value: {0}'.format(hl_info['uuid']),
                        'units: {0}'.format(resource_id_for_replica_1)
                    ])

                for path in [hard_link_b, hard_link_a]:
                    self.admin.assert_icommand(['irm', '-f', path], 'STDOUT', ['deprecated'])

                self.admin.assert_icommand(['irm', '-f', data_object])
            finally:
                self.admin.assert_icommand(['iadmin', 'rmresc', resc_0])
                self.admin.assert_icommand(['iadmin', 'rmresc', resc_1])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_irm_with_single_hard_link_on_a_single_data_object(self):
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
            hl_info = self.get_hard_link_info(data_object)[0]
            for path in [data_object, hard_link_a, hard_link_b]:
                self.admin.assert_icommand(['ils', '-L', path], 'STDOUT', [hl_info['physical_path']])
                self.admin.assert_icommand(['imeta', 'ls', '-d', path], 'STDOUT', [
                    'attribute: irods::hard_link',
                    'value: {0}'.format(hl_info['uuid']),
                    'units: {0}'.format(hl_info['resource_id'])
                ])

            # Remove all data objects starting with the hard links.
            # Verify that the parent collection's mtime is being updated to reflect a
            # change in the collection's contents.
            count = 3
            for path in [hard_link_b, hard_link_a]:
                self.assertTrue(self.hard_link_count(hl_info['uuid'], hl_info['resource_id']) == count)
                collection = os.path.dirname(path)
                old_mtime = self.get_collection_mtime(collection)
                self.admin.assert_icommand(['irm', '-f', path], 'STDOUT', ['deprecated'])
                self.assertNotEqual(old_mtime, self.get_collection_mtime(collection))
                count -= 1

            self.assertTrue(self.hard_link_count(hl_info['uuid'], hl_info['resource_id']) == 0)
            self.admin.assert_icommand(['irm', '-f', data_object])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_irm_with_multiple_hard_links_on_a_single_data_object(self):
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

            # Verify that all data object have the same metadata AVUs.
            # Verify that the physical path is the same for each data object.
            hl_info = self.get_hard_link_info(data_object)
            for path in [data_object, hard_link_a, hard_link_b]:
                self.admin.assert_icommand(['ils', '-L', path], 'STDOUT', [hl_info[0]['physical_path']])
                self.admin.assert_icommand(['imeta', 'ls', '-d', path], 'STDOUT', [
                    'attribute: irods::hard_link',
                    'value: {0}'.format(hl_info[0]['uuid']),
                    'units: {0}'.format(hl_info[0]['resource_id'])
                ])

            # Create new resource.
            other_resc = 'otherResc'
            self.create_resource(other_resc)

            try:
                # Replicate the data object to the new resource.
                self.admin.assert_icommand(['irepl', '-R', other_resc, data_object])

                # Create a third hard link that references the new replica.
                hard_link_c = os.path.join(self.admin.session_collection, 'bar')
                self.make_hard_link(data_object, '1', hard_link_c)

                # Verify that the new hard link and the original data object represent
                # proper hard links.
                other_hl_info = self.get_hard_link_info(hard_link_c)[0]
                self.admin.assert_icommand(['ils', '-L', data_object], 'STDOUT', [other_hl_info['physical_path']])
                self.admin.assert_icommand(['imeta', 'ls', '-d', data_object], 'STDOUT', [
                    'attribute: irods::hard_link',
                    'value: {0}'.format(other_hl_info['uuid']),
                    'units: {0}'.format(other_hl_info['resource_id'])
                ])

                # Remove the latest hard link and verify that the original data object
                # is still part of the hard link group containing the first two hard links.
                self.admin.assert_icommand(['irm', '-f', hard_link_c], 'STDOUT', ['deprecated'])

                hl_info = self.get_hard_link_info(data_object)[0]
                for path in [data_object, hard_link_a, hard_link_b]:
                    self.admin.assert_icommand(['ils', '-L', path], 'STDOUT', [hl_info['physical_path']])
                    self.admin.assert_icommand(['imeta', 'ls', '-d', path], 'STDOUT', [
                        'attribute: irods::hard_link',
                        'value: {0}'.format(hl_info['uuid']),
                        'units: {0}'.format(hl_info['resource_id'])
                    ])

                # Remove all data objects starting with the hard links.
                count = 3
                for path in [hard_link_b, hard_link_a]:
                    self.assertTrue(self.hard_link_count(hl_info['uuid'], hl_info['resource_id']) == count)
                    self.admin.assert_icommand(['irm', '-f', path], 'STDOUT', ['deprecated'])
                    count -= 1

                self.assertTrue(self.hard_link_count(hl_info['uuid'], hl_info['resource_id']) == 0)
                self.admin.assert_icommand(['irm', '-f', data_object])
            finally:
                self.admin.assert_icommand(['iadmin', 'rmresc', other_resc])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_itrim_with_multiple_hard_links_on_a_single_data_object(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_hard_links_rule_engine_plugin(config)

            # Create two additional resources.
            # These will be used to create the W-case.
            resc_0 = 'resc_0'
            self.create_resource(resc_0)

            resc_1 = 'resc_1'
            self.create_resource(resc_1)

            try:
                # Put a file: foo [on demoResc]
                data_object = 'foo'
                file_path = os.path.join(self.admin.local_session_dir, data_object)
                lib.make_file(file_path, 1024, 'arbitrary')
                self.admin.assert_icommand(['iput', file_path])
                data_object = os.path.join(self.admin.session_collection, data_object)

                # Replicate the data object to the other resources.
                for r in [resc_0, resc_1]:
                    self.admin.assert_icommand(['irepl', '-R', r, data_object])

                # Create hard links to the new replicas.
                hard_link_a = os.path.join(self.admin.session_collection, 'foo.0')
                self.make_hard_link(data_object, '1', hard_link_a)

                hard_link_b = os.path.join(self.admin.session_collection, 'foo.1')
                self.make_hard_link(data_object, '2', hard_link_b)

                self.admin.assert_icommand(['ils', '-L'], 'STDOUT', [' '])

                # Verify the hard link metadata AVUs and physical paths are correct.
                hl_info_a = self.get_hard_link_info(hard_link_a)[0]
                hl_info_b = self.get_hard_link_info(hard_link_b)[0]
                for hl_info in [hl_info_a, hl_info_b]:
                    self.admin.assert_icommand(['ils', '-L', data_object], 'STDOUT', [hl_info['physical_path']])
                    self.admin.assert_icommand(['imeta', 'ls', '-d', data_object], 'STDOUT', [
                        'attribute: irods::hard_link',
                        'value: {0}'.format(hl_info['uuid']),
                        'units: {0}'.format(hl_info['resource_id'])
                    ])

                # There should now be three physical copies under iRODS. One under the
                # default resourc eand two more under "resc_0" and "resc_1". All replicas
                # except the one on "demoResc" are hard linked.

                # Trim the replicas down to a count of one. The only replica left should
                # be the one on "demoResc". This shows that the plugin maintains support
                # for trimming multiple replicas. In this case, the replicas were unregisterd
                # instead of being unlinked.
                self.admin.assert_icommand(['itrim', '-N1', '-n1', data_object], 'STDOUT', ['trimmed'])
                self.admin.assert_icommand(['itrim', '-N1', '-n2', data_object], 'STDOUT', ['trimmed'])
                self.admin.assert_icommand(['ils', '-L'], 'STDOUT', [' '])

                # Verify that the metadata has been removed.
                for path in [data_object, hard_link_a, hard_link_b]:
                    self.admin.assert_icommand(['imeta', 'ls', '-d', path], 'STDOUT', ['None'])

                # Clean-up.
                for path in [data_object, hard_link_a, hard_link_b]:
                    self.admin.assert_icommand(['irm', '-f', path])
            finally:
                self.admin.assert_icommand(['iadmin', 'rmresc', resc_0])
                self.admin.assert_icommand(['iadmin', 'rmresc', resc_1])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_itrim_returns_deprecation_message_when_minimum_number_of_replicas_to_keep_is_specified(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_hard_links_rule_engine_plugin(config)

            # Put a file: foo
            data_object = 'foo'
            file_path = os.path.join(self.admin.local_session_dir, data_object)
            lib.make_file(file_path, 1024, 'arbitrary')
            self.admin.assert_icommand(['iput', file_path])
            data_object = os.path.join(self.admin.session_collection, data_object)

            # Create a hard link to the data object previously put into iRODS.
            hard_link_a = os.path.join(self.admin.session_collection, 'foo.0')
            self.make_hard_link(data_object, '0', hard_link_a)

            # Trigger the deprecation message.
            self.admin.assert_icommand(['itrim', '-N2', data_object], 'STDOUT', ['Specifying a minimum number of replicas to keep is deprecated.'])

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
            hard_link = os.path.join(self.admin.session_collection, 'foo.0')
            self.make_hard_link(data_object, '0', hard_link)

            # Capture the physical path of the hard link for verification.
            hard_link_physical_path = self.get_physical_path(data_object)
            self.admin.assert_icommand(['ils', '-L', hard_link], 'STDOUT', [hard_link_physical_path])

            # Create new resource.
            other_resc = 'otherResc'
            self.create_resource(other_resc)

            try:
                # Replicate the data object to the new resource.
                # Capture the physical path for verification.
                self.admin.assert_icommand(['irepl', '-R', other_resc, data_object])
                replica_physical_path = self.get_physical_path(data_object, replica_number=1)
                self.admin.assert_icommand(['ils', '-L', data_object], 'STDOUT', [replica_physical_path])

                # Capture the mtime of the parent collection.
                # This will be used to show that renaming a data object causes the mtime of parent
                # collection to be updated.
                parent_collection = os.path.dirname(data_object)
                old_mtime = self.get_collection_mtime(parent_collection)

                # Rename the original data object and show that only the logical path changed.
                # Hard Links never modify the physical path of any data objects.
                new_name = 'bar'
                self.admin.assert_icommand(['imv', data_object, new_name])
                data_object = new_name
                self.admin.assert_icommand(['ils', '-L', data_object], 'STDOUT', [data_object_physical_path, replica_physical_path])
                self.admin.assert_icommand(['ils', '-L', hard_link], 'STDOUT', [data_object_physical_path])

                # Show that the mtime of the parent collection has been updated.
                new_mtime = self.get_collection_mtime(parent_collection)
                self.assertNotEqual(old_mtime, new_mtime)

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
            finally:
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
            self.admin.assert_icommand(['irm', '-f', data_object], 'STDOUT', ['deprecated'])
            # 3. Verify that the permissions have been maintained.
            data_object = hard_link
            self.admin.assert_icommand(['ils', '-A', data_object], 'STDOUT', expected_permissions)
            self.admin.assert_icommand(['istream', 'read', data_object], 'STDOUT', [contents])
            self.user.assert_icommand(['istream', 'read', data_object], 'STDOUT', [contents])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_post_peps_are_triggered_after_manipulating_hard_links(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_hard_links_rule_engine_plugin(config)

            # Put a file into iRODS.
            data_object = os.path.join(self.admin.session_collection, 'foo')
            contents = 'Did it work!?'
            self.admin.assert_icommand(['istream', 'write', data_object], input=contents)
            self.admin.assert_icommand(['istream', 'read', data_object], 'STDOUT', [contents])

            # Create a hard link to the data object previously put into iRODS.
            hard_link = os.path.join(self.admin.session_collection, 'foo.0')
            self.make_hard_link(data_object, '0', hard_link)

            core_re_path = os.path.join(config.core_re_directory, 'core.re')

            with lib.file_backed_up(core_re_path):
                # The metadata to attach to the data object. Used to determine if the test was successful.
                key = 'post_pep_attr_name'
                value = 'IT WORKED!'

                # Add a post PEP that attaches metadata to the original data object.
                with open(core_re_path, 'a') as core_re:
                    core_re.write('''
                        pep_api_data_obj_unlink_post(*INSTANCE_NAME, *COMM, *DATAOBJINP) {{
                            *kvp.'{key}' = '{value}';
                            msiSetKeyValuePairsToObj(*kvp, '{data_object}', '-d');
                        }}
                    '''.format(**locals()))

                # Trigger the post PEP and verify that a new AVU exists on the data object.
                self.admin.assert_icommand(['irm', '-f', hard_link])
                self.admin.assert_icommand(['imeta', 'ls', '-d', data_object], 'STDOUT', [
                    'attribute: {0}'.format(key),
                    'value: {0}'.format(value)
                ])

    def enable_hard_links_rule_engine_plugin(self, config):
        config.server_config['plugin_configuration']['rule_engines'].insert(0, {
            'instance_name': 'irods_rule_engine_plugin-hard_links-instance',
            'plugin_name': 'irods_rule_engine_plugin-hard_links',
            'plugin_specific_configuration': {}
        })
        lib.update_json_file_from_dict(config.server_config_path, config.server_config)

    def make_hard_link(self, logical_path, replica_number, link_name, session=None):
        hard_link_op = json.dumps({
            'operation': 'hard_links_create',
            'logical_path': logical_path,
            'replica_number': replica_number,
            'link_name': link_name
        })
        session = self.admin if session == None else session
        session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-hard_links-instance', hard_link_op, 'null', 'ruleExecOut'])

    def make_perm_string(self, user, permission):
        return user.username + '#' + user.zone_name + ':' + permission

    def get_hard_link_info(self, data_object):
        gql = "select META_DATA_ATTR_VALUE, META_DATA_ATTR_UNITS, DATA_REPL_NUM, DATA_PATH where COLL_NAME = '{0}' and DATA_NAME = '{1}' and META_DATA_ATTR_NAME = 'irods::hard_link'"
        coll_name = os.path.dirname(data_object)
        data_name = os.path.basename(data_object)
        utf8_stdout, stderr, ec = self.admin.run_icommand(['iquest', '%s,%s,%s,%s', gql.format(coll_name, data_name)])

        self.assertTrue(0 == len(stderr))
        self.assertTrue(0 == ec)

        rows = []
        for row in str(utf8_stdout).strip().split('\n'):
            columns = row.split(',')
            rows.append({
                'uuid': columns[0],
                'resource_id': columns[1],
                'replica_number': columns[2],
                'physical_path': columns[3]
            })

        return rows

    def get_uuid(self, data_object, replica_number=0):
        gql = "select META_DATA_ATTR_VALUE where COLL_NAME = '{0}' and DATA_NAME = '{1}' and META_DATA_ATTR_NAME = 'irods::hard_link' and DATA_REPL_NUM = '{2}'"
        coll_name = os.path.dirname(data_object)
        data_name = os.path.basename(data_object)
        utf8_stdout, stderr, ec = self.admin.run_icommand(['iquest', '%s', gql.format(coll_name, data_name, replica_number)])
        self.assertTrue(0 == len(stderr))
        self.assertTrue(0 == ec)
        return str(utf8_stdout).strip()

    def get_resource_id(self, data_object, replica_number=0):
        gql = "select RESC_ID where COLL_NAME = '{0}' and DATA_NAME = '{1}' and DATA_REPL_NUM = '{2}'"
        coll_name = os.path.dirname(data_object)
        data_name = os.path.basename(data_object)
        utf8_stdout, stderr, ec = self.admin.run_icommand(['iquest', '%s', gql.format(coll_name, data_name, replica_number)])
        self.assertTrue(0 == len(stderr))
        self.assertTrue(0 == ec)
        return str(utf8_stdout).strip()

    def get_resource_name(self, data_object, replica_number=0):
        gql = "select RESC_NAME where COLL_NAME = '{0}' and DATA_NAME = '{1}' and DATA_REPL_NUM = '{2}'"
        coll_name = os.path.dirname(data_object)
        data_name = os.path.basename(data_object)
        utf8_stdout, stderr, ec = self.admin.run_icommand(['iquest', '%s', gql.format(coll_name, data_name, replica_number)])
        self.assertTrue(0 == len(stderr))
        self.assertTrue(0 == ec)
        return str(utf8_stdout).strip()

    def get_physical_path(self, data_object, replica_number=0):
        gql = "select DATA_PATH where COLL_NAME = '{0}' and DATA_NAME = '{1}' and DATA_REPL_NUM = '{2}'"
        coll_name = os.path.dirname(data_object)
        data_name = os.path.basename(data_object)
        utf8_stdout, stderr, ec = self.admin.run_icommand(['iquest', '%s', gql.format(coll_name, data_name, replica_number)])
        self.assertTrue(0 == len(stderr))
        self.assertTrue(0 == ec)
        return str(utf8_stdout).strip()

    def get_collection_mtime(self, collection):
        gql = "select COLL_MODIFY_TIME where COLL_NAME = '{0}'"
        utf8_stdout, stderr, ec = self.admin.run_icommand(['iquest', '%s', gql.format(collection)])
        self.assertTrue(0 == len(stderr))
        self.assertTrue(0 == ec)
        return str(utf8_stdout).strip()

    def hard_link_count(self, uuid, resource_id):
        gql = "select COUNT(DATA_NAME) where META_DATA_ATTR_NAME = 'irods::hard_link' and META_DATA_ATTR_VALUE = '{0}' and RESC_ID = '{1}'"
        utf8_stdout, stderr, ec = self.admin.run_icommand(['iquest', '%s', gql.format(uuid, resource_id)])
        self.assertTrue(0 == len(stderr))
        self.assertTrue(0 == ec)
        return int(str(utf8_stdout).strip())

    def create_resource(self, resource_name):
        vault_name = resource_name + '_vault'
        vault_directory = os.path.join(self.admin.local_session_dir, vault_name)
        if not os.path.exists(vault_directory):
            os.mkdir(vault_directory)
        vault = socket.gethostname() + ':' + vault_directory
        self.admin.assert_icommand(['iadmin', 'mkresc', resource_name, 'unixfilesystem', vault], 'STDOUT', [resource_name])

