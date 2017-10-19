# -*- coding: utf-8 -*-

# Import Python libs
from __future__ import absolute_import
import os
import shutil
import stat

# Import Salt Testing libs
from tests.support.case import ShellCase
from tests.integration.utils import testprogram

# Import 3rd-party libs

# Import Salt libs
import salt.utils.files


# all read, only owner write
autosign_file_permissions = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | stat.S_IWUSR


class AutosignGrainsTest(ShellCase, testprogram.TestProgramCase):
    '''
    Test autosigning minions based on grain values.
    '''

    def setUp(self):
        super(ShellCase, self).setUp()

        self.master = testprogram.TestDaemonSaltMaster(
            name='autosign_grains_accept_master',
            parent_dir=self._test_dir,
        )
        # Call setup here to ensure config and script exist
        self.master.setup()
        self.master.run('-d')
        self.master.shutdown(wait_for_orphans=3)

        self.run_key('-d minion -y')
        self.run_call('test.ping -l quiet')  # get minon to try to authenticate itself again

        if 'minion' in self.run_key('-l acc'):
            self.skipTest('Could not deauthorize minion')
        if 'minion' not in self.run_key('-l un'):
            self.skipTest('minion did not try to reauthenticate itself')

        self.autosign_grains_dir = os.path.join(self.master_opts['autosign_grains_dir'])
        if not os.path.isdir(self.autosign_grains_dir):
            os.makedirs(self.autosign_grains_dir)

    def tearDown(self):
        self.run_call('test.ping -l quiet')  # get minon to authenticate itself again

        if os.path.isdir(self.autosign_grains_dir):
            shutil.rmtree(self.autosign_grains_dir)

    def test_autosign_grains_accept(self):
        grain_file_path = os.path.join(self.autosign_grains_dir, 'test_grain')
        with salt.utils.files.fopen(grain_file_path, 'w') as f:
            f.write('#invalid_value\ncheese')
        os.chmod(grain_file_path, autosign_file_permissions)

        self.run_call('test.ping -l quiet')  # get minon to try to authenticate itself again
        self.assertIn('minion', self.run_key('-l acc'))

    def test_autosign_grains_fail(self):
        grain_file_path = os.path.join(self.autosign_grains_dir, 'test_grain')
        with salt.utils.files.fopen(grain_file_path, 'w') as f:
            f.write('#cheese\ninvalid_value')
        os.chmod(grain_file_path, autosign_file_permissions)

        self.run_call('test.ping -l quiet')  # get minon to try to authenticate itself again
        self.assertNotIn('minion', self.run_key('-l acc'))
        self.assertIn('minion', self.run_key('-l un'))
