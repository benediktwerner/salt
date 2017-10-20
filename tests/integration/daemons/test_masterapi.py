# -*- coding: utf-8 -*-

# Import Python libs
from __future__ import absolute_import
import os
import shutil
import stat
import time

# Import Salt Testing libs
from tests.support.case import ShellCase
from tests.support.paths import TMP
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
        self.autosign_grains_dir = os.path.join(TMP, 'autosign_grains_dir')
        if not os.path.isdir(self.autosign_grains_dir):
            os.makedirs(self.autosign_grains_dir)

        self.master = testprogram.TestDaemonSaltMaster(
            name='autosign_grains_master',
            configs={'master': {'map': {'autosign_grains_dir': self.autosign_grains_dir}}},
            parent_dir=self._test_dir,
        )
        self.master.setup()
        _, status = self.master.run(args=['-d'], with_retcode=True)
        if status != 0:
            self.skipTest("Failed to start master daemon")

        self.minion = testprogram.TestDaemonSaltMinion(
            name='autosign_grains_minion',
            configs={'minion': {'map': {
                'autosign_grains': ['test_grain'],
                'grains': {'test_grain': 'test_value'}
            }}},
            parent_dir=self._test_dir,
        )
        self.minion.setup()
        _, status = self.minion.run(args=['-d'], with_retcode=True)
        if status != 0:
            self.skipTest("Failed to start minion daemon")

        time.sleep(10)
        self.master_conf_dir = self.master.abs_path(self.master.config_dir)
        print(self.run_script('salt-key', '-c {} -L'.format(self.master_conf_dir)))

    def tearDown(self):
        self.master.shutdown()
        self.minion.shutdown()
        if os.path.isdir(self.autosign_grains_dir):
            shutil.rmtree(self.autosign_grains_dir)
        super(ShellCase, self).tearDown()

    def test_autosign_grains_accept(self):
        grain_file_path = os.path.join(self.autosign_grains_dir, 'test_grain')
        with salt.utils.files.fopen(grain_file_path, 'w') as f:
            f.write('#invalid_value\ntest_value')
        os.chmod(grain_file_path, autosign_file_permissions)

        self.run_call('test.ping -l quiet')  # get minon to try to authenticate itself again
        accepted = self.run_script('salt-key', '-c {} -l acc'.format(self.master_conf_dir))
        print('accepted:', accepted)
        self.assertIn('minion', accepted)
        pending = self.run_script('salt-key', '-c {} -l un'.format(self.master_conf_dir))
        print('pending:', pending)
        self.assertNotIn('minion', pending)

    def test_autosign_grains_fail(self):
        grain_file_path = os.path.join(self.autosign_grains_dir, 'test_grain')
        with salt.utils.files.fopen(grain_file_path, 'w') as f:
            f.write('#test_value\ninvalid_value')
        os.chmod(grain_file_path, autosign_file_permissions)

        self.run_call('test.ping -l quiet')  # get minon to try to authenticate itself again
        accepted = self.run_script('salt-key', '-c {} -l acc'.format(self.master_conf_dir))
        print('accepted:', accepted)
        self.assertNotIn('minion', accepted)
        pending = self.run_script('salt-key', '-c {} -l un'.format(self.master_conf_dir))
        print('pending:', pending)
        self.assertIn('minion', pending)
