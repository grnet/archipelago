from cluster import *
import os
from shutil import copy2 as copy
import datetime

class TestCluster(Cluster):
    def execute_test(self, ci_dir, packages_dir):
        tests = os.path.join(ci_dir, '../xseg/tools/qa')
        self.inject_file(tests, '/root')
        self.inject_file(packages_dir, '/root')
        cmd = """dpkg -i \
        libxseg0_*_amd64.deb                    \
        libxseg0-dbg_*_amd64.deb                \
        python-xseg_*_amd64.deb                 \
        python-archipelago_*_amd64.deb          \
        archipelago-modules-dkms_*_amd64.deb    \
        archipelago_*_amd64.deb                 \
        archipelago-dbg_*_amd64.deb             \
        archipelago-ganeti_*_amd64.deb"""
        remote_folder = os.path.normpath(packages_dir)
        remote_folder = os.path.basename(remote_folder)
        self.execute_command('cd /root/' + remote_folder + ' ; ' + cmd)
        #self.execute_command('python /root/qa/tests.py -v', verbose=True)
        self.execute_command('python /root/qa/tests.py -v FiledTest', verbose=True)
        self.execute_command('python /root/qa/tests.py -v MapperdTest', verbose=True)
        self.execute_command('python /root/qa/tests.py -v VlmcdTest', verbose=True)
        self.execute_command('archipelago start', verbose=True)
        self.execute_command('python /root/qa/basictest.py', verbose=True)

if __name__ == '__main__':
    now = datetime.datetime.now().strftime('%b-%d-%I%M%p-%G')
    node = 'archipelago-test ' + now
    token = os.environ['TOKEN']
    token = open(token).read().strip()
    packages_dir = os.environ['PACKAGES_DIR']
    image_id = os.environ['IMAGE_ID']
    image_id = open(image_id).read().strip()
    ci_dir = os.path.dirname(os.path.abspath(__file__))
    conffile = os.path.join(ci_dir, 'config')
    tmpfile = '/tmp/tmpconfig_' + now
    copy(conffile, tmpfile)
    conffile = tmpfile

    tc = TestCluster(conffile=conffile, token=token, servers=node, image_id=image_id)
    tc.create()
    tc.execute_test(ci_dir, packages_dir)
    os.unlink(conffile)
    tc.destroy()

