#!/usr/bin/env python

import os
import sys
import time
import logging
import subprocess
import StringIO
import fabric.api as fabric
from ConfigParser import ConfigParser

from kamaki.clients.astakos import AstakosClient
from kamaki.clients.cyclades import CycladesClient
from kamaki.clients.image import ImageClient

fabric.env.disable_known_hosts = True
fabric.env.shell = "/bin/bash -c"
fabric.env.connection_attempts = 10
#fabric.env.output_prefix = None


#dir = os.path.dirname(os.path.abspath(__file__))
def get_list_items(s):
    l = s.split(',')
    return [ x.strip() for x in l ]

#TODO add support for seperate output file
def _run(cmd):
    """Run fabric"""
    return fabric.run(cmd)

def _red(msg):
    """Red color"""
    return "\x1b[31m" + str(msg) + "\x1b[0m"


def _yellow(msg):
    """Yellow color"""
    return "\x1b[33m" + str(msg) + "\x1b[0m"


def _green(msg):
    """Green color"""
    return "\x1b[32m" + str(msg) + "\x1b[0m"


def _check_fabric(fun):
    """Check if fabric env has been set"""
    def wrapper(self, *args):
        """wrapper function"""
        if not self.fabric_installed:
            self.setup_fabric()
        return fun(self, *args)
    return wrapper

def capture_streams(func):
    myout = StringIO.StringIO()
    myerr = StringIO.StringIO()

    def write_streams(stdout, stderr):
        if stdout:
            f = open(stdout, 'w+')
            f.write(myout.getvalue())
            f.close()
        if stderr:
            f = open(stderr, 'w+')
            f.write(myerr.getvalue())
            f.close()

    def inner(*args, **kwargs):
        stdout = kwargs.pop('stdout', None)
        stderr = kwargs.pop('stderr', None)
        mock = kwargs.pop('mock', True)
        __stdout = sys.stdout
        sys.stdout = myout
        __stderr = sys.stderr
        sys.stderr = myerr
        exc = True
        try:
            ret = func(*args, **kwargs)
            exc = False
        finally:
            write_streams(stdout, stderr)
            sys.stdout = __stdout
            sys.stderr = __stderr
            if not mock or exc:
                print myout.getvalue()
                print myerr.getvalue()
            myout.truncate(0)
            myerr.truncate(0)

        return ret
    return inner

def get_port_from_ip(ip):
    ip = ip.split('.')
    port = 10000 + int(ip[2]) * 256 + int(ip[3])
    return port

class Timeout(Exception):
    timeout = 0
    def __init__(self, timeout):
        self.timeout = timeout

    def __str__(self):
        return "Timed out after %d secs" % self.timeout

class RemoteCommandFailed(Exception):
    cmd = None
    def __init__(self, cmd):
        self.cmd = cmd

    def __str__(self):
        return "Remote command failed: %s" % self.cmd

class RemotePutFailed(Exception):
    local_file = None
    remote_path = None
    def __init__(self, local, remote):
        self.local_file = local
        self.remote_path = remote

    def __str__(self):
        return "Failed to put local file %s to remote path %s" % \
                (self.local_file, self.remote_path)


class _MyFormatter(logging.Formatter):
    """Logging Formatter"""
    def format(self, record):
        format_orig = self._fmt
        if record.levelno == logging.DEBUG:
            self._fmt = "  %(msg)s"
        elif record.levelno == logging.INFO:
            self._fmt = "%(msg)s"
        elif record.levelno == logging.WARNING:
            self._fmt = _yellow("[W] %(msg)s")
        elif record.levelno == logging.ERROR:
            self._fmt = _red("[E] %(msg)s")
        result = super(_MyFormatter, self).format(record)
        self._fmt = format_orig
        return result

class ConfigClient(object):
    logger = None
    config = None

    def __init__(self, conffile=None, **kwargs):
        if self.logger is None:
            ConfigClient.set_logger('ConfigClient')

        if self.config is None:
            ConfigClient.set_config(conffile)

        for arg in kwargs:
            self._write_config('Global', arg, kwargs[arg]) 

    @classmethod
    def set_logger(cls, name):
        """Foo"""
        cls.logger = logging.getLogger(name)
        cls.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(_MyFormatter())
        cls.logger.addHandler(handler)

    @classmethod
    def set_config(cls, conffile):
        """Read config file"""
        if not conffile:
            ci_dir = os.path.dirname(os.path.abspath(__file__))
            cls.conffile = os.path.join(ci_dir, "config")
        else:
            cls.conffile = conffile
        cls.config = ConfigParser()
        cls.config.optionxform = str
        cls.config.read(cls.conffile)

    def _write_config(self, section, option, value):
        """Write changes back to config file"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, option, str(value))
        with open(self.conffile, 'wb') as configfile:
            self.config.write(configfile)

    def _remove_config(self, section, option):
        """Write changes back to config file"""
        if not self.config.has_section(section):
            return
        self.config.remove_option(section, option)
        with open(self.conffile, 'wb') as configfile:
            self.config.write(configfile)


class CloudClient(ConfigClient):
    image_client = None
    cyclades_client = None
    astakos_client = None
    logger = None
    auth_url = None
    token = None
    cyclades_url = None

    def __init__(self, conffile=None):
        ConfigClient.__init__(self, conffile)
        if self.logger is None:
            CloudClient.set_logger('CloudClient')

        if self.auth_url is None:
            CloudClient.set_auth_url()

        if self.token is None:
            CloudClient.set_token()

        if self.astakos_client is None:
            CloudClient.set_astakos_client(self.auth_url, self.token)

        if self.cyclades_url is None:
            CloudClient.set_cyclades_url()

        if self.cyclades_client is None:
            CloudClient.set_cyclades_client(self.cyclades_url, self.token)

        if self.image_client is None:
            CloudClient.set_image_client(self.cyclades_url, self.token)

    @classmethod
    def set_logger(cls, name):
        """Foo"""
        cls.logger = logging.getLogger(name)
        cls.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(_MyFormatter())
        cls.logger.addHandler(handler)

    @classmethod
    def set_auth_url(cls):
        """Foo"""
        cls.logger.info("Setup kamaki client..")
        cls.auth_url = cls.config.get('Global', 'auth_url')
        cls.logger.debug("Authentication URL is %s" % _green(cls.auth_url))

    @classmethod
    def set_cyclades_url(cls):
        """Foo"""
        cls.cyclades_url = \
            cls.astakos_client.get_service_endpoints('compute')['publicURL']
        cls.logger.debug("Cyclades API url is %s" % _green(cls.cyclades_url))

    @classmethod
    def set_token(cls):
        """Foo"""
        cls.token = cls.config.get('Global', 'token')
        cls.logger.debug("Token is %s" % _green(cls.token))

    @classmethod
    def set_astakos_client(cls, auth_url, token):
        """Foo"""
        cls.astakos_client = AstakosClient(auth_url, token)

    @classmethod
    def set_cyclades_client(cls, cyclades_url, token):
        """Foo"""
        cls.cyclades_client = CycladesClient(cyclades_url, token)
        cls.cyclades_client.CONNECTION_RETRY_LIMIT = 2

    @classmethod
    def set_image_client(cls, cyclades_url, token):
        """Foo"""
        image_url = \
            cls.astakos_client.get_service_endpoints('image')['publicURL']
        cls.logger.debug("Images API url is %s" % _green(image_url))
        cls.image_client = ImageClient(cyclades_url, token)
        cls.image_client.CONNECTION_RETRY_LIMIT = 2

    def _wait_transition(self, server_id, new_status):
        """Wait for server to go to new_status"""
        self.logger.debug("Waiting for server to become %s" % new_status)
        timeout = self.config.getint('Global', 'build_timeout')
        sleep_time = 5
        while True:
            server = self.cyclades_client.get_server_details(server_id)
            if server['status'] == new_status:
                return server
            elif timeout < 0:
                self.logger.error(
                    "Waiting for server to become %s timed out" % new_status)
                return None
            time.sleep(sleep_time)

class Server(CloudClient):
    server = None
    config_id = None
    name = None
    flavor_id = None
    image_id = None
    server_id = None
    ipv4 = None
    port = None
    user = None
    passwd = None
    status = None
    packages = None
    install_cmd = None
    update_cmd = None
    files = []

    def __init__(self, config_id):
        CloudClient.__init__(self)
        self.logger = logging.getLogger(config_id)
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(_MyFormatter())
        self.logger.addHandler(handler)

        self.config_id = config_id
        self.__get_flavor_id()
        self.__get_image_id()
        self.__get_name()
        self.__get_packages()
        self.__get_update_cmd()
        self.__get_install_cmd()
        self.__get_files()

        if self.config.has_option(self.config_id, 'server_id'):
            self.server_id = int(self.config.get(self.config_id, 'server_id'))
        if self.config.has_option(self.config_id, 'user'):
            self.user = self.config.get(self.config_id, 'user')
        if self.config.has_option(self.config_id, 'passwd'):
            self.passwd = self.config.get(self.config_id, 'passwd')

        if self.flavor_id is None:
            raise Exception("Flavor id not found for %s" % self.config_id)

        if self.image_id is None:
            raise Exception("Image id not found for %s" % self.config_id)

        if self.server_id is not None:
            server = self.cyclades_client.get_server_details(self.server_id)
            if not server:
                raise Exception("Invalid server id")
            self.update(server)

    def __get_packages(self):
        packages = []
        if self.config.has_option(self.config_id, 'packages'):
            packages += get_list_items(self.config.get(self.config_id, 'packages'))
        if self.config.has_option('Global', 'packages'):
            packages += get_list_items(self.config.get('Global', 'packages'))

        if len(packages) > 0:
            self.packages = packages

    def __get_files(self):
        files = []
        tmp = []
        tmp1 = []
        if self.config.has_option(self.config_id, 'files'):
            tmp1 = get_list_items(self.config.get(self.config_id, 'files'))
            if len(tmp1) > 0 and len(tmp1) % 2 == 0:
                tmp += tmp1
        if self.config.has_option('Global', 'files'):
            tmp1 += get_list_items(self.config.get('Global', 'files'))
            if len(tmp1) > 0 and len(tmp1) % 2 == 0:
                tmp += tmp1

        for i in range(0, len(tmp), 2):
            t = (tmp[i], tmp[i+1])
            files.append(t)

        if len(files) > 0:
            self.files = files

    def __get_flavor_id(self):
        if self.config.has_option(self.config_id, 'flavor_id'):
            self.flavor_id = self.config.get(self.config_id, 'flavor_id')
        elif self.config.has_option('Global', 'flavor_id'):
            self.flavor_id = self.config.get('Global', 'flavor_id')

    def __get_image_id(self):
        if self.config.has_option(self.config_id, 'image_id'):
            self.image_id = self.config.get(self.config_id, 'image_id')
        elif self.config.has_option('Global', 'image_id'):
            self.image_id = self.config.get('Global', 'image_id')

    def __get_name(self):
        if self.config.has_option(self.config_id, 'name'):
            self.name = self.config.get(self.config_id, 'name')
        else:
            self.name = self.config_id

    def __get_update_cmd(self):
        if self.config.has_option(self.config_id, 'update_cmd'):
            self.update_cmd = self.config.get(self.config_id, 'update_cmd')
        elif self.config.has_option('Global', 'update_cmd'):
            self.update_cmd = self.config.get('Global', 'update_cmd')

    def __get_install_cmd(self):
        if self.config.has_option(self.config_id, 'install_cmd'):
            self.install_cmd = self.config.get(self.config_id, 'install_cmd')
        elif self.config.has_option('Global', 'install_cmd'):
            self.install_cmd = self.config.get('Global', 'install_cmd')


    def wait_transition(self, new_status):
        if self.server_id:
            server = self._wait_transition(self.server_id, new_status)
            if server:
                self.update(server)
                return server
        else:
            return False

    def create(self, wait=False):
        if self.status and self.status != "DELETED":
            return False
        self.logger.info("Create a new server..")
        server = self.cyclades_client.create_server(self.name, self.flavor_id,
                                                    self.image_id)
        self.server = server
        self.server_id = server['id']
        self.logger.debug("Server got id %s" % _green(self.server_id))
        self.user = server['metadata']['users']
        self.logger.debug("Server's admin user is %s" % _green(self.user))
        self.passwd= server['adminPass']
        self.logger.debug(
            "Server's admin password is %s" % _green(self.passwd))
        if wait:
            server = self.wait_transition("ACTIVE")
            if not server:
                return False
        return True

    def destroy(self, wait=False):
        if self.server_id is None:
            self.logger.debug("Server %s does not have server_id" %
                    self.config_id)
            return True

        if self.status == "DELETED":
            self.logger.debug("Server %d is marked as DELETED" %
                    self.server_id)
            self.update()
            return True

        self.logger.info("Destoying server with id %s " % self.server_id)
        self.cyclades_client.delete_server(self.server_id)
        if wait:
            return self.wait_transition("DELETED")
        return True

    def update(self, server=None):
        if not server:
            if self.server_id is not None:
                server = self.cyclades_client.get_server_details(self.server_id)
            else:
                raise Exception("Server id is not set")
        try:
            server_ip = server['attachments'][0]['ipv4']
        except:
            server_ip = None
        server_port = 22
        if server_ip and self.config.has_option('Global', 'okeanos_io'):
            io = self.config.getboolean('Global', 'okeanos_io')
            if io:
                server_port = get_port_from_ip(server_ip)
                server_ip = "gate.okeanos.io"

        self.logger.debug("Server's IPv4 is %s" % _green(server_ip))
        self.logger.debug("Server's ssh port is %s" % _green(server_port))
        self.ipv4 = server_ip
        self.port = server_port
        self.status = server['status']
        self.write_config()

    def write_config(self):
        if self.status == "DELETED":
            return self.clear_config()
        if self.server_id:
            self._write_config(self.config_id, 'server_id', self.server_id)
        else:
            self._remove_config(self.config_id, 'server_id')
        if self.user:
            self._write_config(self.config_id, 'user', self.user)
        else:
            self._remove_config(self.config_id, 'user')
        if self.passwd:
            self._write_config(self.config_id, 'passwd', self.passwd)
        else:
            self._remove_config(self.config_id, 'passwd')
        if self.ipv4:
            self._write_config(self.config_id, 'ipv4', self.ipv4)
        else:
            self._remove_config(self.config_id, 'ipv4')
        if self.port:
            self._write_config(self.config_id, 'port', self.port)
        else:
            self._remove_config(self.config_id, 'port')

    def clear_config(self):
        self._remove_config(self.config_id, 'server_id')
        self._remove_config(self.config_id, 'user')
        self._remove_config(self.config_id, 'passwd')
        self._remove_config(self.config_id, 'ipv4')
        self._remove_config(self.config_id, 'port')


    def ping(self, timeout):
        start = time.time()

        while timeout == 0 or time.time() - start < timeout:
            self.logger.info("Pinging host %s(%s)" % \
                    (_green(self.config_id), _green(self.ipv4)))
            cmd = ['ping', '-c', '1', '-w', '20', self.ipv4]
            ping = subprocess.Popen(cmd, shell=False,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
            (stdout, stderr) = ping.communicate()
            ret = ping.wait()
            if ret == 0:
                self.logger.info("Pinging host %s %s" % \
                        (self.config_id, _green("succeeded")))
                return True
            self.logger.info("Pinging host %s failed. %s" % \
                    (self.config_id, _yellow("Retrying")))

        raise Timeout(timeout)

    @capture_streams
    def __execute_command(self, cmd):
        with fabric.settings(host_string=str(self.ipv4), port=self.port,
                user=self.user, password=self.passwd, warn_only=True):
            if not _run(cmd).succeeded:
                raise RemoteCommandFailed(cmd)

    def execute_command(self, cmd, verbose=False):
        host = "%s@%s:%d" % (self.user, self.ipv4, self.port)
        self.logger.info("Executing cmd \"%s\" on host %s " % \
                (_yellow(cmd), _green(host)))
        mock = not verbose
        return self.__execute_command(cmd, mock=mock, stdout='/tmp/cmd_out',
                stderr='/tmp/cmd_err')

    def install_packages(self, packages=None):
        if not packages:
            packages = self.packages

        if not packages:
            return

        self.logger.info("Installing packages \"%s\" on host %s " % \
                (_green(' '.join(packages)), _green(self.config_id)))
        self.execute_command("""
        {0}
        {1} {2}
        """.format(self.update_cmd, self.install_cmd, ' '.join(packages)))

    @capture_streams
    def _inject_file(self, local_file, remote_path):
        with fabric.settings(host_string=str(self.ipv4), port=self.port,
                user=self.user, password=self.passwd, warn_only=True):
            if not fabric.put(local_file, remote_path).succeeded:
                raise RemotePutFailed(local_file, remote_path)

    def inject_file(self, local_file, remote_path, verbose=False):
        self.logger.info("Putting file %s on host %s" %
                         (_yellow(local_file), _green(self.config_id)))
        mock = not verbose
        self._inject_file(local_file, remote_path, mock=mock)

    def inject_files(self):
        for f in self.files:
            self.inject_file(f[0], f[1])

class Cluster(ConfigClient):

    def __init__(self, **kwargs):
        ConfigClient.__init__(self, **kwargs)

        # Setup logger
        self.logger = logging.getLogger('Cluster')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(_MyFormatter())
        self.logger.addHandler(handler)
        self.server_list = self.config.get('Global', 'servers')
        self.server_list = get_list_items(self.server_list)
        self.servers = []
        self.cluster_created = True
        for s in self.server_list:
            server = Server(s)
            if not server.status or server.status == "DELETED":
                self.cluster_created = False
            self.servers.append(server)

        self.destroy_on_error = False
        if self.config.has_option('Global', 'destroy_on_error'):
            self.destroy_on_error = \
                    self.config.getboolean('Global', 'destroy_on_error')

        self.cleanup_servers = False
        if self.config.has_option('Global', 'cleanup_servers'):
            self.cleanup_servers = \
                    self.config.getboolean('Global', 'cleanup_servers')

    def create(self):
        if self.cleanup_servers:
            self.destroy()

        try:
            submitted = []
            for s in self.servers:
                if not s.status or s.status != "ACTIVE":
                    s.create()
                    submitted.append(s)

            self.wait_status(submitted, "ACTIVE")

            for s in self.servers:
                s.ping(100)

            for s in self.servers:
                s.inject_files()

            for s in self.servers:
                s.install_packages()

        except Exception as e:
            if self.destroy_on_error:
                self.destroy()
            raise e
        self.cluster_created = True

    def destroy(self):
        submitted = []
        for s in self.servers:
            s.destroy()
            submitted.append(s)

        self.wait_status(submitted, "DELETED")
        self.cluster_created = False

    def execute_command(self, cmd, verbose=False):
        for s in self.servers:
            s.execute_command(cmd, verbose)

    def inject_file(self, local_file, remote_path, verbose=False):
        for s in self.servers:
            s.inject_file(local_file, remote_path, verbose=verbose)

    def install_packages(self, packages=None):
        for s in self.servers:
            s.install_packages(packages)


    def wait_status(self, servers, status):
        self.logger.debug("Waiting for %d servers to become %s" %
                (len(servers), status ))
        for s in servers:
            if s.wait_transition(status):
                self.logger.debug("Server %d became %s" % (s.server_id, status))
            else:
                return False
        return True

    def get_server(self, name):
        for s in self.servers:
            if s.config_id == name:
                return s
        return None

if __name__ == '__main__':
    c = Cluster()
    c.create()
    c.destroy()

