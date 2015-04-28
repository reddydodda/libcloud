# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import with_statement

import re
import os
import socket
import time
import platform
import subprocess
import mimetypes
import signal

from os.path import join as pjoin
from collections import defaultdict

try:
    from lxml import etree as ET
except ImportError:
    from xml.etree import ElementTree as ET

from libcloud.compute.base import NodeDriver, Node
from libcloud.compute.base import NodeState
from libcloud.compute.types import Provider
from libcloud.utils.networking import is_public_subnet

try:
    import libvirt
    have_libvirt = True
except ImportError:
    raise RuntimeError('Libvirt driver requires \'libvirt\' Python ' +
                               'package')
# increase default timeout for libvirt connection
libvirt_connection_timeout = 2*60

class LibvirtNodeDriver(NodeDriver):
    """
    Libvirt (http://libvirt.org/) node driver.

    To enable debug mode, set LIBVIR_DEBUG environment variable.
    """

    type = Provider.LIBVIRT
    name = 'Libvirt'
    website = 'http://libvirt.org/'

    NODE_STATE_MAP = {
        0: NodeState.TERMINATED,  # no state
        1: NodeState.RUNNING,  # domain is running
        2: NodeState.PENDING,  # domain is blocked on resource
        3: NodeState.TERMINATED,  # domain is paused by user
        4: NodeState.TERMINATED,  # domain is being shut down
        5: NodeState.TERMINATED,  # domain is shut off
        6: NodeState.UNKNOWN,  # domain is crashed
        7: NodeState.UNKNOWN,  # domain is suspended by guest power management
    }

    def timeout_handler(self, sig_code, frame):
        if 14 == sig_code:
            raise Exception('Timeout!')


    def __init__(self, host, user='root', ssh_key=None, ssh_port=22):
        """Support the three ways to connect: local system, qemu+tcp, qemu+ssh
        Host can be an ip address or hostname
        ssh key should be a filename with the private key
        """

        if host in ['localhost', '127.0.0.1']:
            # local connection
            uri = 'qemu:///system'
        else:
            if ssh_key:
                # ssh connection
                uri = 'qemu+ssh://%s@%s:%s/system?keyfile=%s&no_tty=1&no_verify=1' % (user, host, ssh_port, ssh_key)
            else:
                #tcp connection
                uri = 'qemu+tcp://%s:5000/system' % host

        self._uri = uri
        self.secret = ssh_key
        self.key = user
        self.host = host
        try:
            signal.signal(signal.SIGALRM, self.timeout_handler)
            signal.alarm(libvirt_connection_timeout)
            self.connection = libvirt.open(uri)
            signal.alarm(0)      # Disable the alarm
        except Exception as exc:
            signal.alarm(0)      # Disable the alarm
            if 'Could not resolve' in exc.message:
                raise Exception("Make sure hostname is accessible")
            if 'Connection refused' in exc.message:
                raise Exception("Make sure hostname is accessible and libvirt is running")
            if 'Permission denied' in exc.message:
                raise Exception("Make sure ssh key and username are valid")
            if 'End of file while reading data' in exc.message:
                raise Exception("Make sure libvirt is running and user %s is authorised to connect" % user)
            raise Exception("Connection error")

    def list_nodes(self, show_hypervisor=True):
        # active domains
        domain_ids = self.connection.listDomainsID()
        domains = [self.connection.lookupByID(id) for id in domain_ids]
        # non active domains
        inactive_domains = map(self.connection.lookupByName, self.connection.listDefinedDomains())
        domains.extend(inactive_domains)

        # get the arp table of the hypervisor. Try to connect with provided
        # ssh key and paramiko

        # libvirt does not know the ip addresses of guest vms. One way to
        # get this info is by getting the arp table and providing it to the
        # libvirt connection. Then we can check what ip address each MAC
        # address has
        self.arp_table = {}
        if self.secret:
            try:
                import paramiko
                ssh=paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                ssh.connect(self.host, username=self.key, key_filename=self.secret,
                            timeout=None, allow_agent=False, look_for_keys=False)
                stdin,stdout,stderr = ssh.exec_command("arp -an")
                output = stdout.read()
                ssh.close()
                self.arp_table = self._parse_arp_table(output)
            except:
                pass
        else:
            cmd = ['arp', '-an']
            child = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
            stdout, _ = child.communicate()
            self.arp_table = self._parse_arp_table(arp_output=stdout)



        nodes = [self._to_node(domain) for domain in domains]

        if show_hypervisor:
            # append hypervisor as well
            name = self.connection.getHostname()
            try:
                public_ip = socket.gethostbyname(self.host)
            except:
                public_ip = self.host

            extra = {'tags': {'type': 'hypervisor'}}
            node = Node(id=self.host, name=name, state=0,
                    public_ips=[public_ip], private_ips=[], driver=self,
                    extra=extra)
            nodes.append(node)

        return nodes

    def _to_node(self, domain):
        state, max_mem, memory, vcpu_count, used_cpu_time = domain.info()
        state = self.NODE_STATE_MAP.get(state, NodeState.UNKNOWN)

        public_ips, private_ips = [], []

        ip_addresses = self._get_ip_addresses_for_domain(domain)

        for ip_address in ip_addresses:
            if is_public_subnet(ip_address):
                public_ips.append(ip_address)
            else:
                private_ips.append(ip_address)
        try:
            # this will work only if real name is given to a guest VM's name.
            public_ip = socket.gethostbyname(domain.name())
        except:
            public_ip = ''
        if public_ip and public_ip not in ip_addresses:
            # avoid duplicate insertion in public ips
            public_ips.append(public_ip)


        extra = {'uuid': domain.UUIDString(), 'os_type': domain.OSType(),
                 'types': self.connection.getType(),
                 'hypervisor_name': self.connection.getHostname(),
                 'used_memory': memory / 1024, 'vcpu_count': vcpu_count,
                 'used_cpu_time': used_cpu_time}

        node = Node(id=domain.UUIDString(), name=domain.name(), state=state,
                    public_ips=public_ips, private_ips=private_ips,
                    driver=self, extra=extra)
        node._uuid = domain.UUIDString()  # we want to use a custom UUID
        return node

    def _get_ip_addresses_for_domain(self, domain):
        """
        Retrieve IP addresses for the provided domain.

        Note: This functionality is currently only supported on Linux and
        only works if this code is run on the same machine as the VMs run
        on.

        :return: IP addresses for the provided domain.
        :rtype: ``list``
        """
        result = []
        if platform.system() != 'Linux':
            # Only Linux is supported atm
            return result

        mac_addresses = self._get_mac_addresses_for_domain(domain=domain)

        for mac_address in mac_addresses:
            if mac_address in self.arp_table:
                ip_addresses = self.arp_table[mac_address]
                result.extend(ip_addresses)

        return result

    def _get_mac_addresses_for_domain(self, domain):
        """
        Parses network interface MAC addresses from the provided domain.
        """
        xml = domain.XMLDesc()
        etree = ET.XML(xml)
        elems = etree.findall("devices/interface/mac")

        result = []
        for elem in elems:
            mac_address = elem.get('address')
            result.append(mac_address)

        return result

    def list_sizes(self):
        return []

    def list_locations(self):
        return []

    def list_images(self):
        return []

    def reboot_node(self, node):
        domain = self._get_domain_for_node(node=node)
        return domain.reboot(flags=0) == 0

    def destroy_node(self, node):
        domain = self._get_domain_for_node(node=node)
        return domain.destroy() == 0

    def ex_start_node(self, node):
        """
        Start a stopped node.

        :param  node: Node which should be used
        :type   node: :class:`Node`

        :rtype: ``bool``
        """
        domain = self._get_domain_for_node(node=node)
        return domain.create() == 0

    def ex_stop_node(self, node):
        """
        Shutdown a running node.

        Note: Usually this will result in sending an ACPI event to the node.

        :param  node: Node which should be used
        :type   node: :class:`Node`

        :rtype: ``bool``
        """
        domain = self._get_domain_for_node(node=node)
        return domain.shutdown() == 0

    def ex_suspend_node(self, node):
        """
        Suspend a running node.

        :param  node: Node which should be used
        :type   node: :class:`Node`

        :rtype: ``bool``
        """
        domain = self._get_domain_for_node(node=node)
        return domain.suspend() == 0

    def ex_resume_node(self, node):
        """
        Resume a suspended node.

        :param  node: Node which should be used
        :type   node: :class:`Node`

        :rtype: ``bool``
        """
        domain = self._get_domain_for_node(node=node)
        return domain.resume() == 0

    def ex_take_node_screenshot(self, node, directory, screen=0):
        """
        Take a screenshot of a monitoring of a running instance.

        :param node: Node to take the screenshot of.
        :type node: :class:`libcloud.compute.base.Node`

        :param directory: Path where the screenshot will be saved.
        :type directory: ``str``

        :param screen: ID of the monitor to take the screenshot of.
        :type screen: ``int``

        :return: Full path where the screenshot has been saved.
        :rtype: ``str``
        """
        if not os.path.exists(directory) or not os.path.isdir(directory):
            raise ValueError('Invalid value for directory argument')

        domain = self._get_domain_for_node(node=node)
        stream = self.connection.newStream()
        mime_type = domain.screenshot(stream=stream, screen=0)
        extensions = mimetypes.guess_all_extensions(type=mime_type)

        if extensions:
            extension = extensions[0]
        else:
            extension = '.png'

        name = 'screenshot-%s%s' % (int(time.time()), extension)
        file_path = pjoin(directory, name)

        with open(file_path, 'wb') as fp:
            def write(stream, buf, opaque):
                fp.write(buf)

            stream.recvAll(write, None)

        try:
            stream.finish()
        except Exception:
            # Finish is not supported by all backends
            pass

        return file_path

    def ex_get_hypervisor_hostname(self):
        """
        Return a system hostname on which the hypervisor is running.
        """
        hostname = self.connection.getHostname()
        return hostname

    def ex_get_hypervisor_sysinfo(self):
        """
        Retrieve hypervisor system information.

        :rtype: ``dict``
        """
        xml = self.connection.getSysinfo()
        etree = ET.XML(xml)

        attributes = ['bios', 'system', 'processor', 'memory_device']

        sysinfo = {}
        for attribute in attributes:
            element = etree.find(attribute)
            entries = self._get_entries(element=element)
            sysinfo[attribute] = entries

        return sysinfo

    def _get_domain_for_node(self, node):
        """
        Return libvirt domain object for the provided node.
        """
        domain = self.connection.lookupByUUIDString(node.uuid)
        return domain

    def _get_entries(self, element):
        """
        Parse entries dictionary.

        :rtype: ``dict``
        """
        elements = element.findall('entry')

        result = {}
        for element in elements:
            name = element.get('name')
            value = element.text
            result[name] = value

        return result

    def _parse_arp_table(self, arp_output):
        """
        Parse arp command output and return a dictionary which maps mac address
        to an IP address.

        :return: Dictionary which maps mac address to IP address.
        :rtype: ``dict``
        """
        lines = arp_output.split('\n')

        arp_table = defaultdict(list)
        for line in lines:
            match = re.match('.*?\((.*?)\) at (.*?)\s+', line)

            if not match:
                continue

            groups = match.groups()
            ip_address = groups[0]
            mac_address = groups[1]
            arp_table[mac_address].append(ip_address)

        return arp_table

    def disconnect(self):
        # closes connection to the hypevisor
        try:
            self.connection.close()
        except:
            pass

    def __del__(self):
        self.disconnect()
