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
import shlex
import socket
import time
import platform
import subprocess
import mimetypes
import signal
import paramiko

from os.path import join as pjoin
from collections import defaultdict

try:
    from lxml import etree as ET
except ImportError:
    from xml.etree import ElementTree as ET

from libcloud.compute.base import NodeDriver, Node, NodeImage, NodeSize
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
        self.ssh_port = ssh_port
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
        cmd = "arp -an"
        self.arp_table = self._parse_arp_table(self.run_command(cmd))

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
                 'Memory': '%s MB' % str(memory / 1024), 'Processors': vcpu_count,
                 'used_cpu_time': used_cpu_time}

        node = Node(id=domain.UUIDString(), name=domain.name(), state=state,
                    public_ips=public_ips, private_ips=private_ips,
                    driver=self, extra=extra)
        node._uuid = domain.UUIDString()  # we want to use a custom UUID
        return node


    def _get_vnc_port_for_domain(self, node):
        """
        Returns the vnc port for a domain
        """
        cmd = "virsh vncdisplay %s" % node.name
        output = self.run_command(cmd)

        try:
            port = output.split(":")[1].replace('\n', '')
            vnc_port = int(port) + 5900
        except:
            vnc_port = None

        return vnc_port

    def ex_set_ssh_fw(self, node):
        """
        """
        remote_port = self._get_vnc_port_for_domain(node)
        local_port = self.ex_bind_local_port()
        if remote_port and local_port:
            cmd = "nohup ssh -L %s:localhost:%s %s@%s -i %s -N &" % \
                (local_port, remote_port, self.key, self.host, self.secret)
        else:
            return None

        cmd = shlex.split(cmd)
        child = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        return local_port

    # SOS: ssh fw need to be closed as longs as vnc session closes

    def ex_bind_local_port(self):
        """
        Find a local port to bind and return
        """
        for port in range(50000, 65535):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.bind(("", port))
                s.listen(1)
                s.close()
                return port
            except:
                pass
        return None

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
        """
        Returns sizes
        A min and a max size are returned
        """
        sizes = []
        min_size = NodeSize(id=0, name='small', ram=1000, 
                            disk=1, bandwidth=None, price=None,
                            driver=self, extra={'cpu': 1})
        sizes.append(min_size)
        
        try:
            # not supported by all hypervisors
            info = self.connection.getInfo()
            ram = info[1]
            cores = info[2]
            max_size = NodeSize(id=1, name='large', ram=ram, disk=1, bandwidth=None, 
                       price=None, driver=self, extra={'cpu': cores})
            sizes.append(max_size)
        except:
            pass

        return sizes

    def list_locations(self):
        return []

    def list_images(self, location='/var'):
        """
        Returns iso images as NodeImages
        Searches inside /var, unless other location is specified
        """
        images = []
        cmd = "find %s -name '*.iso'" % location
        output = self.run_command(cmd)

        if output:
            for image in output.strip().split('\n'):
                nodeimage = NodeImage(id=image, name=image, driver=self, extra={})
                images.append(nodeimage)

        return images

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

    def ex_get_capabilities(self):
        """
        Return hypervisor capabilities
        """
        capabilities = self.connection.getCapabilities()
        return capabilities

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

    def create_node(self, name, disk_path=None, disk_size=4, ram=1024,
                    cpus=1, os_type='linux', image='' ):
        """
        Creates a VM

        If image is missing, we assume we are creating the VM by importing
        existing image (disk_path has to be specified)

        image is optional and  needs to be a path,
        eg /var/lib/libvirt/images/CentOS-7-x86_64-Minimal-1503-01.iso

        If disk_path is specified, needs to be a path, eg /var/lib/libvirt/images/name.img
        If it exists, we assume it is already there to be used. Otherwise we will try to create
        it with qemu-img - disk_size being the size of it
        disk_size should be an int specifying the Gigabytes of disk space.

        Cases that are covered by this:
        1) Boot from iso -needs name, iso image, ram, cpu, disk space, size
        2) Import existing image - needs disk_path, ram, cpu

        """
        # name validator, name should be unique
        name = self.ex_name_validator(name)

        # check which case we are on. If both image and disk_path are empty, then fail with error.

        if not disk_path and not image:
            raise Exception("You have to specify at least an image iso, to boot from, or an existing disk_path to import")

        disk_size = str(disk_size) + 'G'
        ram = ram * 1000

        # TODO: get available ram, cpu and disk and inform if not available
        if image:
            if not disk_path:
                # make a default disk_path of  /var/lib/libvirt/images/vm_name.img
                disk_path = '/var/lib/libvirt/images/%s.img' % name

            self.ex_create_disk(disk_path, disk_size)
        else:
            # if disk_path is specified but the path does not exist fail with error
            if not self.ex_validate_disk(disk_path):
                raise Exception("You have specified no image iso and a disk path to import that does not exist")

        capabilities = self.ex_get_capabilities()
        if "<domain type='kvm'>" in capabilities:
            # kvm hypervisor supported by the system
            emu = 'kvm'
        else:
            # only qemu emulator available
            emu = 'qemu'

        # define the VM
        if image:
            image_conf = IMAGE_TEMPLATE % image
        else:
            image_conf = ''

        # bridges = self.ex_list_bridges()
        # FIXME: needs testing
        bridges = []
        if bridges:
            net_type = 'bridge'
            net_name = bridges[0]
        else:
            net_type = 'network'
            net_name = 'default'


        conf = XML_CONF_TEMPLATE % (emu, name, ram, cpus, disk_path, image_conf, net_type, net_type, net_name)

        self.connection.defineXML(conf)

        # start the VM

        domain = self.connection.lookupByName(name)
        try:
            domain.create()
        except:
            raise

        return True

    def ex_name_validator(self, name):
        """
        Makes sure name is not in use, and checks
        it is comprised only by alphanumeric chars and -_."
        """
        if not re.search(r'^[0-9a-zA-Z-_.]+[0-9a-zA-Z]$', name):
            raise Exception("Alphanumeric, dots, dashes and underscores are only allowed in VM name")

        nodes = self.list_nodes(show_hypervisor=False)

        if name in [node.name for node in nodes]:
            raise Exception("VM with name %s already exists" % name)

        return name

    def ex_validate_disk(self, disk_path):
        """
        Check if disk_path exists
        """

        cmd = 'ls %s' % disk_path
        output = self.run_command(cmd)

        if output:
            return True
        else:
            return False

    def ex_create_disk(self, disk_path, disk_size):
        """
        Create disk using qemu-img
        """
        cmd = "qemu-img create -f qcow2 %s %s" % (disk_path, disk_size)

        output = self.run_command(cmd)
        if output:
            return True
        else:
            return False

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

    def ex_list_bridges(self):
        bridges = []
        try:
            # not supported by all hypervisors
            for net in self.connection.listAllNetworks():
                    bridges.append(net.bridgeName())
        except:
            pass
        return bridges

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

    def run_command(self, cmd):
        """
        Run a command on a local or remote hypervisor
        If the hypervisor is remote, run the command with paramiko
        """
        output = ''
        if self.secret:
            try:
                ssh=paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                ssh.connect(self.host, username=self.key, key_filename=self.secret,
                            port=self.ssh_port, timeout=None, allow_agent=False, look_for_keys=False)
                stdin,stdout,stderr = ssh.exec_command(cmd)

                output = stdout.read()
                ssh.close()
            except:
                pass
        else:
            try:
                cmd = shlex.split(cmd)
                child = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
                output, _ = child.communicate()
            except:
                pass
        return output


XML_CONF_TEMPLATE = '''
<domain type='%s'>
  <name>%s</name>
  <memory>%s</memory>
  <vcpu>%s</vcpu>
  <os>
   <type arch='x86_64'>hvm</type>
    <boot dev='hd'/>
    <boot dev='cdrom'/>
  </os>
 <features>
    <acpi/>
  </features>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='%s'/>
      <target dev='hda' bus='ide'/>
    </disk>%s
    <interface type='%s'>
      <source %s='%s'/>
    </interface>
    <input type='mouse' bus='ps2'/>
    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>
    <video>
      <model type='cirrus' vram='9216' heads='1'/>
    </video>
  </devices>
</domain>
'''

IMAGE_TEMPLATE = '''
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='%s'/>
     <target dev='hdb' bus='ide'/>
     <readonly/>
    </disk>
'''
