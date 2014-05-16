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

"""
Docker (http://docker.io) driver.
Created by Markos Gogoulos (mgogoulos@mist.io)
"""

import base64
import datetime
import shlex
try:
    import simplejson as json
except:
    import json

from libcloud.utils.py3 import httplib
from libcloud.utils.py3 import b

from libcloud.compute.providers import Provider
from libcloud.common.base import JsonResponse, ConnectionUserAndKey
from libcloud.compute.types import NodeState, InvalidCredsError
from libcloud.compute.base import Node, NodeDriver, NodeImage, NodeSize, NodeLocation

VALID_RESPONSE_CODES = [httplib.OK, httplib.ACCEPTED, httplib.CREATED,
                        httplib.NO_CONTENT]


class DockerResponse(JsonResponse):

    valid_response_codes = [httplib.OK, httplib.ACCEPTED, httplib.CREATED,
                            httplib.NO_CONTENT]

    def parse_error(self):
        if self.status == 401:
            raise InvalidCredsError('Invalid credentials')
        return self.body

    def success(self):
        return self.status in self.valid_response_codes


class DockerConnection(ConnectionUserAndKey):

    responseCls = DockerResponse

    def add_default_headers(self, headers):
        """
        Add parameters that are necessary for every request
        If user and password are specified, include a base http auth
        header
        """
        headers['Content-Type'] = 'application/json'
        if self.user_id and self.key:
            user_b64 = base64.b64encode(b('%s:%s' % (self.user_id, self.key)))
            headers['Authorization'] = 'Basic %s' % (user_b64.decode('utf-8'))
        return headers


class DockerNodeDriver(NodeDriver):

    type = Provider.DOCKER
    name = 'Docker'
    website = 'http://docker.io'
    connectionCls = DockerConnection
    features = {'create_node': ['password']}

    def __init__(self, key=None, secret=None, host='localhost',
                 port=4243, secure=False):
        super(DockerNodeDriver, self).__init__(key=key, secret=secret,
              host=host, port=port)
        if host.startswith('https://'):
            secure = True
            port = 443
        prefixes = ['http://', 'https://']
        for prefix in prefixes:
            if host.startswith(prefix):
                host = host.strip(prefix)
        self.connection.host = host
        self.connection.secure = secure
        self.connection.port = port

    def list_images(self):
        result = self.connection.request('/images/json').object

        images = []
        for image in result:
            try:
                name = image.get('RepoTags')[0]
            except:
                name = image.get('Id')
            images.append(NodeImage(
                id=image.get('Id'),
                name=name,
                driver=self.connection.driver,
                extra={
                    "created": image.get('Created'),
                    "size": image.get('Size'),
                    "virtual_size": image.get('VirtualSize'),
                },
            ))

        return images

    def list_sizes(self):
        return (
            [NodeSize(
                id='default',
                name='default',
                ram=1024,
                disk=5120,
                bandwidth=0,
                price=0,
                driver=self)]
        )

    def list_nodes(self):
        result = self.connection.request("/containers/ps?all=1").object

        nodes = []
        for value in result:
            node = self._to_node(value)
            nodes.append(node)

        return nodes

    def reboot_node(self, node):
        data = json.dumps({'t': 10})
        result = self.connection.request('/containers/%s/start' % (node.id),
                                         data=data, method='POST')
        return result.status in VALID_RESPONSE_CODES

    def destroy_node(self, node):
        result = self.connection.request('/containers/%s' % (node.id),
                                         method='DELETE')
        return result.status in VALID_RESPONSE_CODES

    def ex_start_node(self, node):
        result = self.connection.request('/containers/%s/start' % (node.id),
                                         method='POST')
        return result.status in VALID_RESPONSE_CODES

    def ex_stop_node(self, node):
        result = self.connection.request('/containers/%s/stop' % (node.id),
                                         method='POST')
        return result.status in VALID_RESPONSE_CODES

    def create_node(self, image, size, command=None, hostname=None, user=None,
                    detach=False, stdin_open=False, tty=False,
                    mem_limit=0, ports=None, environment=None, dns=None,
                    volumes=None, volumes_from=None,
                    network_disabled=False, name=None, entrypoint=None,
                    cpu_shares=None, working_dir=None, domainname=None,
                    memswap_limit=0):

        command = shlex.split(str(command))

        payload = {
            'Hostname': hostname,
            'Domainname': domainname,
            'ExposedPorts': ports,
            'User': user,
            'Tty': tty,
            'OpenStdin': stdin_open,
            'StdinOnce': False,
            'Memory': mem_limit,
            'AttachStdin': False,
            'AttachStdout': False,
            'AttachStderr': False,
            'Env': environment,
            'Cmd': command,
            'Dns': dns,
            'Image': image,
            'Volumes': volumes,
            'VolumesFrom': volumes_from,
            'NetworkDisabled': network_disabled,
            'Entrypoint': entrypoint,
            'CpuShares': cpu_shares,
            'WorkingDir': working_dir,
            'MemorySwap': memswap_limit
        }

        data = json.dumps(payload)
        result = self.connection.request('/containers/create', data=data,
                                         method='POST')

        id_ = result.object['Id']

        payload = {
            'Binds': [],
        }

        data = json.dumps(payload)
        result = self.connection.request(
            '/containers/%s/start' % id_, data=data,
            method='POST')

        return Node(id=id_, name=id_, state=NodeState.RUNNING,
                    public_ips=[], private_ips=[],
                    driver=self.connection.driver, extra={})

    def _to_node(self, data):
        try:
            name = data.get('Names')[0]
        except:
            name = data.get('Id')
        if 'Exited' in data.get('Status'):
            state = NodeState.STOPPED
        elif data.get('Status').startswith('Up '):
            state = NodeState.RUNNING
        else:
            state = NodeState.STOPPED

        extra = {
            'id': data.get('Id'),
            'status': data.get('Status'),
            'created': ts_to_str(data.get('Created')),
            'image': data.get('Image'),
            'ports': data.get('Ports'),
            'command': data.get('Command'),
            'sizerw': data.get('SizeRw'),
            'sizerootfs': data.get('SizeRootFs'),
        }

        node = (Node(id=data['Id'],
                     name=name,
                     state=state,
                     public_ips=[],
                     private_ips=[],
                     driver=self.connection.driver,
                     extra=extra))
        return node


def ts_to_str(timestamp):
    """Return a timestamp as a nicely formated datetime string."""
    date = datetime.datetime.fromtimestamp(timestamp)
    date_string = date.strftime("%d/%m/%Y %H:%M %Z")
    return date_string
