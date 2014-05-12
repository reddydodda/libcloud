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

try:
    import simplejson as json
except:
    import json

from libcloud.utils.py3 import httplib

from libcloud.compute.providers import Provider
from libcloud.common.base import JsonResponse, ConnectionUserAndKey
from libcloud.compute.types import NodeState, InvalidCredsError
from libcloud.compute.base import Node, NodeDriver, NodeImage, NodeSize


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
        headers['Content-Type'] = 'application/json'
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

    def list_locations(self):
        return []

    def list_nodes(self):
        result = self.connection.request("/containers/ps?all=1").object

        nodes = []
        for value in result:
            node = self._to_node(value)
            nodes.append(node)

        return nodes

    def reboot_node(self, node):
        data = json.dumps({'t': 10})
        self.connection.request(
            self.group_url + '/containers/%s/restart' % (node.id),
            data=data, method='POST')

    def destroy_node(self, node):
        result = self.connection.request('/containers/%s/kill' % (node.id),
                                         method='POST')
        return result.status == httplib.NO_CONTENT

    def create_node(self, **kwargs):
        # name = kwargs['name']
        # size = kwargs['size']
        # image = kwargs['image']

        # auth = kwargs.get('auth', None)

        payload = {
            # 'Hostname': None,
            # 'PortSpecs': None,
            # 'User': None,
            # 'Tty': False,
            # 'OpenStdin': False,
            # 'Memory': 0,
            'AttachStdin': False,
            'AttachStdout': False,
            'AttachStderr': False,
            # 'Env': None,
            'Cmd': ['ls'],
            # 'Dns': None,
            'Image': 'base',
            # 'Volumes': None,
            # 'VolumesFrom': None,
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
        else:
            state = NodeState.RUNNING

        extra = {
            'status': data.get('Status'),
            'created': data.get('Created'),
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
