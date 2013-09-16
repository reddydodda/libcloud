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
NephoScale Cloud driver (http://www.nephoscale.com)
API documentation: http://docs.nephoscale.com
Created by Markos Gogoulos (https://mist.io)
"""

import base64
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

API_HOST = "api.nephoscale.com"

NODE_STATE_MAP = {
    'on': NodeState.RUNNING,
    'off': NodeState.TERMINATED,
    'unknown': NodeState.UNKNOWN,    
}
#FIXME: rebooting/destroying states

class NephoscaleResponse(JsonResponse):
    """
    Nephoscale response class.
    """

    valid_response_codes = [httplib.OK, httplib.ACCEPTED, httplib.CREATED,
                            httplib.NO_CONTENT]

    def parse_error(self):
        if self.status == 401:
            raise InvalidCredsError('Authorization Failed')
        if self.status == 404:
            raise Exception("The resource you are looking for is not found.")

        return self.body

    def success(self):
        return self.status in self.valid_response_codes

class NephoscaleConnection(ConnectionUserAndKey):
    """
    Nephoscale connection class.
    Authenticates to the API through Basic Authentication with username/password
    """
    host = API_HOST
    responseCls = NephoscaleResponse

    def add_default_headers(self, headers):
        user_b64 = base64.b64encode(b('%s:%s' % (self.user_id, self.key)))
        headers['Authorization'] = 'Basic %s' % (user_b64.decode('utf-8'))
        return headers


class NephoscaleNodeDriver(NodeDriver):
    """
    Nephoscale node driver class.
    """

    type = Provider.NEPHOSCALE
    name = 'NephoScale'
    website = 'http://www.nephoscale.com'
    connectionCls = NephoscaleConnection

    def __init__(self, *args, **kwargs):
        super(NephoscaleNodeDriver, self).__init__(*args, **kwargs)


    def list_locations(self):
        #result = self.connection.request('/datacenter/').object    
        #TODO: try if RIC-1 location works, otherwise remove
        return [
            NodeLocation(1, 'SJC-1', 'US', self),
            NodeLocation(3, 'RIC-1', 'US', self),
        ]


    def list_images(self):
        result = self.connection.request('/image/server/').object
        images = []
        for value in result.get('data', []):
            extra = {'architecture': value.get('architecture'), 'disks': value.get('disks'),
                     'billable_type': value.get('billable_type'), 'pcpus': value.get('pcpus'), 
                     'cores': value.get('cores'), 'uri': value.get('uri'), 'storage': value.get('storage'), 
                    }
            image = NodeImage(id=value.get('id'), name=value.get('friendly_name'),
                              driver=self.connection.driver, extra=extra)
            images.append(image)

        return images

    def list_sizes(self):
        result = self.connection.request('/server/type/').object
        sizes = []
        for value in result.get('data', []):
            size = NodeSize(id=value.get('id'), name=value.get('friendly_name'),
                            ram=value.get('ram'), disk=value.get('storage'),
                            bandwidth=None, price=0.0,
                            driver=self.connection.driver)
            sizes.append(size)

        return sizes

    def list_nodes(self):
        result = self.connection.request('/server/cloud/').object
        nodes = []
        for value in result.get('data', []):
            node = self._to_node(value)
            nodes.append(node)

        return nodes

    def reboot_node(self, node):
        pass

        
    def destroy_node(self, node):
        pass

        
    def create_node(self, **kwargs):
        pass
        

    def ex_stop_node(self, node):
        pass

        
    def ex_start_node(self, node):
        pass

        
    def _to_node(self, data):
        state = NODE_STATE_MAP.get(data.get('power_status'), '4')
        public_ips = []
        private_ips = []
        ip_addresses = data.get('ipaddresses', '')
        #"ipaddresses": "198.120.14.6, 10.132.60.1",
        if ip_addresses:
            ip_addresses_list = ip_addresses.split(',')
            for ip in ip_addresses_list:
                ip = ip.replace(' ','')
                if ip.startswith('10.') or ip.startswith('192.168'):
                    private_ips.append(ip)
                else:
                    public_ips.append(ip)
        extra = {'zone': data.get('zone'), 'image': data.get('image'),
         'create_time': data.get('create_time'), 'network_ports': data.get('network_ports'), 'is_console_enabled': data.get('is_console_enabled'), 
         'service_type': data.get('service_type'), 'hostname': data.get('hostname')
        }

        node = Node(id=data.get('id'), name=data.get('name'), state=state,
                    public_ips=public_ips, private_ips=private_ips,
                    driver=self.connection.driver, extra=extra)
        return node
