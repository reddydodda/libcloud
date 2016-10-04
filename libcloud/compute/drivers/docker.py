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
import re
import socket

try:
    import simplejson as json
except:
    import json

from libcloud.utils.py3 import httplib
from libcloud.utils.py3 import b
from libcloud.utils.networking import is_private_subnet, is_public_subnet

from libcloud.compute.providers import Provider
from libcloud.common.base import JsonResponse, ConnectionUserAndKey
from libcloud.compute.types import (NodeState, InvalidCredsError,
                                    MalformedResponseError, LibcloudError)
from libcloud.compute.base import (Node, NodeDriver, NodeImage,
                                   NodeSize, NodeLocation)

VALID_RESPONSE_CODES = [httplib.OK, httplib.ACCEPTED, httplib.CREATED,
                        httplib.NO_CONTENT]


class DockerResponse(JsonResponse):

    valid_response_codes = [httplib.OK, httplib.ACCEPTED, httplib.CREATED,
                            httplib.NO_CONTENT]

    def parse_body(self):
        if len(self.body) == 0 and not self.parse_zero_length_body:
            return self.body

        try:
            # error responses are tricky in Docker. Eg response could be
            # an error, but response status could still be 200
            content_type = self.headers.get('content-type', 'application/json')
            if content_type == 'application/json' or content_type == '':
                body = json.loads(self.body)
            else:
                body = self.body
        except ValueError:
            m = re.search('Error: (.+?)"', self.body)
            if m:
                error_msg = m.group(1)
                raise Exception(error_msg)
            else:
                raise Exception('ConnectionError: Failed to parse JSON response')
        return body

    def parse_error(self):
        if self.status == 401:
            raise InvalidCredsError('Invalid credentials')
        return self.body

    def success(self):
        return self.status in self.valid_response_codes


class DockerConnection(ConnectionUserAndKey):

    responseCls = DockerResponse
    timeout = 60

    def add_default_headers(self, headers):
        """
        Add parameters that are necessary for every request
        If user and password are specified, include a base http auth
        header
        """
        if not headers.get('Content-Type'):
            headers['Content-Type'] = 'application/json'
        if self.user_id and self.key:
            user_b64 = base64.b64encode(b('%s:%s' % (self.user_id, self.key)))
            headers['Authorization'] = 'Basic %s' % (user_b64.decode('utf-8'))
        return headers


class DockerNodeDriver(NodeDriver):
    """
    Docker node driver class.

    >>> from libcloud.compute.providers import get_driver
    >>> driver = get_driver('docker')
    >>> conn = driver(host='198.61.239.128', port=4243)
    >>> conn.list_nodes()
    or connecting to http basic auth protected https host:
    >>> conn = driver('user', 'pass', host='https://198.61.239.128', port=443)

    connect with tls authentication, by providing a hostname, port, a private
    key file (.pem) and certificate (.pem) file
    >>> conn = driver(host='https://198.61.239.128', port=4243, key_file='key.pem', cert_file='cert.pem')
    """

    type = Provider.DOCKER
    name = 'Docker'
    website = 'http://docker.io'
    connectionCls = DockerConnection
    features = {'create_node': ['password']}

    def __init__(self, key=None, secret=None, host='localhost', port=4243,
                 secure=False, key_file=None, cert_file=None, ca_cert=None,
                 verify_match_hostname=False, docker_host=None):
        """
        :param key: username, when using http basic auth protected host
        :param secret: password, when using http basic auth protected host
        :param host: IP address or hostname to connect to (usually the address
        of the docker host)
        :param port: the docker host port to connect, eg 2376
        :param secure: if connecting to https this should be True
        :param key_file: the private key for the docker client certificate, when
        connecting through docker tls authentication
        :param cert_file: the docker server certificate file, when
        connecting through docker tls authentication
        :param ca_cert: the CA certificate file, when
        connecting through docker tls authentication
        :param verify_match_hostname: whether to check if the CN matches the certificate.
        If using self signed certificate, need to be False, otherwise connection will fail
        :param docker_host: the IP address of the docker host. Useful in case
        `host` has been substituted by a middleware
        :return:
        """

        super(DockerNodeDriver, self).__init__(key=key, secret=secret,
                                               host=host, port=port,
                                               secure=secure, key_file=key_file,
                                               cert_file=cert_file,
                                               ca_cert=ca_cert,
                                               verify_match_hostname=verify_match_hostname)
        if host.startswith('https://'):
            secure = True

        # strip the prefix
        prefixes = ['http://', 'https://']
        for prefix in prefixes:
            if host.startswith(prefix):
                host = host.strip(prefix)

        if key_file or cert_file:
            # docker tls authentication - https://docs.docker.com/articles/https/
            # We pass two files, a key_file with the private key and cert_file with the certificate
            # libcloud will handle them through LibcloudHTTPSConnection
            if not (key_file and cert_file):
                    raise Exception('Needs both private key file and '
                                    'certificate file for tls authentication')
            self.connection.key_file = key_file
            self.connection.cert_file = cert_file
            self.connection.secure = True
            if ca_cert:
                self.connection.ca_cert = ca_cert
            self.connection.verify_match_hostname = verify_match_hostname
        else:
            self.connection.secure = secure

        self.connection.host = host
        self.connection.port = port
        self.docker_host = docker_host if docker_host else host

        try:
            socket.setdefaulttimeout(15)
            so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            so.connect((host, int(port)))
            so.close()
        except:
            raise Exception("Make sure host is accessible and docker port "
                            "%s is open" % port)

    def _get_api_version(self):
        """
        Get the docker API version information
        """

        result = self.connection.request('/version').object
        api_version = result.get('ApiVersion')

        return api_version

    def list_sizes(self):
        return (
            [NodeSize(
                id='default',
                name='default',
                ram='unlimited',
                disk='unlimited',
                bandwidth='unlimited',
                price=0,
                driver=self)]
        )

    def list_nodes(self, show_all=True, show_host=True):
        """
        List running and stopped containers
        show_all=False will show only running containers
        show_host=True will also show the docker host along
        with the containers
        """
        try:
            result = self.connection.request("/containers/json?all=%s" %
                                             str(show_all)).object
        except Exception as exc:
            if hasattr(exc, 'errno') and exc.errno == 111:
                raise Exception('Make sure docker host is accessible and the '
                                'API port is correct')
            raise

        nodes = [self._to_node(value) for value in result]

        if show_host:
            # append docker host as well
            public_ips, private_ips = [], []
            try:
                if is_public(self.docker_host):
                    public_ips.append(self.docker_host)
                else:
                    private_ips.append(self.docker_host)
            except:
                public_ips.append(self.docker_host)

            extra = {'tags': {'type': 'docker_host'}}
            node = Node(id=self.docker_host, name=self.docker_host,
                        state=NodeState.RUNNING, public_ips=public_ips,
                        private_ips=private_ips, driver=self, extra=extra)
            nodes.append(node)

        return nodes

    def inspect_node(self, node):
        """
        Inspect a container
        """
        result = self.connection.request("/containers/%s/json" % node.id).object

        name = result.get('Name').strip('/')
        if result['State']['Running']:
            state = NodeState.RUNNING
        else:
            state = NodeState.STOPPED

        extra = {
            'image': result.get('Image'),
            'volumes': result.get('Volumes'),
            'env': result.get('Config', {}).get('Env'),
            'ports': result.get('ExposedPorts'),
            'network_settings': result.get('NetworkSettings', {}),
            'exit_code': result['State'].get("ExitCode")
        }

        node_id = result.get('Id')
        if not node_id:
            node_id = result.get('ID', '')
        public_ips = [self.connection.host] if is_public(self.connection.host) else []
        private_ips = [self.connection.host] if not public_ips else []
        node = (Node(id=node_id,
                     name=name,
                     state=state,
                     public_ips=public_ips,
                     private_ips=private_ips,
                     driver=self.connection.driver,
                     extra=extra))
        return node

    def list_processes(self, node):
        """
        List processes running inside a container
        """
        result = self.connection.request("/containers/%s/top" % node.id).object

        return result

    def reboot_node(self, node):
        """
        Restart a container
        """
        data = json.dumps({'t': 10})
        # number of seconds to wait before killing the container
        result = self.connection.request('/containers/%s/restart' % (node.id),
                                         data=data, method='POST')
        return result.status in VALID_RESPONSE_CODES

    def destroy_node(self, node):
        """
        Remove a container
        """

        result = self.connection.request('/containers/%s' % (node.id),
                                         method='DELETE')
        return result.status in VALID_RESPONSE_CODES

    def ex_start_node(self, node):
        """
        Start a container
        """
        result = self.connection.request('/containers/%s/start' % (node.id),
                                         method='POST')
        return result.status in VALID_RESPONSE_CODES

    def ex_stop_node(self, node):
        """
        Stop a container
        """
        result = self.connection.request('/containers/%s/stop' % (node.id),
                                         method='POST')
        return result.status in VALID_RESPONSE_CODES

    def ex_rename_node(self, node, name):
        """
        rename a container
        """
        result = self.connection.request('/containers/%s/rename?name=%s' % (node.id, name),
                                         method='POST')
        return result.status in VALID_RESPONSE_CODES

    def get_logs(self, node, stream=False):
        """
        Get container logs

        If stream == True, logs will be yielded as a stream
        From Api Version 1.11 and above we need a GET request to get the logs
        Logs are in different format of those of Version 1.10 and below

        """
        payload = {}
        data = json.dumps(payload)
        if float(self._get_api_version()) > 1.10:
            logs = self.connection.request("/containers/%s/logs?follow=%s&stdout=1&stderr=1" %(node.id, int(stream)),headers={"Content-Type": "application/vnd.docker.raw-stream"}).object
        else:
            result = self.connection.request("/containers/%s/attach?logs=1&stream=%s&stdout=1&stderr=1" %
                                             (node.id, str(stream)), method='POST', data=data,
                                             headers={
                                                 "Content-Type": "application/vnd.docker.raw-stream"
                                             })
            logs = result.body

        return logs

    def create_node(self, name, image, command=None, hostname=None, user='',
                    detach=False, stdin_open=True, tty=True,
                    mem_limit=0, ports=None, environment=None, dns=None,
                    volumes=None, volumes_from=None,
                    network_disabled=False, entrypoint=None,
                    cpu_shares=None, working_dir='', domainname=None,
                    memswap_limit=0, port_bindings={}):
        """
        Create a container

        Create a container, based on an image and optionally specify command
        and other settings. If image is not found, try to pull it
        After the container is created, start it
        """
        command = shlex.split(str(command))

        params = {
            'name': name
        }

        payload = {
            'Hostname': hostname,
            'Domainname': domainname,
            'ExposedPorts': ports,
            'User': user,
            'Tty': tty,
            'OpenStdin': stdin_open,
            'StdinOnce': False,
            'Memory': mem_limit,
            'AttachStdin': True,
            'AttachStdout': True,
            'AttachStderr': True,
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
            'MemorySwap': memswap_limit,
            'PublishAllPorts': True,
            'PortBindings': port_bindings,
        }

        data = json.dumps(payload)
        try:
            result = self.connection.request('/containers/create', data=data,
                                             params=params, method='POST')
        except Exception as e:
            # if image not found, try to pull it
            if e.message.startswith('{"message":"No such image'):
                try:
                    self.pull_image(image=image)
                    result = self.connection.request('/containers/create',
                                                     data=data, params=params,
                                                     method='POST')
                except:
                    raise Exception('No such image: %s' % image)
            else:
                raise Exception(e)

        id_ = result.object['Id']

        result = self.connection.request(
            '/containers/%s/start' % id_,
            method='POST')

        return Node(id=id_, name=id_, state=NodeState.RUNNING,
                    public_ips=[], private_ips=[],
                    driver=self.connection.driver, extra={})

    def list_images(self):
        "Return list of images as NodeImage objects"

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

    def search_images(self, term):
        """Search for an image on Docker.io.
           Returns a list of NodeImage objects

           >>> images = conn.search_images(term='mistio')
           >>> images
           [<NodeImage: id=rolikeusch/docker-mistio...>,
            <NodeImage: id=mist/mistio, name=mist/mistio, driver=Docker  ...>]
        """

        term = term.replace(' ', '+')
        result = self.connection.request('/images/search?term=%s' %
                                         term).object
        images = []
        for image in result:
            name = image.get('name')
            images.append(NodeImage(
                id=name,
                name=name,
                driver=self.connection.driver,
                extra={
                    "description": image.get('description'),
                    "is_official": image.get('is_official'),
                    "is_trusted": image.get('is_trusted'),
                    "star_count": image.get('star_count'),
                },
            ))

        return images

    def pull_image(self, image):
        """Create an image,
        Create an image either by pull it from the registry or by
        importing it
        >>> image = conn.pull_image(image='mist/mistio')
        >>> image
        <NodeImage: id=0ec05daec99f, name=mist/mistio, driver=Docker  ...>

        """

        payload = {
        }
        data = json.dumps(payload)

        result = self.connection.request('/images/create?fromImage=%s' %
                                         (image), data=data, method='POST')
        if "errorDetail" in result.body:
            raise Exception(result.body)
        try:
            # get image id
            image_id = re.findall(r'{"status":"Download complete","progressDetail":{},"id":"\w+"}', result.body)[-1]
            image_id = json.loads(image_id).get('id')
        except:
            image_id = image

        image = NodeImage(id=image_id, name=image,
                          driver=self.connection.driver, extra={})
        return image

    def delete_image(self, image):
        "Remove image from the filesystem"
        result = self.connection.request('/images/%s' % (image),
                                         method='DELETE')
        return result.status in VALID_RESPONSE_CODES

    def inspect_image(self, image):
        """
        Inspect an image
        """
        raise NotImplementedError()

    def push_image(self, image):
        """
        Push an image on the registry
        """
        raise NotImplementedError()

    def _to_node(self, data):
        """Convert node in Node instances
        """
        try:
            name = data.get('Names')[0].strip('/')
        except:
            name = data.get('Id')
        if 'Exited' in data.get('Status'):
            state = NodeState.STOPPED
        elif data.get('Status').startswith('Up '):
            state = NodeState.RUNNING
        else:
            state = NodeState.STOPPED
        ports = data.get('Ports', [])
        ports.sort()
        extra = {
            'id': data.get('Id'),
            'status': data.get('Status'),
            'created': ts_to_str(data.get('Created')),
            'image': data.get('Image'),
            'ports': json.dumps(ports),
            'command': data.get('Command'),
            'sizerw': data.get('SizeRw'),
            'sizerootfs': data.get('SizeRootFs'),
        }

        public_ips, private_ips = [], []
        if is_private(self.connection.host):
            private_ips.append(self.connection.host)
        else:
            public_ips.append(self.connection.host)

        node = (Node(id=data['Id'],
                     name=name,
                     state=state,
                     public_ips=public_ips,
                     private_ips=private_ips,
                     driver=self.connection.driver,
                     created_at=data.get('Created'),
                     extra=extra))
        return node


def ts_to_str(timestamp):
    """Return a timestamp as a nicely formatted datetime string."""
    date = datetime.datetime.fromtimestamp(timestamp)
    date_string = date.strftime("%d/%m/%Y %H:%M %Z")
    return date_string


def is_private(hostname):
    hostname = socket.gethostbyname(hostname)
    if is_private_subnet(hostname):
        return True
    return False


def is_public(hostname):
    return not is_private(hostname=hostname)
