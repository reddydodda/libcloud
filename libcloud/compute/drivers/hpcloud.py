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
HP Public cloud driver which is esentially just a small wrapper around
OpenStack driver.
"""

from libcloud.compute.types import Provider, LibcloudError
from libcloud.compute.drivers.openstack import OpenStack_1_1_Connection
from libcloud.compute.drivers.openstack import OpenStack_1_1_NodeDriver


__all__ = [
    'HPCloudNodeDriver'
]

ENDPOINT_ARGS_MAP = {
    'region-a.geo-1': {
        'service_type': 'compute',
        'name': 'Compute',
        'region': 'region-a.geo-1'
    },
    'region-b.geo-1': {
        'service_type': 'compute',
        'name': 'Compute',
        'region': 'region-b.geo-1'
    },
}

AUTH_URL_TEMPLATE = 'https://%s.identity.hpcloudsvc.com:35357/v2.0/tokens'


class HPCloudConnection(OpenStack_1_1_Connection):
    _auth_version = '2.0_password'

    def __init__(self, *args, **kwargs):
        self.region = kwargs.pop('region', None)
        self.get_endpoint_args = kwargs.pop('get_endpoint_args', None)
        super(HPCloudConnection, self).__init__(*args, **kwargs)

    def get_endpoint(self):
        if not self.get_endpoint_args:
            raise LibcloudError(
                'HPCloudConnection must have get_endpoint_args set')

        args = dict(self.get_endpoint_args)

        if self._ex_force_service_type:
            args["service_type"] = self._ex_force_service_type
        if self._ex_force_service_name == None:
            args["name"] = ""
        elif self._ex_force_service_name:
            args["name"] = self._ex_force_service_name
        if self._ex_force_service_region:
            args["region"] = self._ex_force_service_region
        print args
        if '2.0_password' in self._auth_version:
            ep = self.service_catalog.get_endpoint(service_type=args.get("service_type", ""),
                                                   region=args.get("region", ""))

        else:
            raise LibcloudError(
                'Auth version "%s" not supported' % (self._auth_version))

        public_url = ep.url

        if not public_url:
            raise LibcloudError('Could not find specified endpoint')

        return public_url


class HPCloudNodeDriver(OpenStack_1_1_NodeDriver):
    name = 'HP Public Cloud (Helion)'
    website = 'http://www.hpcloud.com/'
    connectionCls = HPCloudConnection
    type = Provider.HPCLOUD

    def __init__(self, key, secret, tenant_name, secure=True,
                 host=None, port=None, region='region-b.geo-1', **kwargs):
        """
        Note: tenant_name argument is required for HP cloud.
        """
        self.tenant_name = tenant_name
        super(HPCloudNodeDriver, self).__init__(key=key, secret=secret,
                                                secure=secure, host=host,
                                                port=port,
                                                region=region,
                                                **kwargs)

    def _ex_connection_class_kwargs(self):
        endpoint_args = ENDPOINT_ARGS_MAP[self.region]

        kwargs = self.openstack_connection_kwargs()
        kwargs['region'] = self.region
        kwargs['get_endpoint_args'] = endpoint_args
        kwargs['ex_force_auth_url'] = AUTH_URL_TEMPLATE % (self.region)
        kwargs['ex_tenant_name'] = self.tenant_name

        return kwargs

    def _neutron_endpoint(func):
        """
        This is a hack. To change the endpoint to neutron and back to
        compute/nova.
        """
        def neutron_connection(self):
            self.connection._ex_force_service_region = self.region
            self.connection._ex_force_service_type = "network"
            self.connection._ex_force_service_name = None

        def restore_connection(self):
            self.connection._ex_force_service_region = ""
            self.connection._ex_force_service_type = ""
            self.connection._ex_force_service_name = ""

        from functools import wraps

        @wraps(func)
        def wrapper(*args, **kwargs):
            neutron_connection(args[0])
            try:
                re = func(*args, **kwargs)
            finally:
                restore_connection(args[0])
            return re

        return wrapper

    @_neutron_endpoint
    def ex_list_networks(self):
        """
        Get a list of Networks that are available.

        :rtype: ``list`` of :class:`OpenStackNetwork`
        """

        networks = self.connection.request(
            self._neutron_networks_url_prefix).object
        subnets = self.connection.request(
            self._neutron_subnets_url_prefix).object
        return self._to_neutron_networks(networks, subnets)

    def _to_neutron_networks(self, obj_networks, obj_subnets):
        networks = obj_networks['networks']
        subnets = obj_subnets['subnets']
        return [self._to_neutron_network(network, subnets) for network in networks]

    def _to_neutron_network(self, obj, subnets):
        added_subnets = []
        for sub in subnets:
            if sub['id'] in obj['subnets']:
                added_subnets.append(
                    HPCloudSubnet(
                        id=sub['id'], name=sub[
                            'name'], enable_dhcp=sub['enable_dhcp'],
                        allocation_pools=sub[
                            'allocation_pools'], gateway_ip=sub['gateway_ip'],
                        cidr=sub['cidr'])
                )
        return HPCloudNetwork(id=obj.pop('id'), name=obj.pop('name'),
                              status=obj.pop('status'), subnets=added_subnets,
                              router_external=obj.pop("router:external", False),
                              extra=obj)

    @_neutron_endpoint
    def ex_create_network(self, name, admin_state_up=True, shared=False):
        """
        Create a new neutron Network

        :param name: Name of the network which should be used
        :type name: ``str``

        :param admin_state_up: The administrative state of the network
        :type admin_state_up: ``bool``

        :param shared: Admin-only. Indicates whether this network is shared across all tenants.
        :type shared: ``bool``

        :param tenant_id: The ID of the tenant that owns the network.
        :type tenant_id: ``str``

        :return: :class:`OpenStackNeutronNetwork`
        """

        data = {
            'network': {
                'name': name,
                'admin_state_up': admin_state_up,
                'shared': shared,
            }
        }

        response = self.connection.request(self._neutron_networks_url_prefix,
                                           method='POST', data=data).object

        return self._to_neutron_network(response['network'], [])

    @_neutron_endpoint
    def ex_delete_network(self, network_id):
        """
        Delete neutron network
        """
        response = self.connection.request(self._neutron_networks_url_prefix +
                                           "/%s" % network_id, method='DELETE').object

        return response

    @_neutron_endpoint
    def ex_create_subnet(self, name, network_id, cidr, allocation_pools=[], gateway_ip=None,
                         ip_version="4", enable_dhcp=True):

        data = {
            'subnet': {
                'name': name,
                'network_id': network_id,
                'ip_version': ip_version,
                'cidr': cidr,
                'gateway_ip': gateway_ip,
                'allocation_pools': allocation_pools,
                'enable_dhcp': enable_dhcp
            }
        }
        response = self.connection.request(self._neutron_subnets_url_prefix,
                                           method='POST', data=data).object

        subnet = response['subnet']
        return HPCloudSubnet(name=subnet['name'], id=subnet['id'], cidr=subnet['cidr'],
                             enable_dhcp=subnet['enable_dhcp'],
                             allocation_pools=subnet['allocation_pools'],
                             gateway_ip=subnet['gateway_ip'],
                             dns_nameservers=subnet['dns_nameservers'])

    @_neutron_endpoint
    def ex_delete_subnet(self, subnet_id):
        """
        Delete neutron subnet
        """
        response = self.connection.request(self._neutron_subnets_url_prefix +
                                           "/%s" % subnet_id, method='DELETE').object
        return response

    @_neutron_endpoint
    def ex_list_routers(self):
        """
        List routers
        """
        resp = self.connection.request('/v2.0/routers', method='GET').object

        return self._to_routers(resp)

    def _to_routers(self, obj_routers):
        routers = obj_routers['routers']
        return [self._to_router(router) for router in routers]

    def _to_router(self, obj):
        return HPCloudRouter(id=obj['id'], name=obj['name'], status=obj['status'],
                             external_gateway=obj['external_gateway_info'])

    @_neutron_endpoint
    def ex_create_router(self, name, external_gateway=False, ext_net_id=""):
        """
        Add external gateway to router
        """
        data = {
            'router': {
                'name': name,
            }
        }
        if external_gateway:
            external_gateway_info = {
                'network_id': ext_net_id,
            }
            data['router']['external_gateway_info'] = external_gateway_info

        resp = self.connection.request('/v2.0/routers', method='POST', data=data).object
        return resp

    @_neutron_endpoint
    def ex_set_gateway_router(self, router_id, ext_net_id):
        """
        Set external gateway for existing router
        """
        data = {
            'router': {
                'external_gateway_info':
                    {
                        'network_id': ext_net_id
                    }
            }
        }
        resp = self.connection.request('/v2.0/routers/%s' % router_id, method='PUT', data=data).object
        return resp

    @_neutron_endpoint
    def ex_add_router_interface(self, router_id, subnet_id):
        """
        Attach router through an interface to a subnet
        """
        data = {
            'subnet_id': subnet_id
        }
        resp = self.connection.request('/v2.0/routers/%s/add_router_interface' % router_id, method='PUT', data=data).object
        return resp

    @_neutron_endpoint
    def ex_list_ports(self):
        """
        List ports
        """
        resp = self.connection.request('/v2.0/ports', method='GET').object

        return resp



class HPCloudNetwork(object):
    """
    An instance of a neutron network
    """

    def __init__(self, id, name, status=None, subnets=[], extra={}, router_external=False):
        self.id = id
        self.name = name
        self.status = status
        self.subnets = subnets
        self.extra = extra
        self.router_external = router_external

    def __repr__(self):
        return '<HPCloudNetwork id=%s name=%s>' % (self.id, self.name)


class HPCloudSubnet(object):
    """
    An instance of a neutron subnet
    """

    def __init__(self, id, name, enable_dhcp=False, dns_nameservers=[], allocation_pools=[],
                 gateway_ip=None, cidr=None,):
        self.id = id
        self.name = name
        self.enable_dhcp = enable_dhcp
        self.dns_nameservers = dns_nameservers
        self.allocation_pools = allocation_pools
        self.gateway_ip = gateway_ip
        self.cidr = cidr

    def __repr__(self):
        return '<HPCloudSubnet id=%s name=%s cidr=%s>' % (self.id, self.name, self.cidr)


class HPCloudRouter(object):
    """
    An instance of a port
    """

    def __init__(self, id, name, status="ACTIVE", external_gateway={},):
        self.id = id
        self.name = name
        self.status = status
        self.external_gateway = external_gateway

    def __repr__(self):
        return '<HPCloudRouter id=%s name=%s external_gateway=%s>' % (self.id, self.name, bool(self.external_gateway))