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

    def ex_list_networks(self):
        """
        Get a list of Networks that are available.

        :rtype: ``list`` of :class:`OpenStackNetwork`
        """

        self.connection._ex_force_service_region = self.region
        self.connection._ex_force_service_type = "network"
        self.connection._ex_force_service_name = None

        networks = self.connection.request(
            self._neutron_networks_url_prefix).object
        subnets = self.connection.request(
            self._neutron_subnets_url_prefix).object
        self.connection._ex_force_service_region = ""
        self.connection._ex_force_service_type = ""
        self.connection._ex_force_service_name = ""
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
                              router_external=obj.pop("router:external"),
                              extra=obj)

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

        self.connection._ex_force_service_region = self.region
        self.connection._ex_force_service_type = "network"
        self.connection._ex_force_service_name = None

        data = {
            'network': {
                'name': name,
                'admin_state_up': admin_state_up,
                'shared': shared,
            }
        }

        response = self.connection.request(self._neutron_networks_url_prefix,
                                           method='POST', data=data).object

        self.connection._ex_force_service_region = ""
        self.connection._ex_force_service_type = ""
        self.connection._ex_force_service_name = ""

        return self._to_neutron_network(response['network'], [])

    def ex_delete_network(self, network_id):
        """
        Delete neutron network
        """
        self.connection._ex_force_service_region = self.region
        self.connection._ex_force_service_type = "network"
        self.connection._ex_force_service_name = None
        response = self.connection.request(self._neutron_networks_url_prefix +
                                           "/%s" % network_id, method='DELETE').object

        self.connection._ex_force_service_region = ""
        self.connection._ex_force_service_type = ""
        self.connection._ex_force_service_name = ""

        return response

    def ex_create_subnet(self, name, network_id, cidr, allocation_pools=[], gateway_ip=None,
                         ip_version="4", enable_dhcp=True):

        self.connection._ex_force_service_region = self.region
        self.connection._ex_force_service_type = "network"
        self.connection._ex_force_service_name = None

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

        self.connection._ex_force_service_region = ""
        self.connection._ex_force_service_type = ""
        self.connection._ex_force_service_name = ""

        subnet = response['subnet']
        return HPCloudSubnet(name=subnet['name'], id=subnet['id'], cidr=subnet['cidr'],
                             enable_dhcp=subnet['enable_dhcp'],
                             allocation_pools=subnet['allocation_pools'],
                             gateway_ip=subnet['gateway_ip'],
                             dns_nameservers=subnet['dns_nameservers'])

    def ex_delete_subnet(self, subnet_id):
        """
        Delete neutron subnet
        """
        self.connection._ex_force_service_region = self.region
        self.connection._ex_force_service_type = "network"
        self.connection._ex_force_service_name = None
        response = self.connection.request(self._neutron_subnets_url_prefix +
                                           "/%s" % subnet_id, method='DELETE').object
        self.connection._ex_force_service_region = ""
        self.connection._ex_force_service_type = ""
        self.connection._ex_force_service_name = ""

        return response


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
    An instance of a neutro subnet
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
