# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# This file is heavily derived from the Ironic AMT driver at
# https://github.com/openstack/ironic/tree/master/ironic/drivers/modules/amt
#
# Thanks much for the hard work of people in that project to produce
# Open Source software that acts as one of the few bits of example
# code for this interface.

import xml.dom.minidom
from xml.etree import ElementTree

import requests
from requests.auth import HTTPDigestAuth

import uuid

import amt.wsman


"""CIM schema urls

Conceptually you can query a Service, everything else is for update
only or modeling only. And, yes this is as redundant as it looks.
"""

SCHEMA_BASE = 'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/'

CIM_AssociatedPowerManagementService = (SCHEMA_BASE +
                                        'CIM_AssociatedPowerManagementService')
CIM_PowerManagementService = (SCHEMA_BASE +
                              'CIM_PowerManagementService')
CIM_BootService = SCHEMA_BASE + 'CIM_BootService'

CIM_ComputerSystem = SCHEMA_BASE + 'CIM_ComputerSystem'
CIM_ComputerSystemPackage = SCHEMA_BASE + 'CIM_ComputerSystemPackage'
CIM_BootConfigSetting = SCHEMA_BASE + 'CIM_BootConfigSetting'
CIM_BootSourceSetting = SCHEMA_BASE + 'CIM_BootSourceSetting'

# Additional useful constants
_SOAP_ENVELOPE = 'http://www.w3.org/2003/05/soap-envelope'
_ADDRESS = 'http://schemas.xmlsoap.org/ws/2004/08/addressing'
_ANONYMOUS = 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'
_WSMAN = 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd'


# magic ports to connect to
AMT_PROTOCOL_PORT_MAP = {
    'http': 16992,
    'https': 16993,
}


def pp_xml(body):
    """Pretty print format some XML so it's readable."""
    pretty = xml.dom.minidom.parseString(body)
    return pretty.toprettyxml(indent="  ")


class Client(object):
    """AMT client.

    Manage interactions with AMT host.
    """
    def __init__(self, address, password,
                 username='admin', protocol='http',
                 vncpasswd=None):
        port = AMT_PROTOCOL_PORT_MAP[protocol]
        self.path = '/wsman'
        self.uri = "%(protocol)s://%(address)s:%(port)s%(path)s" % {
            'address': address,
            'protocol': protocol,
            'port': port,
            'path': self.path}
        self.username = username
        self.password = password
        self.vncpassword = vncpasswd
        self.session = requests.Session()
        self.auth = HTTPDigestAuth(self.username, self.password)

    def post(self, payload, ns=None):
        resp = self.session.post(self.uri,
                             headers={'content-type':
                                      'application/soap+xml;charset=UTF-8'},
                             auth=self.auth,
                             data=payload, verify=False)
        resp.raise_for_status()
        if ns:
            rv = _return_value(resp.content, ns)
            if rv == 0:
                return 0
            print(pp_xml(resp.content))
            return rv
        else:
            return resp.content

    def power_on(self):
        """Power on the box."""
        payload = amt.wsman.power_state_request(self.path, "on")
        self.post(payload, CIM_PowerManagementService)
        return 0

    def power_off(self):
        """Power off the box."""
        payload = amt.wsman.power_state_request(self.path, "off")
        self.post(payload, CIM_PowerManagementService)
        return 0

    def power_cycle(self):
        """Power cycle the box."""
        payload = amt.wsman.power_state_request(self.path, "reboot")
        self.post(payload, CIM_PowerManagementService)
        return 0

    def power_cycle_hard(self):
        """Power cycle hard the box."""
        payload = amt.wsman.power_state_request(self.path, "reset")
        self.post(payload, CIM_PowerManagementService)
        return 0

    def power_sleep(self):
        """Put the box to sleep."""
        payload = amt.wsman.power_state_request(self.path, "sleep")
        self.post(payload, CIM_PowerManagementService)
        return 0

    def power_hibernate(self):
        """Hibernate the box."""
        payload = amt.wsman.power_state_request(self.path, "hibernate")
        self.post(payload, CIM_PowerManagementService)
        return 0

    def pxe_next_boot(self):
        """Sets the machine to PXE boot on its next reboot

        Will default back to normal boot list on the reboot that follows.
        """
        self.set_next_boot(boot_device='pxe')

    def set_next_boot(self, boot_device):
        """Sets the machine to boot to boot_device on its next reboot

        Will default back to normal boot list on the reboot that follows.
        """
        payload = amt.wsman.change_boot_order_request(self.path, boot_device)
        self.post(payload)

        payload = amt.wsman.enable_boot_config_request(self.path)
        self.post(payload)

    def power_status(self):
        payload = amt.wsman.get_request(
            self.path,
            CIM_AssociatedPowerManagementService)
        resp = self.post(payload)
        value = _find_value(
            resp,
            CIM_AssociatedPowerManagementService,
            "PowerState")
        return value

    def get_uuid(self):
        resp = self.post(amt.wsman.get_request(self.path, CIM_ComputerSystemPackage))
        value = _find_value(resp, CIM_ComputerSystemPackage, "PlatformGUID")
        return uuid.UUID(value)

    def enable_vnc(self):
        if self.vncpassword is None:
            print("VNC Password was not set")
            return False
        payload = amt.wsman.enable_remote_kvm(self.path, self.vncpassword)
        self.post(payload)
        payload = amt.wsman.kvm_redirect(self.path)
        self.post(payload)
        return True

    def vnc_status(self):
        payload = amt.wsman.get_request(
            self.path,
            ('http://intel.com/wbem/wscim/1/ips-schema/1/'
             'IPS_KVMRedirectionSettingData'))
        return pp_xml(self.post(payload))


def _find_node(content, ns, key):
    """Find the return value in a response."""
    doc = ElementTree.fromstring(content)
    query = './/{%(ns)s}%(item)s' % {'ns': ns, 'item': key}
    return doc.find(query)


def _find_value(content, ns, key):
    """Find the return value in a CIM response.

    The xmlns is needed because everything in CIM is a million levels
    of namespace indirection.
    """
    return _find_node(content, ns, key).text


def _return_value(content, ns):
    """Find the return value in a CIM response.

    The xmlns is needed because everything in CIM is a million levels
    of namespace indirection.
    """
    rv = _find_node(content, ns, 'ReturnValue')
    return None if rv is None else int(rv.text)
