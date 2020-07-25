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
#
# KVM Redirection derived from https://github.com/Ylianst/MeshCommander
# (amt-redir-ws-0.1.0.js by Ylian Saint-Hilaire)
#
# KVM Redirection derived from https://github.com/Ylianst/MeshCommander
# (amt-ider-ws-0.0.1.js by Ylian Saint-Hilaire)

import xml.dom.minidom
from xml.etree import ElementTree

import requests
from requests.auth import HTTPDigestAuth

from enum import Enum
import hashlib
import pem
import os
import secrets
import select
import socket
import ssl
import stat
import struct
import time
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
CIM_KVMRedirectionSAP = SCHEMA_BASE + 'CIM_KVMRedirectionSAP'

SCHEMA_BASE = 'http://intel.com/wbem/wscim/1/amt-schema/1/'

AMT_PublicKeyManagementService = SCHEMA_BASE + 'AMT_PublicKeyManagementService'
AMT_PublicKeyCertificate = SCHEMA_BASE + 'AMT_PublicKeyCertificate'
AMT_PublicPrivateKeyPair = SCHEMA_BASE + 'AMT_PublicPrivateKeyPair'
AMT_TLSSettingData = SCHEMA_BASE + 'AMT_TLSSettingData'
AMT_TLSCredentialContext = SCHEMA_BASE + 'AMT_TLSCredentialContext'
AMT_SetupAndConfigurationService = SCHEMA_BASE + 'AMT_SetupAndConfigurationService'
AMT_TimeSynchronizationService = SCHEMA_BASE + 'AMT_TimeSynchronizationService'

del SCHEMA_BASE

# Additional useful constants
_SOAP_ENVELOPE = 'http://www.w3.org/2003/05/soap-envelope'
_SOAP_ENUMERATION = 'http://schemas.xmlsoap.org/ws/2004/09/enumeration'
_ADDRESS = 'http://schemas.xmlsoap.org/ws/2004/08/addressing'
_ANONYMOUS = 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'
_WSMAN = 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd'

_TLS_REMOTE = 'Intel(r) AMT 802.3 TLS Settings'
_TLS_LOCAL = 'Intel(r) AMT LMS TLS Settings'
_TLS_EP_COLLECTION = 'TLSProtocolEndpointInstances Collection'


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
                 username=None, protocol='http',
                 vncpasswd=None, ca=None, key=None, cert=None):
        port = AMT_PROTOCOL_PORT_MAP[protocol]
        self.path = '/wsman'
        self.uri = "%(protocol)s://%(address)s:%(port)s%(path)s" % {
            'address': address,
            'protocol': protocol,
            'port': port,
            'path': self.path}
        self.address = address
        self.protocol = protocol
        self.port = port
        self.username = username if username is not None else 'admin'
        self.password = password
        self.vncpassword = vncpasswd
        self.session = requests.Session()
        self.session.auth = HTTPDigestAuth(self.username, self.password)
        self.session.verify = ca if ca is not None else False
        if key is not None and cert is not None:
            self.session.cert = (cert, key)

    def post(self, payload, ns=None):
        resp = self.session.post(self.uri,
                                 headers={'content-type':
                                          'application/soap+xml;charset=UTF-8'},
                                 data=payload)
        resp.raise_for_status()
        self.version = resp.headers.get('Server')
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

    def get_pki_certs(self):
        certs = self._enum_values(AMT_PublicKeyCertificate)
        return [_xml_to_dict(cert) for cert in certs]

    def add_pki_cert(self, filename, trusted):
        certs = []
        for cert in pem.parse_file(filename):
            content = "".join(cert.as_text().splitlines()[1:-1])
            resp = self.post(amt.wsman.add_cert(self.path, content, trusted))
            rv = _return_value(resp, AMT_PublicKeyManagementService)
            selector = _find_node(resp, _WSMAN, "Selector")
            certs.append((rv, None if selector is None else selector.text))
        return certs

    def remove_pki_cert(self, selector):
        resp = self.post(amt.wsman.delete_item(self.path, AMT_PublicKeyCertificate, "InstanceID", selector))
        return _find_value(resp, _ADDRESS, "Action") == "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse"

    def get_pki_keys(self):
        keys = self._enum_values(AMT_PublicPrivateKeyPair)
        return [_xml_to_dict(key) for key in keys]

    def add_pki_key(self, filename):
        keys = []
        for key in pem.parse_file(filename):
            content = "".join(key.as_text().splitlines()[1:-1])
            resp = self.post(amt.wsman.add_key(self.path, content))
            rv = _return_value(resp, AMT_PublicKeyManagementService)
            selector = _find_node(resp, _WSMAN, "Selector")
            keys.append((rv, None if selector is None else selector.text))
        return keys

    def generate_pki_key(self, bits):
        resp = self.post(amt.wsman.generate_key(self.path, bits))
        rv = _return_value(resp, AMT_PublicKeyManagementService)
        selector = _find_node(resp, _WSMAN, "Selector")
        return (rv, None if selector is None else selector.text)

    def sign_pki_csr(self, filename, selector):
        requests = []
        for request in pem.parse_file(filename):
            content = "".join(request.as_text().splitlines()[1:-1])
            resp = self.post(amt.wsman.sign_pki_csr(self.path, content, "InstanceID", selector))
            rv = _return_value(resp, AMT_PublicKeyManagementService)
            signed_request = _find_node(resp, AMT_PublicKeyManagementService, "SignedCertificateRequest")
            requests.append((rv, None if signed_request is None else signed_request.text))
        return requests

    def remove_pki_key(self, selector):
        resp = self.post(amt.wsman.delete_item(self.path, AMT_PublicPrivateKeyPair, "InstanceID", selector))
        return _find_value(resp, _ADDRESS, "Action") == "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse"

    def _format_tls_credentials(self, xml_creds):
        creds = {}
        for cred in xml_creds:
            instance = cred.find('./{' + AMT_TLSCredentialContext + '}ElementProvidingContext//{' + _WSMAN + '}Selector')
            if instance is not None:
                instance = instance.text
            creds[instance] = _xml_to_dict(cred)
        return creds

    def get_tls_credentials(self):
        return self._format_tls_credentials(self._enum_values(AMT_TLSCredentialContext))

    def configure_tls_pki(self, instance):
        exists = len(self._enum_values(AMT_TLSCredentialContext)) > 0

        if instance == '':
            if exists:
                self.post(amt.wsman.delete_item(self.path, AMT_TLSCredentialContext, None, None))
            return exists

        creds = amt.wsman.prepare_tls_credentials(instance)

        if exists:
            self.post(amt.wsman.put_item(self.path, AMT_TLSCredentialContext, None, None, creds))
        else:
            self.post(amt.wsman.create_item(self.path, AMT_TLSCredentialContext, creds))

        return True

    def _enable_tls(self, instance, plaintext, mutual, cn):
        resp = self.post(amt.wsman.get_item(self.path, AMT_TLSSettingData, "InstanceID", instance))
        config = _find_node(resp, AMT_TLSSettingData, "AMT_TLSSettingData")
        _xml_set(config, AMT_TLSSettingData, "Enabled", ["true"])
        _xml_set(config, AMT_TLSSettingData, "AcceptNonSecureConnections", plaintext)
        _xml_set(config, AMT_TLSSettingData, "MutualAuthentication", mutual)
        if cn is not None:
            _xml_set(config, AMT_TLSSettingData, "TrustedCN", cn)
        self.post(amt.wsman.put_item(self.path, AMT_TLSSettingData, "InstanceID", instance, config))
        return True

    def enable_remote_tls(self, plaintext, mutual, cn):
        if mutual:
            self.set_time()
        return self._enable_tls(_TLS_REMOTE, [str(plaintext).lower()], [str(mutual).lower()], cn)

    def enable_local_tls(self):
        return self._enable_tls(_TLS_LOCAL, ["true"], ["false"], None)

    def get_tls_status(self):
        types = {
            _TLS_REMOTE: "remote",
            _TLS_LOCAL: "local",
        }
        settings = {}
        for setting in self._enum_values(AMT_TLSSettingData):
            instance = setting.find('./{' + AMT_TLSSettingData + '}InstanceID')
            if instance is not None:
                instance = instance.text
            settings[types.get(instance)] = _xml_to_dict(setting)
        return settings

    def _disable_tls(self, instance):
        resp = self.post(amt.wsman.get_item(self.path, AMT_TLSSettingData, "InstanceID", instance))
        config = _find_node(resp, AMT_TLSSettingData, "AMT_TLSSettingData")
        _xml_set(config, AMT_TLSSettingData, "Enabled", ["false"])
        resp = self.post(amt.wsman.put_item(self.path, AMT_TLSSettingData, "InstanceID", instance, config))
        return _xml_to_dict(_find_node(resp, AMT_TLSSettingData, "AMT_TLSSettingData"))

    def disable_remote_tls(self):
        return self._disable_tls(_TLS_REMOTE)

    def disable_local_tls(self):
        return self._disable_tls(_TLS_LOCAL)

    def commit_setup_changes(self):
        return self.post(amt.wsman.commit_setup_changes(self.path), AMT_SetupAndConfigurationService)

    def set_time(self):
        # Do something first so that the connection and digest auth are
        # established before getting the reference time, otherwise get_time()
        # and set_time() will have different timing, which is not what this
        # process expects.
        self.get_uuid()

        remote_reference_time = int(time.time())
        resp = self.post(amt.wsman.get_time(self.path))
        local_reference_time = int(_find_value(resp, AMT_TimeSynchronizationService, "Ta0"))

        remote_current_time = int(time.time())
        resp = self.post(amt.wsman.set_time(self.path, local_reference_time, remote_reference_time, remote_current_time))

        return {"old": local_reference_time, "new": remote_current_time, "rv": _return_value(resp, AMT_TimeSynchronizationService)}

    def get_uuid(self):
        resp = self.post(amt.wsman.get_request(self.path, CIM_ComputerSystemPackage))
        value = _find_value(resp, CIM_ComputerSystemPackage, "PlatformGUID")
        return uuid.UUID(value)

    def get_version(self):
        self.get_uuid()
        return self.version

    def enable_vnc(self):
        if self.vncpassword is None:
            print("VNC Password was not set")
            return False
        payload = amt.wsman.enable_remote_kvm(self.path, self.vncpassword)
        self.post(payload)
        payload = amt.wsman.kvm_redirect(self.path)
        self.post(payload)
        return True

    def enable_kvm(self, nodelay=False):
        payload = amt.wsman.enable_remote_kvm(self.path, "", False, nodelay)
        self.post(payload)
        return True

    def start_kvm(self):
        payload = amt.wsman.kvm_redirect(self.path)
        return self.post(payload, CIM_KVMRedirectionSAP) == 0

    def vnc_status(self):
        payload = amt.wsman.get_request(
            self.path,
            ('http://intel.com/wbem/wscim/1/ips-schema/1/'
             'IPS_KVMRedirectionSettingData'))
        return pp_xml(self.post(payload))

    def _enum_values(self, resource):
        values = []

        resp = self.post(amt.wsman.enumerate_begin(self.path, resource))
        context = _find_value(resp, _SOAP_ENUMERATION, "EnumerationContext")

        while context:
            resp = self.post(amt.wsman.enumerate_next(self.path, resource, context))
            items = _find_node(resp, _SOAP_ENUMERATION, "Items")
            for item in items:
                values.append(item)

            eos = _find_node(resp, _SOAP_ENUMERATION, "EndOfSequence")
            if eos is not None:
                context = None

        return values


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


def _xml_to_dict(elements):
    data = {}
    for key, value in [(element.tag.rpartition("}")[2], (_xml_to_dict(element) if element else element.text)) for element in elements]:
        if key in data:
            if type(data[key]) != list:
                data[key] = [data[key]]
            data[key].append(value)
        else:
            data[key] = value
    return data


def _xml_set(elements, ns, tag, values):
    for element in elements.findall('./{%(ns)s}%(item)s' % {'ns': ns, 'item': tag}):
        elements.remove(element)
    for value in values:
        element = ElementTree.SubElement(elements, '{%(ns)s}%(item)s' % {'ns': ns, 'item': tag})
        element.text = value


class KVM(object):
    def __init__(self, client, filename):
        self.client = client
        self.filename = filename

    def _unlink(self):
        try:
            if stat.S_ISSOCK(os.lstat(self.filename).st_mode):
                os.unlink(self.filename)
        except FileNotFoundError:
            pass

    def __enter__(self):
        self._unlink()
        rv = self.client.start_kvm()
        assert rv
        self.incoming = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        self.incoming.bind(self.filename)
        self.incoming.listen()
        self.incoming.setblocking(False)
        return self

    def loop(self):
        while True:
            rlist, _, _ = select.select([self.incoming], [], [self.incoming])
            if self.incoming in rlist:
                (conn, _) = self.incoming.accept()

                pid = os.fork()
                if pid == 0:
                    self.incoming.close()
                    self.incoming = None

                    with KVMClient(self.client, conn) as kvm:
                        kvm.start()
                        kvm.loop()
                    return
                else:
                    assert pid > 0
                    conn.close()
            else:
                return

    def __exit__(self, type, value, traceback):
        if self.incoming is not None:
            self.incoming.close()
            self._unlink()
        return False


class RedirClient(object):
    def __init__(self, client, mode):
        self.client = client
        self.mode = list(mode)
        self.amt = None
        self.tls = None
        self.message_lengths = {
            0x10: (7, 0),
            0x11: (12, 0),
            0x13: (4, 4),
            0x14: (4, 4),
        }
        self.seq = 0

        if self.client.protocol == "https":
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if self.client.session.verify != False:
                self.context.load_verify_locations(self.client.session.verify)
            if self.client.session.cert:
                self.context.load_cert_chain(self.client.session.cert[0], self.client.session.cert[1])

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.tls is not None:
            self.tls.close()
        if self.amt is not None:
            self.amt.close()
        return False

    def _recv_msg(self):
        data = self.tls.recv(1)
        if len(data) != 1:
            print("Server closed connection: {} (1)".format(data))
            return None

        cmd = list(data)
        assert cmd[0] in self.message_lengths, bytes(cmd)
        cmd_len = self.message_lengths[cmd[0]][0]

        data = self.tls.recv(cmd_len)
        if len(data) != cmd_len:
            print("Server closed connection: {} ({})".format(data, cmd_len))
            return None
        cmd.extend(list(data))

        if self.message_lengths[cmd[0]][1]:
            data = self.tls.recv(self.message_lengths[cmd[0]][1])
            if len(data) != self.message_lengths[cmd[0]][1]:
                print("Server closed connection: {} {} ({})".format(cmd, data, self.message_lengths[cmd[0]][1]))
                return None

            if len(data) == 4:
                length = data[0] | (data[1] >> 8) | (data[2] >> 16) | (data[3] >> 24)
            elif len(data) == 1:
                length = data[0]
            else:
                assert False
            data = self.tls.recv(length)
            if len(data) != length:
                print("Server closed connection: {} {} ({})".format(cmd, data, length))
                return None

            return (cmd, data)
        else:
            return (cmd, [])

    def _send_msg(self, cmd, data=b""):
        assert cmd[0] in self.message_lengths, bytes(cmd)
        assert len(cmd) == 1 + self.message_lengths[cmd[0]][0], bytes(cmd)
        if self.message_lengths[cmd[0]][1]:
            length = len(data)
            length = bytes([length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, (length >> 24) & 0xFF])
            self.tls.send(bytes(cmd) + length + data)
        else:
            assert len(data) == 0, data
            self.tls.send(bytes(cmd))

    def _send_seq_msg(self, cmd, data=b""):
        cmd[4] = self.seq
        self.seq = (self.seq + 1) & 0xFF
        self._send_msg(cmd, data)

    def start(self):
        def hex_md5(data):
            return hashlib.md5(data).hexdigest().encode("us-ascii")

        def pull(data):
            assert len(data) >= 1, bytes(data)
            length = data.pop(0)
            assert len(data) >= length, (length, bytes(data))
            value = bytes(data[0:length])
            del data[0:length]
            return value

        def wrap(*data):
            return b"".join([bytes([len(x)]) + x for x in data])

        print("Connection starting")
        self.amt = socket.create_connection((self.client.address, self.client.port + 2))
        if self.client.protocol == "https":
            self.tls = self.context.wrap_socket(self.amt, server_hostname=self.client.address)
        else:
            self.tls = self.amt
        self.tls.setblocking(True)

        # StartRedirectionSession
        self._send_msg([0x10, 0x01, 0x00, 0x00] + self.mode)

        # StartRedirectionSessionReply
        cmd, _ = self._recv_msg()
        assert cmd[0:2] == [0x11, 0x00], bytes(cmd)

        # Query for available authentication
        self._send_msg([0x13, 0x00, 0x00, 0x01, 0x00])

        # AuthenticateSessionReply
        cmd, data = self._recv_msg()
        assert cmd[0:2] == [0x14, 0x00], bytes(cmd) # Status
        assert cmd[-1] == 0x00, bytes(cmd) # Auth types
        assert b"\x04" in data, data # Digest auth

        # Digest auth
        print("Authenticating")
        user = self.client.username.encode("us-ascii")
        path = b"/RedirectionService"
        content = wrap(user, b"", b"", wrap(path), b"", b"", b"", b"")
        self._send_msg([0x13, 0x00, 0x00, 0x00, 0x04], content)

        # AuthenticateSessionReply
        cmd, data = self._recv_msg()
        assert cmd[0:2] == [0x14, 0x01], bytes(cmd) # Status
        assert cmd[-1] == 0x04, bytes(cmd) # Auth type (digest)

        data = list(data)
        realm = pull(data)
        nonce = pull(data)
        qop = pull(data)

        snc = b"00000002"
        cnonce = secrets.token_hex(16).encode("us-ascii")
        extra = snc + b":" + cnonce + b":" + qop + b":"
        digest = hex_md5(hex_md5(user + b":" + realm + b":" + self.client.password.encode("us-ascii"))
                              + b":" + nonce + b":" + extra + hex_md5(b"POST:" + path))
        content = wrap(user, realm, nonce, path, cnonce, snc, digest, qop)
        self._send_msg([0x13, 0x00, 0x00, 0x00, 0x04], content)

        # AuthenticateSessionReply
        cmd, _ = self._recv_msg()
        assert cmd[0:2] == [0x14, 0x00], bytes(cmd) # Status
        assert cmd[-1] == 0x04, bytes(cmd) # Auth type (digest)
        print("Authenticated")


class KVMClient(RedirClient):
    def __init__(self, client, vnc):
        super().__init__(client, b"KVMR")
        self.vnc = vnc
        self._want_write = False
        self.message_lengths.update({
            0x40: (7, 0),
            0x41: (7, 0),
        })

    def _read_tls(self):
        try:
            data = self.tls.recv(4096)
            if len(data) == 0:
                print("Server closed connection")
                self.running = False
                return
            self._want_write = False
            self.vnc.setblocking(True)
            self.vnc.send(data)
            self.vnc.setblocking(False)
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLWantWriteError:
            self._want_write = True

    def _read_vnc(self):
        data = self.vnc.recv(4096)
        if len(data) == 0:
            print("Client closed connection")
            self.running = False
            return
        self.tls.setblocking(True)
        self.tls.send(data)
        self.tls.setblocking(False)

    def start(self):
        super().start()

        # Open session
        self._send_seq_msg([0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        cmd, _ = self._recv_msg()
        assert cmd[0] == 0x41, bytes(cmd)

        print("Remote desktop started")
        self.tls.setblocking(False)
        self.vnc.setblocking(False)
        self.running = True

    def loop(self):
        while self.running:
            self._read_tls()
            rlist, wlist, _ = select.select([self.vnc, self.tls], [self.tls] if self._want_write else [], [])
            if self.tls in rlist or (self._want_write and self.tls in wlist):
                self._read_tls()
            if self.vnc in rlist:
                self._read_vnc()

    def __exit__(self, type, value, traceback):
        self.vnc.close()
        return super().__exit__(type, value, traceback)


class IDEActivation(Enum):
    Reset = 0x08
    Graceful = 0x10
    Immediate = 0x18

class IDEClient(RedirClient):
    def __init__(self, client, activation, a_type="auto", a_filename=None, b_type="auto", b_filename=None):
        super().__init__(client, b"IDER")
        self.activation = activation
        if a_type == "auto":
            a_type = "floppy"
        if b_type == "auto":
            b_type = "cd"
        self.devices = {
            0xA0: (a_type, a_filename,
                   0 if a_filename is None else os.stat(a_filename).st_size,
                   None if a_filename is None else open(a_filename, "rb")),
            0xB0: (b_type, b_filename,
                   0 if b_filename is None else os.stat(b_filename).st_size,
                   None if b_filename is None else open(b_filename, "rb")),
        }
        self.ready = set()
        self.message_lengths.update({
            0x40: (17, 0),
            0x41: (28, 1),
            0x46: (8, 0),
            0x47: (7, 0),
            0x48: (12, 0),
            0x49: (12, 0),
            0x50: (27, 0),
        })

    def start(self):
        super().start()

        # Open session
        rx_timeout = 30000
        tx_timeout = 0
        heartbeat = 20000
        version = 1
        self._send_seq_msg([0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] + list(struct.pack("<HHHI", rx_timeout, tx_timeout, heartbeat, version)))

        cmd, _ = self._recv_msg()
        assert cmd[0] == 0x41, bytes(cmd)
        self.major, self.minor, self.fwmajor, self.fwminor, self.readbfr, self.writebfr, self.proto, self.iana = struct.unpack("<BBBBxxxxHHxBxxI", bytes(cmd[8:28]))
        assert self.proto == 0, self.proto
        assert self.readbfr <= 8192, self.readbfr
        assert self.writebfr <= 8192, self.writebfr

        # Set features
        self._send_seq_msg([0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01 | self.activation.value, 0x00, 0x00, 0x00])
        cmd, _= self._recv_msg()
        assert cmd[0] == 0x49, bytes(cmd)
        type, value = struct.unpack("<BI", bytes(cmd[8:13]))
        assert type == 3, (type, value)
        assert value == 1, (type, value)

        print("IDE redirection started")
        self.running = True

    def loop(self):
        while True:
            cmd, data = self._recv_msg()

            if cmd[0] == 0x46: # Reset occurred
                self._send_seq_msg([0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            elif cmd[0] == 0x50: # Command written
                device = 0xB0 if (cmd[14] & 0x10) else 0xA0
                device_flags = cmd[14]
                cdb = cmd[16:28]
                feature_reg = cmd[9]
                print("SCSI_CMD {0:02X} {1} {2:02X} {3:02X}".format(device, cdb, feature_reg, device_flags))
                self.scsi_cmd(device, cdb, feature_reg, device_flags)
            else:
                print(bytes(cmd), data)
    
    def scsi_cmd(self, dev, cdb, feature_reg, dev_flags):
        cfg = self.devices.get(dev, (None, None))

        if cdb[0] == 0x00: # TEST_UNIT_READY
            print("SCSI: TEST_UNIT_READY {0:02X}".format(dev))

            if cfg[1] is None:
                self.send_cmd_end(1, 0x02, dev, 0x3A, 0x00)
                return

            if dev not in self.ready:
                self.ready.add(dev)
                self.send_cmd_end(1, 0x06, dev, 0x28, 0x00) # Switch to ready
                return

            self.send_cmd_end(1, 0x00, dev, 0x00, 0x00) # Indicate ready
        elif cdb[0] == 0x08: # READ_6
            lba = ((cdb[1] & 0x1F) << 16) | (cdb[2] << 8) | cdb[3]
            length = cdb[4]
            if length == 0:
                length = 256
            print("SCSI: READ_6 {0:02X} {1:08X} {2}".format(dev, lba, length))
            self.read_disk(dev, lba, len, feature_reg)
        elif cdb[1] == 0x0A: # WRITE_6
            print("SCSI: READ_6 {0:02X} {1:08X} {2}".format(dev, lba, length))
            self.send_cmd_end(1, 0x02, dev, 0x3A, 0x00) # Write not supported
        #elif cdb[1] == 0x15: # MODE_SELECT_6
        elif cdb[1] == 0x1A: # MODE_SENSE_6
            print("SCSI: MODE_SENSE_6 {0:02X}".format(dev))
            
            if cdb[2] == 0x3F and cdb[3] == 0x00:
                if cfg[1] is None:
                    self.send_cmd_end(1, 0x02, dev, 0x3A, 0x00)
                    return

                # 0x80 read only
                # 0x00 read write
                if "cd" in cfg[0]:
                    self.send_data(dev, True, bytes([0x00, 0x05, 0x80, 0x00]), feature_reg & 1)
                else:
                    self.send_data(dev, True, bytes([0x00, 0x00, 0x80, 0x00]), feature_reg & 1)
                return
            
            self.send_cmd_end(1, 0x05, dev, 0x24, 0x00)
        elif cdb[1] == 0x1B: # START_STOP
            print("SCSI: START_STOP {0:02X}".format(dev))

            immediate = (cdb[1] & 0x01) != 0
            loej = (cdb[4] & 0x02) != 0
            start = (cdb[4] & 0x01) != 0
            self.send_cmd_end(1, 0, dev)
        elif cdb[1] == 0x1E: # ALLOW_MEDIUM_REMOVAL
            print("SCSI: ALLOW_MEDIUM_REMOVAL {0:02X}".format(dev))

            if cfg[1] is None:
                self.send_cmd_end(1, 0x02, dev, 0x3A, 0x00)
                return

            self.send_cmd_end(1, 0x00, dev, 0x00, 0x00)
        elif cdb[1] == 0x23: # READ_FORMAT_CAPACITIES
            print("SCSI: READ_FORMAT_CAPACITIES {0:02X}".format(dev))

            buflen = (cdb[7] << 16) | cdb[8]
            self.send_data(dev, True, bytes([0, 0, 0, 8] + [0x00, 0x00, 0x0B, 0x40, 0x02, 0x00, 0x02, 0x00]), feature_reg & 1)
        elif cdb[1] == 0x25: # READ_CAPACITY
            print("SCSI: READ_CAPACITY {0:02X}".format(dev))

            if cfg[1] is None or cfg[2] == 0:
                self.send_cmd_end(0, 0x02, dev, 0x3A, 0x00)
                return
            
            if "cd" in cfg[0]:
                length = (cfg[3] >> 11) - 1 # 2048 byte blocks
                blocks = 0x08
            else:
                length = (cfg[3] >> 9) - 1 # 512 byte blocks
                blocks = 0x02

            self.send_data(dev_flags, True, bytes([(length >> 24) & 0xFF,
                                                   (length >> 16) & 0xFF,
                                                   (length >> 8) & 0xFF,
                                                   length & 0xFF]
                                                   + [0, 0, blocks]), feature_reg & 1)
        elif cdb[1] == 0x28: # READ_10
            lba = (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5]
            length = (cdb[7] << 16) | cdb[7]
            print("SCSI: READ_10 {0:02X} {1:08X} {2}".format(dev, lba, length))
            self.read_disk(dev, lba, len, feature_reg)
        elif cdb[1] in [0x2A, 0x2E]: # WRITE_10, WRITE_AND_VERIFY
            lba = (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5]
            length = ((cdb[7] << 16) | cdb[7]) * 512
            print("SCSI: WRITE_10 {0:02X} {1:08X} {2}".format(dev, lba, length))
            self.send_cmd(0x52, bytes([0, (length & 0xFF), (length >> 8) & 0xFF, 0, 0xB5, 0, 0, 0, (length & 0xFF), (length >> 8) & 0xFF, dev, 0x58, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), False)
        elif cdb[1] == 0x43: # READ_TOC
            buflen = (cdb[7] << 8) | cdb[8]
            msf = (cdb[1] & 0x02) != 0
            format = (cdb[2] & 0x07) != 0
            if format == 0:
                format = cdb[9] >> 6
            print("SCSI: READ_TOC {0:02X} {1} {2} {3}".format(dev, buflen, msf, format))

            if "cd" not in cfg[0]:
                self.send_cmd_end(1, 0x05, dev, 0x20, 0x00)
                return

            if format == 1:
                self.send_data(dev, True, bytes([0x00, 0x0a, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]), feature_reg & 0x01)
            elif format == 0:
                if msf:
                    self.send_data(dev, True, bytes([0x00, 0x12, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x14, 0xaa, 0x00, 0x00, 0x00, 0x34, 0x13]), feature_reg & 0x01)
                else:
                    self.send_data(dev, True, bytes([0x00, 0x12, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00]), feature_reg & 0x01)
        elif cdb[1] == 0x46: # GET_CONFIGURATION
            sendall = (cdb[1] != 2)
            firstcode = (cdb[2] << 8) | cdb[3]
            buflen = (cdb[7] << 8) | cdb[8]
            print("SCSI: GET_CONFIGURATION {0:02X} {1} {2} {3}".format(dev, sendall, firstcode, buflen))
            
            if buflen == 0:
                self.send_data(dev, True, bytes([0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x08]), feature_reg & 1) # FIXME
            
            r = [0x00, 0x00, 0x00, 0x08]

            if firstcode == 0x00:
                r.extend(IDE_CD_ConfigArrayProfileList)
            if firstcode == 0x01 or (sendall and (firstcode < 0x01)):
                r.extend(IDE_CD_ConfigArrayCore)
            if firstcode == 0x02 or (sendall and (firstcode < 0x02)):
                r.extend(IDE_CD_Morphing)
            if firstcode == 0x03 or (sendall and (firstcode < 0x03)):
                r.extend(IDE_CD_ConfigArrayRemovable)
            if firstcode == 0x10 or (sendall and (firstcode < 0x10)):
                r.extend(IDE_CD_ConfigArrayRandom)
            if firstcode == 0x1E or (sendall and (firstcode < 0x1E)):
                r.extend(IDE_CD_Read)
            if firstcode == 0x100 or (sendall and (firstcode < 0x100)):
                r.extend(IDE_CD_PowerManagement)
            if firstcode == 0x105 or (sendall and (firstcode < 0x105)):
                r.extend(IDE_CD_Timeout)

            r.extend([(len(r) >> 24) & 0xFF, (len(r) >> 16) & 0xFF, (len(r) >> 8) & 0xFF, len(r) & 0xFF])
            if len(r) > buflen:
                r = r[0:buflen]

            self.send_data(dev, True, bytes(r), feature_reg & 1)
        elif cdb[1] == 0x4A: # GET_EVENT_STATUS_NOTIFICATION
            pass


















