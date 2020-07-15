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

# This file is a hack and slash implementation of just-enough-wsman
# needed for the commands in amtctrl.
#
# The only python implementation is a set of bindings on openwsman
# library, which is written in C. wsman is just about building /
# parsing XML and sending HTTP requests (with digest auth). Shifting
# out to a C library to do all of this is sub optimal, when this is
# largely built into python. The python openwsman bindings are also
# not straight forward to build, so the code is hard to test, and
# quite non portable.

from xml.etree import ElementTree
import uuid

POWER_STATES = {
    'on': 2,
    'off': 8,
    'standby': 4,
    'reboot': 5,
    'reset': 10,
    'sleep': 3,
    'hibernate': 7,
}

# Valid boot devices
BOOT_DEVICES = {
    'pxe': 'Intel(r) AMT: Force PXE Boot',
    'hd': 'Intel(r) AMT: Force Hard-drive Boot',
    'cd': 'Intel(r) AMT: Force CD/DVD Boot',
}

FRIENDLY_POWER_STATE = {v: k for (k, v) in POWER_STATES.items()}

ElementTree.register_namespace("s", "http://www.w3.org/2003/05/soap-envelope")
ElementTree.register_namespace("wsa", "http://schemas.xmlsoap.org/ws/2004/08/addressing")
ElementTree.register_namespace("wsman", "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd")


def friendly_power_state(state):
    return FRIENDLY_POWER_STATE.get(int(state), 'unknown')


def get_request(uri, resource):
    xml = ElementTree.fromstring("""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
   <s:Header>
       <wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>
       <wsa:To s:mustUnderstand="true"></wsa:To>
       <wsman:ResourceURI s:mustUnderstand="true"></wsman:ResourceURI>
       <wsa:MessageID s:mustUnderstand="true"></wsa:MessageID>
       <wsa:ReplyTo>
           <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
       </wsa:ReplyTo>
   </s:Header>
   <s:Body/>
</s:Envelope>
""")  # noqa
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}To').text = uri
    xml.find('.//{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}ResourceURI').text = resource
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}MessageID').text = "uuid:" + str(uuid.uuid4())
    return ElementTree.tostring(xml)


def enumerate_begin(uri, resource):
    xml = ElementTree.fromstring("""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:e="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
   <s:Header>
       <wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</wsa:Action>
       <wsa:To s:mustUnderstand="true"></wsa:To>
       <wsman:ResourceURI s:mustUnderstand="true"></wsman:ResourceURI>
       <wsa:MessageID s:mustUnderstand="true"></wsa:MessageID>
       <wsa:ReplyTo>
           <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
       </wsa:ReplyTo>
   </s:Header>
   <s:Body>
       <e:Enumerate/>
   </s:Body>
</s:Envelope>
""")  # noqa
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}To').text = uri
    xml.find('.//{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}ResourceURI').text = resource
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}MessageID').text = "uuid:" + str(uuid.uuid4())
    return ElementTree.tostring(xml)


def enumerate_next(uri, resource, context):
    xml = ElementTree.fromstring("""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:e="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
   <s:Header>
       <wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull</wsa:Action>
       <wsa:To s:mustUnderstand="true"></wsa:To>
       <wsman:ResourceURI s:mustUnderstand="true"></wsman:ResourceURI>
       <wsa:MessageID s:mustUnderstand="true"></wsa:MessageID>
       <wsa:ReplyTo>
           <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
       </wsa:ReplyTo>
   </s:Header>
   <s:Body>
       <e:Pull>
           <e:EnumerationContext></e:EnumerationContext>
       </e:Pull>
   </s:Body>
</s:Envelope>
""")  # noqa
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}To').text = uri
    xml.find('.//{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}ResourceURI').text = resource
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/09/enumeration}EnumerationContext').text = context
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}MessageID').text = "uuid:" + str(uuid.uuid4())
    return ElementTree.tostring(xml)


def enable_remote_kvm(uri, passwd):
    xml = ElementTree.fromstring("""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
<s:Header>
<wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Put</wsa:Action>
<wsa:To s:mustUnderstand="true"></wsa:To>
<wsman:ResourceURI s:mustUnderstand="true">http://intel.com/wbem/wscim/1/ips-schema/1/IPS_KVMRedirectionSettingData</wsman:ResourceURI>
<wsa:MessageID s:mustUnderstand="true"></wsa:MessageID>
<wsa:ReplyTo>
    <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
</wsa:ReplyTo>
</s:Header>
<s:Body>
<g:IPS_KVMRedirectionSettingData xmlns:g="http://intel.com/wbem/wscim/1/ips-schema/1/IPS_KVMRedirectionSettingData">
<g:DefaultScreen>0</g:DefaultScreen>
<g:ElementName>Intel(r) KVM Redirection Settings</g:ElementName>
<g:EnabledByMEBx>true</g:EnabledByMEBx>
<g:InstanceID>Intel(r) KVM Redirection Settings</g:InstanceID>
<g:Is5900PortEnabled>true</g:Is5900PortEnabled>
<g:OptInPolicy>false</g:OptInPolicy>
<g:RFBPassword></g:RFBPassword>
<g:SessionTimeout>0</g:SessionTimeout>
</g:IPS_KVMRedirectionSettingData>
</s:Body>
</s:Envelope>""")  # noqa
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}To').text = uri
    xml.find('.//{http://intel.com/wbem/wscim/1/ips-schema/1/IPS_KVMRedirectionSettingData}RFBPassword').text = passwd
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}MessageID').text = "uuid:" + str(uuid.uuid4())
    return ElementTree.tostring(xml)


def kvm_redirect(uri):
    xml = ElementTree.fromstring("""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:n1="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_KVMRedirectionSAP">
<s:Header>
<wsa:Action s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_KVMRedirectionSAP/RequestStateChange</wsa:Action>
<wsa:To s:mustUnderstand="true"></wsa:To>
<wsman:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_KVMRedirectionSAP</wsman:ResourceURI>
<wsa:MessageID s:mustUnderstand="true"></wsa:MessageID>
<wsa:ReplyTo>
<wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
</wsa:ReplyTo>
</s:Header>
<s:Body>
<n1:RequestStateChange_INPUT>
<n1:RequestedState>2</n1:RequestedState>
</n1:RequestStateChange_INPUT>
</s:Body></s:Envelope>""")  # noqa
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}To').text = uri
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}MessageID').text = "uuid:" + str(uuid.uuid4())
    return ElementTree.tostring(xml)


def power_state_request(uri, power_state):
    xml = ElementTree.fromstring("""<?xml version="1.0" encoding="UTF-8"?>
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:n1="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_PowerManagementService">
    <s:Header>
    <wsa:Action s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_PowerManagementService/RequestPowerStateChange</wsa:Action>
    <wsa:To s:mustUnderstand="true"></wsa:To>
    <wsman:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_PowerManagementService</wsman:ResourceURI>
    <wsa:MessageID s:mustUnderstand="true"></wsa:MessageID>
    <wsa:ReplyTo>
        <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:SelectorSet>
       <wsman:Selector Name="Name">Intel(r) AMT Power Management Service</wsman:Selector>
    </wsman:SelectorSet>
    </s:Header>
    <s:Body>
      <n1:RequestPowerStateChange_INPUT>
        <n1:PowerState></n1:PowerState>
        <n1:ManagedElement>
          <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
          <wsa:ReferenceParameters>
             <wsman:ResourceURI>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ComputerSystem</wsman:ResourceURI>
             <wsman:SelectorSet>
                <wsman:Selector wsman:Name="Name">ManagedSystem</wsman:Selector>
             </wsman:SelectorSet>
           </wsa:ReferenceParameters>
         </n1:ManagedElement>
       </n1:RequestPowerStateChange_INPUT>
      </s:Body></s:Envelope>
""")  # noqa
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}To').text = uri
    xml.find('.//{http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_PowerManagementService}PowerState').text = str(POWER_STATES[power_state])
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}MessageID').text = "uuid:" + str(uuid.uuid4())
    return ElementTree.tostring(xml)


def change_boot_to_pxe_request(uri):
    return change_boot_order_request(
        uri, boot_device='pxe')


def change_boot_order_request(uri, boot_device):
    assert boot_device in BOOT_DEVICES
    xml = ElementTree.fromstring("""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:n1="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BootConfigSetting">
<s:Header>
<wsa:Action s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BootConfigSetting/ChangeBootOrder</wsa:Action>
<wsa:To s:mustUnderstand="true"></wsa:To>
<wsman:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BootConfigSetting</wsman:ResourceURI>
<wsa:MessageID s:mustUnderstand="true"></wsa:MessageID>
<wsa:ReplyTo>
    <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
</wsa:ReplyTo>
<wsman:SelectorSet>
   <wsman:Selector Name="InstanceID">Intel(r) AMT: Boot Configuration 0</wsman:Selector>
</wsman:SelectorSet>
</s:Header>
<s:Body>
  <n1:ChangeBootOrder_INPUT>
     <n1:Source>
        <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
        <wsa:ReferenceParameters>
            <wsman:ResourceURI>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BootSourceSetting</wsman:ResourceURI>
            <wsman:SelectorSet>
                <wsman:Selector wsman:Name="InstanceID"></wsman:Selector>
            </wsman:SelectorSet>
         </wsa:ReferenceParameters>
     </n1:Source>
   </n1:ChangeBootOrder_INPUT>
</s:Body></s:Envelope>""")  # noqa
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}To').text = uri
    xml.find('.//{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}Selector').text = BOOT_DEVICES[boot_device]
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}MessageID').text = "uuid:" + str(uuid.uuid4())
    return ElementTree.tostring(xml)


def enable_boot_config_request(uri):
    xml = ElementTree.fromstring("""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:n1="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BootService">
<s:Header>
<wsa:Action s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BootService/SetBootConfigRole</wsa:Action>
<wsa:To s:mustUnderstand="true"></wsa:To>
<wsman:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BootService</wsman:ResourceURI>
<wsa:MessageID s:mustUnderstand="true"></wsa:MessageID>
<wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
<wsman:SelectorSet>
    <wsman:Selector Name="Name">Intel(r) AMT Boot Service</wsman:Selector>
</wsman:SelectorSet>
</s:Header>
<s:Body>
<n1:SetBootConfigRole_INPUT>
    <n1:BootConfigSetting>
        <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
        <wsa:ReferenceParameters>
             <wsman:ResourceURI>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BootConfigSetting</wsman:ResourceURI>
             <wsman:SelectorSet>
                  <wsman:Selector wsman:Name="InstanceID">Intel(r) AMT: Boot Configuration 0</wsman:Selector>
             </wsman:SelectorSet>
        </wsa:ReferenceParameters>
    </n1:BootConfigSetting>
    <n1:Role>1</n1:Role>
</n1:SetBootConfigRole_INPUT>
</s:Body></s:Envelope>""")  # noqa
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}To').text = uri
    xml.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}MessageID').text = "uuid:" + str(uuid.uuid4())
    return ElementTree.tostring(xml)


# Local Variables:
# eval: (whitespace-mode -1)
# End:
