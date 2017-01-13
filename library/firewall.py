#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: firewall
short_description: Module for firewall role
requirements: python-firewall for firewalld or system-config-firewall/lokkit.
description:
  - Manage firewall with firewalld on RHEL-7 or system-config-firewall/lokkit on RHEL-6.
author: "Thomas Woerner (twoerner@redhat.com)"
options:
  service:
    description:
      - "Name of a service to add or remove inbound access to. The service needs to be defined in firewalld or system-config-firewall/lokkit configuration."
    required: false
    default: null
  port:
    description:
      - "Port or port range to add or remove inbound access to. It needs to be in the format port=<port>[-<port>]/<protocol>."
    required: false
    default: null
  trust:
    description:
      - "Interface to add or remove to the trusted interfaces."
    required: false
    default: null
  trust_by_mac:
    description:
      - "Interface to add or remove to the trusted interfaces by MAC address."
    required: false
    default: null
  masq:
    description:
      - "Interface to add or remove to the interfaces that are masqueraded."
    required: false
    default: null
  masq_by_mac:
    description:
      - "Interface to add or remove to the interfaces that are masqueraded by MAC address."
    required: false
    default: null
  forward_port:
    description:
      - "Add or remove port forwarding for ports or port ranges over an interface. It needs to be in the format <interface>,<port>[-<port>]/<protocol>,[<to-port>],[<to-addr>]."
    required: false
    default: null
  forward_port_by_mac:
    description:
      - "Add or remove port forwarding for ports or port ranges over an interface itentified ba a MAC address. It needs to be in the format <interface>,<port>[-<port>]/<protocol>,[<to-port>],[<to-addr>]."
    required: false
    default: null
  state:
    description:
      - "Enable or disable the entry."
    required: true
    choices: [ "enabled", "disabled" ]
'''

import os, os.path
import sys

try:
    from firewall.client import FirewallClient
    try:
        from firewall.core.fw_nm import nm_is_imported, \
            nm_get_connection_of_interface, nm_get_zone_of_connection, \
            nm_set_zone_of_connection
        HAS_FIREWALLD_NM = True
    except ImportError:
        HAS_FIREWALLD_NM = False
    HAS_FIREWALLD = True
    HAS_SYSTEM_CONFIG_FIREWALL = False
except ImportError:
    HAS_FIREWALLD = False
    HAS_FIREWALLD_NM = False
    try:
        sys.path.append('/usr/share/system-config-firewall')
        import fw_lokkit
        from fw_functions import getPortRange
        HAS_SYSTEM_CONFIG_FIREWALL = True
    except ImportError:
        HAS_SYSTEM_CONFIG_FIREWALL = False

def try_set_zone_of_interface(_zone, interface):
    """Try to set zone of interface with NetworkManager"""
    if not HAS_FIREWALLD_NM:
        return False
    if nm_is_imported():
        try:
            connection = nm_get_connection_of_interface(interface)
        except Exception:
            pass
        else:
            if connection is not None:
                nm_set_zone_of_connection(_zone, connection)
                return True
    return False

class ifcfg(object):
    """ifcfg file reader class"""
    def __init__(self, filename):
        self._config = { }
        self._deleted = [ ]
        self.filename = filename
        self.clear()

    def clear(self):
        self._config = { }
        self._deleted = [ ]

    def cleanup(self):
        self._config.clear()

    def get(self, key):
        return self._config.get(key.strip())

    def set(self, key, value):
        _key = key.strip()
        self._config[_key] = value.strip()
        if _key in self._deleted:
            self._deleted.remove(_key)

    def read(self):
        self.clear()
        try:
            f = open(self.filename, "r")
        except Exception:
            raise

        for line in f:
            if not line:
                break
            line = line.strip()
            if len(line) < 1 or line[0] in ['#', ';']:
                continue
            # get key/value pair
            pair = [ x.strip() for x in line.split("=", 1) ]
            if len(pair) != 2:
                continue
            if len(pair[1]) >= 2 and \
               pair[1].startswith('"') and pair[1].endswith('"'):
                pair[1] = pair[1][1:-1]
            if pair[1] == '':
                continue
            elif self._config.get(pair[0]) is not None:
                continue
            self._config[pair[0]] = pair[1]
        f.close()

def get_device_for_mac(mac_addr):
    """Get device for the MAC address from ifcfg file"""

    IFCFGDIR = "/etc/sysconfig/network-scripts"
    # Return quickly if config.IFCFGDIR does not exist
    if not os.path.exists(IFCFGDIR):
        return None

    for filename in sorted(os.listdir(IFCFGDIR)):
        if not filename.startswith("ifcfg-"):
            continue
        for ignored in [ ".bak", ".orig", ".rpmnew", ".rpmorig", ".rpmsave",
                         "-range" ]:
            if filename.endswith(ignored):
                continue
        if "." in filename:
            continue
        ifcfg_file = ifcfg("%s/%s" % (IFCFGDIR, filename))
        ifcfg_file.read()
        hwaddr = ifcfg_file.get("HWADDR")
        device = ifcfg_file.get("DEVICE")
        if hwaddr and device and hwaddr.lower() == mac_addr.lower():
            return device
    return None

def main():
    module = AnsibleModule(
        argument_spec = dict(
            service=dict(required=False, default=None),
            port=dict(required=False, default=None),
            trust=dict(required=False, default=None),
            trust_by_mac=dict(required=False, default=None),
            masq=dict(required=False, default=None),
            masq_by_mac=dict(required=False, default=None),
            forward_port=dict(required=False, default=None),
            forward_port_by_mac=dict(required=False, default=None),
            state=dict(choices=['enabled', 'disabled'], required=True),
        ),
        supports_check_mode=True
    )

    service = module.params['service']
    if module.params['port'] is not None:
        port, protocol = module.params['port'].split('/')
        if protocol is None:
            module.fail_json(msg='improper port format (missing protocol?)')
    else:
        port = None
    trust = module.params['trust']
    trust_by_mac = module.params['trust_by_mac']
    if trust_by_mac is not None:
        interface = get_device_for_mac(trust_by_mac)
        if interface is None:
            module.fail_json(msg='MAC address not found')
    masq = module.params['masq']
    masq_by_mac = module.params['masq_by_mac']
    if masq_by_mac is not None:
        interface = get_device_for_mac(masq_by_mac)
        if interface is None:
            module.fail_json(msg='MAC address not found')
    if module.params['forward_port'] is not None:
        args = module.params['forward_port'].split(",")
        if len(args) != 4:
            module.fail_json(msg='improper forward_port format')
        interface, _port, to_port, to_addr = args
        forward_port, protocol = _port.split('/')
        if protocol is None:
            module.fail_json(msg='improper port format (missing protocol?)')
        if to_port == "":
            to_port = None
        if to_addr == "":
            to_addr = None
    else:
        forward_port = None
    if module.params['forward_port_by_mac'] is not None:
        args = module.params['forward_port_by_mac'].split(",")
        if len(args) != 4:
            module.fail_json(msg='improper port format')
        mac_addr, _port, to_port, to_addr = args
        forward_port_by_mac, protocol = _port.split('/')
        if protocol is None:
            module.fail_json(msg='improper port format (missing protocol?)')
        if to_port == "":
            to_port = None
        if to_addr == "":
            to_addr = None
        interface = get_device_for_mac(mac_addr)
        if interface is None:
            module.fail_json(msg='MAC address not found')
    else:
        forward_port_by_mac = None
    desired_state = module.params['state']

    modification_count = 0
    if service is not None:
        modification_count += 1
    if port is not None:
        modification_count += 1
    if trust is not None:
        modification_count += 1
    if trust_by_mac is not None:
        modification_count += 1
    if masq is not None:
        modification_count += 1
    if masq_by_mac is not None:
        modification_count += 1
    if forward_port is not None:
        modification_count += 1

    if modification_count > 1:
        module.fail_json(msg='can only operate on one of service, port, " + \
        "trust, trust-by-mac, masq, masq-by-mac, forward_port or " + \
        "forward_port_by_mac at once')

    if not HAS_FIREWALLD and not HAS_SYSTEM_CONFIG_FIREWALL:
        module.fail_json(msg='No firewall backend could be imported.')

    if HAS_FIREWALLD:
        fw = FirewallClient()

        def exception_handler(exception_message):
            module.fail_json(msg=exception_message)
        fw.setExceptionHandler(exception_handler)

        if not fw.connected:
            module.fail_json(msg='firewalld service must be running')

        trusted_zone = "trusted"
        external_zone = "external"
        default_zone = fw.getDefaultZone()
        fw_zone = fw.config().getZoneByName(default_zone)
        fw_settings = fw_zone.getSettings()

        if service is not None:
            if desired_state == "enabled":
                if not fw_settings.queryService(service):
                    fw_settings.addService(service)
                    fw_zone.update(fw_settings)
                    #fw.reload()
                    if module.check_mode:
                        module.exit_json(changed=True)
            elif desired_state == "disabled":
                if fw_settings.queryService(service):
                    fw_settings.removeService(service)
                    fw_zone.update(fw_settings)
                    #fw.reload()
                    if module.check_mode:
                        module.exit_json(changed=True)

        if port is not None:
            if desired_state == "enabled":
                if not fw_settings.queryPort(port, protocol):
                    fw_settings.addPort(port, protocol)
                    fw_zone.update(fw_settings)
                    #fw.reload()
                    if module.check_mode:
                        module.exit_json(changed=True)
            elif desired_state == "disabled":
                if fw_settings.queryPort(port, protocol):
                    fw_settings.removePort(port, protocol)
                    fw_zone.update(fw_settings)
                    #fw.reload()
                    if module.check_mode:
                        module.exit_json(changed=True)

        if trust is not None or trust_by_mac is not None:
            if trust_by_mac is not None:
                trust = interface

            if default_zone != trusted_zone:
                fw_zone = fw.config().getZoneByName(trusted_zone)
                fw_settings = fw_zone.getSettings()
            if desired_state == "enabled":
                if try_set_zone_of_interface(trusted_zone, trust):
                    if module.check_mode:
                        module.exit_json(changed=True)
                else:
                    if not fw_settings.queryInterface(trust):
                        fw_settings.addInterface(trust)
                        fw_zone.update(fw_settings)
                        #fw.reload()
                        if module.check_mode:
                            module.exit_json(changed=True)
            elif desired_state == "disabled":
                if try_set_zone_of_interface("", trust):
                    if module.check_mode:
                        module.exit_json(changed=True)
                else:
                    if fw_settings.queryInterface(trust):
                        fw_settings.removeInterface(trust)
                        fw_zone.update(fw_settings)
                        #fw.reload()
                        if module.check_mode:
                            module.exit_json(changed=True)

        if masq is not None or masq_by_mac is not None:
            if masq_by_mac is not None:
                masq = interface

            if default_zone != external_zone:
                fw_zone = fw.config().getZoneByName(external_zone)
                fw_settings = fw_zone.getSettings()
            if desired_state == "enabled":
                if try_set_zone_of_interface(external_zone, masq):
                    if module.check_mode:
                        module.exit_json(changed=True)
                else:
                    if not fw_settings.queryInterface(masq):
                        fw_settings.addInterface(masq)
                        fw_zone.update(fw_settings)
                        #fw.reload()
                        if module.check_mode:
                            module.exit_json(changed=True)
            elif desired_state == "disabled":
                if try_set_zone_of_interface("", masq):
                    if module.check_mode:
                        module.exit_json(changed=True)
                else:
                    if fw_settings.queryInterface(masq):
                        fw_settings.removeInterface(masq)
                        fw_zone.update(fw_settings)
                        #fw.reload()
                        if module.check_mode:
                            module.exit_json(changed=True)

        if forward_port is not None or forward_port_by_mac is not None:
            if forward_port_by_mac is not None:
                _port = forward_port_by_mac
            else:
                _port = forward_port
            if interface != "":
                _zone = fw.getZoneOfInterface(interface)
                if _zone != "" and _zone != default_zone:
                    fw_zone = fw.config.getZoneByName(_zone)
                    fw_settings = fw_zone.getSettings()

            if desired_state == "enabled":
                if not fw_settings.queryForwardPort(_port, protocol,
                                                    to_port, to_addr):
                    fw_settings.addForwardPort(_port, protocol,
                                               to_port, to_addr)
                    fw_zone.update(fw_settings)
                    #fw.reload()
                    if module.check_mode:
                        module.exit_json(changed=True)
            elif desired_state == "disabled":
                if fw_settings.queryForwardPort(_port, protocol,
                                                to_port, to_addr):
                    fw_settings.removeForwardPort(_port, protocol,
                                                  to_port, to_addr)
                    fw_zone.update(fw_settings)
                    #fw.reload()
                    if module.check_mode:
                        module.exit_json(changed=True)


    elif HAS_SYSTEM_CONFIG_FIREWALL:
        (config, old_config, _) = fw_lokkit.loadConfig(args=[])

        if service is not None:
            if config.services is None:
                config.services = [ ]
            if desired_state == "enabled":
                if service not in config.services:
                    config.services.append(service)
                    fw_lokkit.updateFirewall(config, old_config)
                    if module.check_mode:
                        module.exit_json(changed=True)
            elif desired_state == "disabled":
                if service in config.services:
                    config.services.remove(service)
                    fw_lokkit.updateFirewall(config, old_config)
                    if module.check_mode:
                        module.exit_json(changed=True)

        if port is not None:
            if config.ports is None:
                config.ports = [ ]
            _range = getPortRange(port)
            if _range < 0:
                module.fail_json(msg='invalid port definition')
            elif _range is None:
                module.fail_json(msg='port _range is not unique.')
            elif len(_range) == 2 and _range[0] >= _range[1]:
                module.fail_json(msg='invalid port range')
            port_proto = (_range, protocol)
            if desired_state == "enabled":
                if port_proto not in config.ports:
                    config.ports.append(port_proto)
                    fw_lokkit.updateFirewall(config, old_config)
                    if module.check_mode:
                        module.exit_json(changed=True)
            elif desired_state == "disabled":
                if port_proto in config.ports:
                    config.ports.remove(port_proto)
                    fw_lokkit.updateFirewall(config, old_config)
                    if module.check_mode:
                        module.exit_json(changed=True)

        if trust is not None or trust_by_mac is not None:
            if config.trust is None:
                config.trust = [ ]

            if trust_by_mac is not None:
                trust = interface

            if desired_state == "enabled":
                if trust not in config.trust:
                    config.trust.append(trust)
                    fw_lokkit.updateFirewall(config, old_config)
                    if module.check_mode:
                        module.exit_json(changed=True)
            elif desired_state == "disabled":
                if trust in config.trust:
                    config.trust.remove(trust)
                    fw_lokkit.updateFirewall(config, old_config)
                    if module.check_mode:
                        module.exit_json(changed=True)

        if masq is not None or masq_by_mac is not None:
            if config.masq is None:
                config.masq = [ ]

            if masq_by_mac is not None:
                masq = interface

            if desired_state == "enabled":
                if masq not in config.masq:
                    config.masq.append(masq)
                    fw_lokkit.updateFirewall(config, old_config)
                    if module.check_mode:
                        module.exit_json(changed=True)
            elif desired_state == "disabled":
                if masq in config.masq:
                    config.masq.remove(masq)
                    fw_lokkit.updateFirewall(config, old_config)
                    if module.check_mode:
                        module.exit_json(changed=True)

        if forward_port is not None or forward_port_by_mac is not None:
            if config.forward_port is None:
                config.forward_port = [ ]

            if forward_port_by_mac is not None:
                _port = forward_port_by_mac
            else:
                _port = forward_port
            _range = getPortRange(_port)
            if _range < 0:
                module.fail_json(msg='invalid port definition')
            elif _range is None:
                module.fail_json(msg='port _range is not unique.')
            elif len(_range) == 2 and _range[0] >= _range[1]:
                module.fail_json(msg='invalid port range')
            fwd_port = { "if": interface, "port": _range, "proto": protocol }
            if to_port is not None:
                _range = getPortRange(to_port)
                if _range < 0:
                    module.fail_json(msg='invalid port definition %s' % to_port)
                elif _range is None:
                    module.fail_json(msg='port _range is not unique.')
                elif len(_range) == 2 and _range[0] >= _range[1]:
                    module.fail_json(msg='invalid port range')
                fwd_port["toport"] = _range
            if to_addr is not None:
                fwd_port["toaddr"] = to_addr

            if desired_state == "enabled":
                if fwd_port not in config.forward_port:
                    config.forward_port.append(fwd_port)
                    fw_lokkit.updateFirewall(config, old_config)
                    if module.check_mode:
                        module.exit_json(changed=True)
            elif desired_state == "disabled":
                if fwd_port in config.forward_port:
                    config.forward_port.remove(fwd_port)
                    fw_lokkit.updateFirewall(config, old_config)
                    if module.check_mode:
                        module.exit_json(changed=True)

    else:
        module.fail_json(msg='No firewalld and system-config-firewall')

    msgs = [ ]
    module.exit_json(changed=False, msg=', '.join(msgs))

#################################################
# import module snippets
from ansible.module_utils.basic import *

main()
