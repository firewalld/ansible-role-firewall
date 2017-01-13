ansible-role-firewall
=====================

This role configures the firewall on RHEL-6 and RHEL-7 machines using the
default firewall system.

For the configuration the role tries to use the firewalld client interface
which is available in RHEL-7. If this failes it tries to use the
system-config-firewall interface which is available in RHEL-6 and in RHEL-7
as an alternative.

Limitations
-----------

### Configuration over Network

The configuration of the firewall could limit access to the machine over the
network. Therefore it is needed to make sure that the SSH port is still
accessible for the ansible server.

### Using MAC addresses

As MAC addresses can no be used in netfilter to identify interfaces, this
role is doing a mapping from the MAC addresses to interfaces for netfilter.
The network needs to be configured before the firewall to be able to get the
mapping to interfaces.
After a MAC address change on the system, the firewall needs to be configured
again if the MAC address has been used in the configuration.

If the MAC address or an interface has been changed in RHEL-6, then it is
needed to adapt the firewall configuration also. For RHEL-7 this could be done
automatically if NetworkManager is controlling the affected interface.

### The Error Case

If the configuration failed or if the firwall configuration limits access to
the machine in a bad way, it is most likely be needed to get physical access
to the machine to fix the issue.

### Rule sorting

If you want to add forwarding rules to an interface that also is masqueraded,
then the masquerading rules needs to be sorted before the forwarding rule.


Usage
-----

$ git clone https://github.com/firewalld/ansible-role-firewall.git

This configures the firewall
$ ansible-playbook -k -i hostname, ansible-firewall-role/firewall_playbook1.yml 

This reverts the configuration from playbook1
$ ansible-playbook -k -i hostname, ansible-firewall-role/firewall_playbook2.yml


Variables
---------

### Examples

- firewall: service=ssh state=enabled
- firewall: port=444-445/tcp state=enabled
- firewall: trust=eth2 state=enabled
- firewall: trust_by_mac=00:11:22:33:44:55 state=enabled
- firewall: masq=eth3 state=enabled
- firewall: masq_by_mac=00:11:22:33:44:66 state=enabled
- firewall: forward_port=eth3,80/tcp,,10.0.0.3 state=enabled
- firewall: forward_port_by_mac=11:22:33:44:55:66,8080/tcp,81, state=enabled
