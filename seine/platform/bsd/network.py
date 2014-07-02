
import os
import sys
import re

from subprocess import check_output, CalledProcessError

from seine.address import IPv4Address, IPv6Address, \
                          EthernetMACAddress, FirewireLocalLinkAddress
from seine.classes import NetworkInterface, NetworkAddress, NetworkInterfaceList, \
                          Route, RoutingTable, ARPTable, ARPTableEntry, NetworkError


if sys.platform == 'darwin':
    NETSTAT = '/usr/sbin/netstat'
else:
    NETSTAT = '/usr/bin/netstat'


ARP_ENTRY_FORMATS = (
    re.compile('^\? \((?P<address>[0-9.]+)\) at (?P<ethernet>[^\s]+) on (?P<interface>[^\s]+) ifscope (?P<ifscope>.*)$'),
    re.compile('^\? \((?P<address>[0-9.]+)\) at (?P<ethernet>[^\s]+) on (?P<interface>[^\s]+) permanent (?P<ifscope>.*)$'),
    re.compile('^\? \((?P<address>[0-9.]+)\) at (?P<ethernet>[^\s]+) on (?P<interface>[^\s]+) expires in (?P<expires>\d+) seconds (?P<ifscope>.*)$'),
)

NETSTAT_HEADER_MATCHES = (
    re.compile('^Routing tables$'),
    re.compile('^Internet:$'),
    re.compile('^Internet6:$'),
    re.compile('^Destination\s+.*$'),
)

IPV6_ROUTE_ADDRESS_FORMATS = (
    re.compile('^(?P<address>[0-9a-f:]+)$'),
    re.compile('^(?P<address>[0-9a-f:.]+)/(?P<bitmask>\d+)$'),
    re.compile('^(?P<address>.*)%(?P<interface>[a-z0-9]+)$'),
    re.compile('^(?P<address>.*)%(?P<interface>[a-z0-9]+)/(?P<bitmask>\d+)$'),
)

def parse_ipv4_route_target(value):
    if value == 'default':
        return IPv4Address('0.0.0.0/0')

    elif value[:5] == 'link#':
        return value

    else:
        try:
            return EthernetMACAddress(value)
        except ValueError:
            pass

    return IPv4Address(value)


def parse_ipv6_route_target(value):
    if value == 'default':
        return IPv6Address('0::/0')

    elif value[:5] == 'link#':
        return value

    else:
        try:
            return EthernetMACAddress(value)
        except ValueError:
            pass

    for fmt in IPV6_ROUTE_ADDRESS_FORMATS:
        m = fmt.match(value)
        if m:
            return IPv6Address('%s/%s' % (
                m.groupdict()['address'],
                m.groupdict().get('bitmask', 128),
            ))
            break

    raise ValueError('Error parsing address from %s' % value)


class BSDNetworkAddress(NetworkAddress):
    def __init__(self, family, address, options=[]):
        NetworkAddress.__init__(self, family, address, options)

    def parse_options(self, options):
        if self.family == 'inet':
            option = None

            while options:
                if option is None:
                    option = options[0]

                elif option in ( 'netmask', 'broadcast'):
                    try:
                        value = IPv4Address(options[0])
                    except ValueError:
                        raise NetworkError('Error parsing %s %s' % (option, value))

                    if option == 'netmask':
                        self.address = IPv4Address(self.address, value)

                    if option == 'broadcast':
                        value = IPv4Address('%s/32' % value)
                        self.broadcast = value

                    option = None

                options = options[1:]

        if self.family == 'inet6':

            try:
                address, interface = self.address.split('%')
                self.address = IPv6Address(address)
                self.interface = interface

            except ValueError:
                self.address = IPv6Address(self.address)
                self.interface = None

            option = None
            while options:
                option = options[0]

                if option == 'prefixlen':
                    self.address = IPv6Address('%s/%s' % (self.address.address, options[1]))
                    options = options[1:]

                elif option == 'scopeid':
                    self.flags['scope_id'] = options[1]
                    options = options[1:]

                elif option in ( 'deprecated', 'autoconf', 'temporary', ):
                    if option not in self.flags.keys():
                        self.flags[option] = True

                options = options[1:]


class BSDNetworkInterface(NetworkInterface):
    def __init__(self, name):
        NetworkInterface.__init__(self, name)


    def __parse_status__(self, fields):
        value = ' '.join(fields)

        if value == 'active':
            self.media_status = True

        elif value == 'inactive':
            self.media_status = False

        else:
            raise ValueError('Unsupported status field value: %s' % value)

    def __parse_options__(self, fields):
        index, options = fields.rstrip('>').split('<',1)
        for key in options.split(','):
            self.options[key] = True

    def __parse_nd6_options__(self, fields):
        index, options = fields.rstrip('>').split('<',1)
        for key in options.split(','):
            self.nd6_options[key] = True

    def __parse_media__(self, fields):
        if fields[0] == 'autoselect' or fields[:2] == ['Ethernet', 'autoselect']:
            self.media_config = ' '.join(fields[1:2])
            if len(fields) == 1:
                media_type = None
            elif fields[1] == '(none)':
                self.media_state = None
            else:
                states = [x.lstrip('(').rstrip(')').lstrip('<').rstrip('>') for x in fields[1:]]
                self.media_state = states

        elif ' '.join(fields) == '<unknown type>':
            self.media_config = None
            self.media_state = None

        else:
            raise ValueError('Error parsing media type %s' % ' '.join(fields))

    def parse_flags(self, flags):
        fields = flags.split()
        while fields:
            if fields[0] == 'mtu':
                self.mtu = fields[1]
                fields = fields[1:]

            if fields[0][:6] == 'flags=':
                number, flags = fields[0][6:].split('<', 1)
                self.flags.extend(flags.replace('>','').split(','))

            fields = fields[1:]

    def parse_bridge_configuration(self, fields):
        if fields[0] == 'Configuration:':
            return

        if fields[0] == 'id':
            self.configuration['bridge_id'] = fields[1]
            self.configuration['bridge_priority'] = int(fields[3])
            self.configuration['bridge_hello_time'] = int(fields[5])
            self.configuration['bridge_fwd_delay'] = int(fields[7])

        elif fields[0] == 'member:':
            if 'bridge_member_interfaces' not in self.configuration:
                self.configuration['bridge_member_interfaces'] = {}

            config = {}
            if fields[2][:6] == 'flags=':
                index, flags = fields[2][6:].split('<',1)
                config['index'] = index
                config['flags'] = flags.replace('>', '').split(',')
                self.configuration['bridge_member_interfaces'][fields[1]] = config

        elif fields[0] == 'maxage':
            self.configuration['bridge_max_age'] = int(fields[1])
            self.configuration['bridge_hold_count'] = int(fields[3])
            self.configuration['bridge_proto'] = fields[5]
            self.configuration['bridge_max_addr'] = int(fields[7])
            self.configuration['bridge_timeout'] = int(fields[9])

        elif fields[0] == 'ifmaxaddr':
            self.configuration['bridge_ifmaxaddr'] = int(fields[1])
            self.configuration['bridge_ifmaxaddr_port'] = int(fields[3])
            self.configuration['bridge_ifmaxaddr_priority'] = int(fields[5])
            self.configuration['bridge_ifmaxaddr_path_cost'] = int(fields[8])

        elif fields[0] == 'ipfilter':
            self.configuration['bridge_ipfilter_status'] = fields[1]
            self.configuration['bridge_ipfilter_flags'] = fields[3]

        elif ' '.join(fields[:2]) == 'root id':
            self.configuration['bridge_root_id'] = fields[2]
            self.configuration['bridge_root_priority'] = int(fields[4])
            self.configuration['bridge_root_ifcost'] = int(fields[6])
            self.configuration['bridge_root_port'] = int(fields[8])

    def parse(self, line):
        line = line.lstrip()
        fields = line.split()

        if fields[0] == 'inet':
            self.ipv4_addresses.append(BSDNetworkAddress('inet', fields[1], fields[2:]))

        elif fields[0] == 'inet6':
            self.ipv6_addresses.append(BSDNetworkAddress('inet6', fields[1], fields[2:]))

        elif fields[0] == 'ether':
            self.media = EthernetMACAddress(fields[1])

        elif fields[0] == 'lladdr':
            self.media = FirewireLocalLinkAddress(fields[1])

        elif fields[0] == 'status:':
            self.__parse_status__(fields[1:])

        elif fields[0] == 'media:':
            self.__parse_media__(fields[1:])

        elif fields[0][:8] == 'options=':
            self.__parse_options__(fields[0][8:])

        elif fields[0] == 'nd6':
            self.__parse_nd6_options__(fields[1])

        elif self.name[:6] == 'bridge':
            self.parse_bridge_configuration(fields)

        elif fields[0] == 'vlan:':
            self.vlan_id = fields[1]
            self.vlan_device = fields[4]


class BSDNetworkInterfaces(NetworkInterfaceList):
    def update(self):
        self.__delslice__(0, len(self))

        try:
            output = check_output(['/sbin/ifconfig'])
        except CalledProcessError, emsg:
            raise NetworkError('Error getting interfaces: %s' % emsg)

        interface = None
        for l in [l for l in output.split('\n') if l.strip() != '']:
            if l.startswith('\t'):
                interface.parse(l)

            else:
                name, flags = l.split(':', 1)
                interface = BSDNetworkInterface(name)
                interface.parse_flags(flags)
                self.append(interface)


class IPv4RouteEntry(Route):
    def __init__(self, table, line):
        fields = line.split()

        address = parse_ipv4_route_target(fields[0])
        target = parse_ipv4_route_target(fields[1])
        flags = fields[2]
        refs = int(fields[3])
        use = int(fields[3])
        interface = fields[4]

        if len(fields) == 6:
            expires = fields[5]
        else:
            expires = None

        Route.__init__(self, table, address, target, flags=flags, refs=refs, use=use, interface=interface, expires=expires)

    def __str__(self):
        return '%s %s' % (self.address, self.target)


class IPv6RouteEntry(Route):
    def __init__(self, table, line):
        fields = line.split()

        address = parse_ipv6_route_target(fields[0])
        target = parse_ipv6_route_target(fields[1])
        flags = fields[2]
        interface = fields[3]

        if len(fields) == 5:
            expires = fields[4]
        else:
            expires = None

        Route.__init__(self, table, address, target, flags=flags, interface=interface, expires=expires)

    def __str__(self):
        return '%s %s' % (self.address, self.target)


class BSDRoutes(RoutingTable):
    """BSD style netstat parsing

    Parse BSD style netstat -rn outputs

    """
    def update(self):
        self.ipv4 = []
        self.ipv6 = []

        try:
            output = check_output([NETSTAT, '-rn', '-f', 'inet'])
        except CalledProcessError, emsg:
            raise NetworkError('Error getting IPv4 routes: %s' % emsg)

        interface = None
        for l in [l for l in output.split('\n') if l.strip() != '']:
            if l.strip() == '':
                continue
            header = False
            for m in NETSTAT_HEADER_MATCHES:
                if m.match(l):
                    header = True
                    break
            if header:
                continue

            self.ipv4.append(IPv4RouteEntry(self, l))

        try:
            output = check_output([NETSTAT, '-rn', '-f', 'inet6'])
        except CalledProcessError, emsg:
            raise NetworkError('Error getting IPv6 routes: %s' % emsg)

        interface = None
        for l in [l for l in output.split('\n') if l.strip() != '']:
            if l.strip() == '':
                continue
            header = False
            for m in NETSTAT_HEADER_MATCHES:
                if m.match(l):
                    header = True
                    break
            if header:
                continue

            self.ipv6.append(IPv6RouteEntry(self, l))

        self.sort()

    def sort(self):
        self.ipv4.sort()
        self.ipv6.sort()


class BSDARP(ARPTable):
    def update(self):
        self.__delslice__(0, len(self))

        try:
            output = check_output(['/usr/sbin/arp', '-an'])
        except CalledProcessError, emsg:
            raise NetworkError('Error getting ARP table: %s' % emsg)

        for l in [l for l in output.split('\n') if l.strip() != '']:
            if l.strip() == '':
                continue

            for fmt in ARP_ENTRY_FORMATS:
                m = fmt.match(l)
                if m:
                    self.append(ARPTableEntry(**m.groupdict()))

