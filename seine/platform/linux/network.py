
import os
import re
from subprocess import check_output, CalledProcessError

from seine.address import IPv4Address, IPv6Address, \
                          EthernetMACAddress, FirewireLocalLinkAddress
from seine.classes import NetworkInterface, NetworkAddress, NetworkInterfaceList, \
                          Route, RoutingTable, ARPTable, ARPTableEntry, NetworkError

RE_INTERFACE = re.compile('^\d+: (?P<name>[^:]+): <(?P<flags>[^>]+)> mtu (?P<mtu>\d+) (?P<options>.*)$')
ARP_ENTRY_FORMATS = (
    re.compile('^\? \((?P<address>[0-9.]+)\) at (?P<ethernet>[^\s]+) (?P<ifscope>.*) on (?P<interface>[^\s]+)$'),
)

NETSTAT_HEADER_MATCHES = {
    re.compile('^Kernel IP.* routing table$'),
    re.compile('^Destination\s+.*$'),
}


def parse_ipv4_route_target(value, netmask=None):
    if value == 'default':
        return IPv4Address('0.0.0.0/0')

    elif value[:5] == 'link#':
        return value

    else:
        try:
            return EthernetMACAddress(value)
        except ValueError:
            pass

    return IPv4Address(value, netmask)


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

    return IPv6Address(value)


class LinuxNetworkAddress(NetworkAddress):
    def __init__(self, family, address, options=[]):
        NetworkAddress.__init__(self, family, address, options)

    def parse_options(self, options):
        if self.family == 'inet':
            option = None

            while options:
                if options[0] == 'scope':
                    self.flags['scope'] = options[1]
                    options = options[3:]

                elif options[0] == 'brd':
                    self.broadcast = IPv4Address('%s/32' % options[1])
                    options = options[2:]

                else:
                    options = options[1:]

        if self.family == 'inet6':
            option = None

            while options:
                if options[0] == 'scope':
                    if options[1] in ('host', 'link'):
                        self.flags['scope'] = options[1]
                        options = ' '.join(options[2:])
                    elif options[1] == 'global':
                        self.flags['scope'] = ' '.join(options[1:3])
                        options = options[3:]
                    else:
                        options = options[1:]
                else:
                    options = options[1:]


class LinuxNetworkInterface(NetworkInterface):
    def __init__(self, name):
        NetworkInterface.__init__(self, name)
        self.__latest_parsed_address = None

        if self.name.count('@') == 1:
            self.parse_vlan_options()

    def parse_vlan_options(self):
        self.name, self.vlan_device = self.name.split('@', 1)
        try:
            output = check_output(['/sbin/ip', '-d', 'link', 'show', self.name])
        except CalledProcessError, emsg:
            raise NetworkError('Error getting interfaces: %s' % emsg)

        for l in [l for l in output.split('\n')[1:] if l.strip() != '']:
            fields = l.split()
            if fields[0] != 'vlan':
                continue

            while fields:
                if fields[0] == 'id':
                    self.vlan_id = fields[1]
                    fields = fields[2:]
                if fields[0] in ( 'protocol', ):
                    self.vlan_options[fields[0]] = fields[1]
                    fields = fields[2:]
                elif fields[0].startswith('<'):
                    self.vlan_options['flags'] = fields[0].strip('<>').split(',')
                    fields = fields[1:]
                else:
                    fields = fields[1:]

    def parse_options(self, fields):
        fields = fields.split()

        while fields:
            if fields[0] == 'state':
                if fields[1] == 'UNKNOWN':
                    self.media_state = None
                else:
                    self.media_state = fields[1]
                self.options['state'] = fields[1]
                fields = fields[2:]

            elif fields[0] == 'qlen':
                self.options['qlen'] = int(fields[1])
                fields = fields[2:]

            else:
                self.options[fields[0]] = True
                fields = fields[1:]

    def parse(self, line):
        fields = line.strip().split()

        if not fields:
            return

        if fields[0] == 'inet':
            address = LinuxNetworkAddress('inet', fields[1], fields[2:])
            self.ipv4_addresses.append(address)
            self.__latest_parsed_address = address

        elif fields[0] == 'inet6':
            address = LinuxNetworkAddress('inet6', fields[1], fields[2:])
            self.ipv6_addresses.append(address)
            self.__latest_parsed_address = address

        elif fields[0] == 'link/ether':
            self.media = EthernetMACAddress(fields[1])

        elif fields[0] == 'link/loopback':
            self.media = EthernetMACAddress(fields[1])

        elif fields[0] == 'valid_lft':
            address = self.__latest_parsed_address
            address.flags['valid_lft'] = fields[1]
            address.flags['preferred_lft'] = fields[3]


class LinuxNetworkInterfaces(NetworkInterfaceList):
    def update(self):
        self.__delslice__(0, len(self))

        try:
            output = check_output(['/sbin/ip', 'addr', 'show'])
        except CalledProcessError, emsg:
            raise NetworkError('Error getting interfaces: %s' % emsg)

        interface = None
        for l in [l for l in output.split('\n') if l.strip() != '']:
            m = RE_INTERFACE.match(l)
            if m:
                interface = LinuxNetworkInterface(m.groupdict()['name'])
                interface.mtu = m.groupdict()['mtu']
                interface.flags = m.groupdict()['flags'].split(',')
                interface.parse_options(m.groupdict()['options'])
                self.append(interface)

            else:
                interface.parse(l)


class IPv4RouteEntry(Route):
    def __init__(self, table, line):
        fields = line.split()

        address = parse_ipv4_route_target(fields[0], fields[2])
        target = parse_ipv4_route_target(fields[1])
        flags = fields[4]
        interface = fields[7]

        Route.__init__(self, table, address, target, flags=flags, interface=interface)

    def __str__(self):
        return '%s %s' % (self.address, self.target)


class IPv6RouteEntry(Route):
    def __init__(self, table, line):
        fields = line.split()

        address = parse_ipv6_route_target(fields[0])
        target = parse_ipv6_route_target(fields[1])
        flags = fields[2]
        refs = fields[4]
        use = fields[5]
        interface = fields[6]

        Route.__init__(self, table, address, target, flags=flags, interface=interface, refs=refs, use=use)

    def __str__(self):
        return '%s %s' % (self.address, self.target)


class LinuxRoutes(RoutingTable):
    """Linux style netstat parsing

    Parse linux style netstat -rn outputs

    """
    def update(self):
        self.ipv4 = []
        self.ipv6 = []

        try:
            output = check_output(['/bin/netstat', '-rn', '-4'])
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
            output = check_output(['/bin/netstat', '-rn', '-6'])
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


class LinuxARP(ARPTable):
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
