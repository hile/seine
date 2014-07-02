"""
Parse network interfaces and routing tables
"""

import os
import sys
import fnmatch

from systematic.log import Logger, LoggerError

from seine.address import IPv4Address, IPv6Address, \
                          EthernetMACAddress, FirewireLocalLinkAddress


class Interfaces(object):
    """
    Thin wrapper to load OS specific implementation for network interfaces
    """
    __loader = None

    def __init__(self):
        if Interfaces.__loader is None:
            if sys.platform[:5] == 'linux':
                from seine.platform.linux.network import LinuxNetworkInterfaces
                Interfaces.__loader = LinuxNetworkInterfaces()

            elif sys.platform == 'darwin' or fnmatch.fnmatch(sys.platform, 'freebsd*'):
                from seine.platform.bsd.network import BSDNetworkInterfaces
                Interfaces.__loader = BSDNetworkInterfaces()

            else:
                raise ValueError('Interfaces loader for OS not available: %s' % sys.platform)

        self.__dict__['_Interfaces__loader'] = Interfaces.__loader
        self.__loader.update()
        self.__loader.sort()

    def __repr__(self):
        return '%s' % [x.name for x in self.__loader]

    def __getattr__(self, attr):
        return getattr(self.__loader, attr)

    def __getitem__(self, item):
        return self.__loader.__getitem__(item)

    def __iter__(self):
        return self.__loader.__iter__()

    def next(self):
        return self.__loader.next()


class ARP(object):
    __loader = None

    def __init__(self):
        if ARP.__loader is None:
            if sys.platform[:5] == 'linux':
                from seine.platform.linux.network import LinuxARP
                ARP.__loader = LinuxARP()

            elif sys.platform == 'darwin' or fnmatch.fnmatch(sys.platform, 'freebsd*'):
                from seine.platform.bsd.network import BSDARP
                ARP.__loader = BSDARP()

            else:
                raise ValueError('ARP loader for OS not available: %s' % sys.platform)

        self.__dict__['_ARP__loader'] = ARP.__loader
        self.__loader.update()
        self.__loader.sort()

    def __getattr__(self, attr):
        return getattr(self.__loader, attr)

    def __getitem__(self, item):
        return self.__loader.__getitem__(item)

    def __iter__(self):
        return self.__loader.__iter__()

    def next(self):
        return self.__loader.next()

    def match(self, value):
        matches = []
        for entry in self:
            if entry.ethernet is not None and fnmatch.fnmatch('%s' % entry.ethernet, value):
                matches.append(entry)

            if fnmatch.fnmatch('%s' % entry.address, value):
                matches.append(entry)

        return matches


class Routes(object):
    """
    Thin wrapper to load OS specific implementation for network interfaces
    """
    __loader = None

    def __init__(self):
        if Routes.__loader is None:
            if sys.platform[:5] == 'linux':
                from seine.platform.linux.network import LinuxRoutes
                Routes.__loader = LinuxRoutes()

            elif sys.platform == 'darwin' or fnmatch.fnmatch(sys.platform, 'freebsd*'):
                from seine.platform.bsd.network import BSDRoutes
                Routes.__loader = BSDRoutes()

            else:
                raise ValueError('Routes loader for OS not available: %s' % sys.platform)

        self.__dict__['_Routes__loader'] = Routes.__loader
        self.__loader.update()

    def __getattr__(self, attr):
        return getattr(self.__loader, attr)
