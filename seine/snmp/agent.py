"""
SNMP agent base class for net-snmp pass/pass_persist agents.

See the SNMPAgentTest class below how to use the SNMPAgent class.
"""

import sys
import os
import re
import time
import signal
import errno
import select

from systematic.shell import Script, ScriptThread, ScriptError
from systematic.log import Logger, LoggerError
from seine.snmp import SNMPError

# Valid SNMP data types

SNMP_DATA_TYPE_MAP = {
    'integer':      lambda x: int(x),
    'gauge':        lambda x: int(x),
    'counter':      lambda x: int(x),
    'timeticks':    lambda x: int(x),
    'string':       lambda x: str(x),
    'ipaddress':    lambda x: str(IPv4Address(x)),
    'objectid':     lambda x: str(x),
}

class SNMPItem(object):
    def __init__(self, index, key, value):
        self.log = Logger('snmp').default_stream
        self.parent = None
        self.index = int(index)
        self.key = key
        if not key in SNMP_DATA_TYPE_MAP.keys():
            raise SNMPError('Invalid item type: %s' % key)
        try:
            value = SNMP_DATA_TYPE_MAP[key](value)
        except:
            raise SNMPError('Invalid item type %s value "%s"' % (key, value))
        self.value = value

    def __repr__(self):
        return '%s\n%s' % (self.oid, self.value)

    @property
    def oid(self):
        if self.parent is None:
            return '.%s' % self.index
        return '.%s.%s' % ('.'.join('%s'%x for x in self.parent.oid), self.index)

    def set_parent(self, parent):
        self.parent = parent

class SNMPTree(dict):
    def __init__(self, oid):
        self.log = Logger('snmp').default_stream
        self.sorted_keys = []
        self.oid = self.__format_oid__(oid)
        self.oid_string = '.%s'% '.'.join(str(x) for x in self.oid)

    def __repr__(self):
        return 'TREE %s' % '.'.join('%s'%x for x in self.oid)

    def __format_oid__(self, oid):
        if not isinstance(oid, list):
            try:
                oid = oid.strip('.').split('.')
            except ValueError:
                raise ValueError('Invalid OID: %s' % oid)
        try:
            oid = [int(x) for x in oid]
            for x in oid:
                if x<=0:
                    raise ValueError
            return oid
        except ValueError:
            raise ValueError('Invalid OID: %s' % oid)

    def __item_index__(self, oid):
        try:
            oid = self.__format_oid__(oid)
            if len(oid)<len(self.oid) or oid[:len(self.oid)]!=self.oid:
                return None
            return oid[len(self.oid):]
        except ValueError:
            return None

    def __invalid__(self, message):
        self.log.debug(message)
        return None

    def add(self, item, value=None):
        if isinstance(item, SNMPItem):
            if self.has_key(item.index):
                raise SNMPError('Duplicate index: %s' % item.index)
            item.set_parent(self)
            self[item.oid] = item

        elif isinstance(item, SNMPTree):
            for oid, entry in item.items():
                self[oid] = entry

    def loaded(self):
        self.sorted_keys = sorted(self.keys())

    def GET(self, oid):
        if oid==self.oid_string:
            return self.__invalid__('GET for tree root')
        try:
            oid = '.%s' % '.'.join(str(x) for x in self.__format_oid__(oid))
        except ValueError:
            return self.__invalid__('GET invalid OID')
        try:
            return '%s'%self[oid].value
        except KeyError:
            return self.__invalid__('GET invalid OID: key not found')

    def NEXT(self, oid):
        if oid==self.oid_string:
            if not len(self.sorted_keys):
                return self.__invalid__('GET for empty tree root')
            return self[self.sorted_keys[0]].value

        try:
            oid = '.%s' % '.'.join(str(x) for x in self.__format_oid__(oid))
        except ValueError:
            return self.__invalid__('NEXT invalid OID')
        try:
            oid_index = self.sorted_keys.index(oid)
        except ValueError:
            return self.__invalid__('NEXT invalid OID')

        if oid_index+1>=len(self.sorted_keys):
            return self.__invalid__('NEXT for last OID')
        try:
            return '%s'%self[self.sorted_keys[oid_index+1]].value
        except KeyError:
            return self.__invalid__('NEXT BUG data screwed up while indexing')

    def SET(self, oid_string, item, value):
        raise NotImplementedError

class SNMPAgent(Script):
    def __init__(self, oid):
        Script.__init__(self)
        self.log = Logger('snmp').default_stream
        self.last_reload_ts = None
        self.oid = oid

        self.add_argument('-g', '--get', help='SNMP GET request')
        self.add_argument('-n', '--next', help='SNMP GET request')
        self.add_argument('-t', '--tree', action='store_true', help='Show OID tree')

        self.tree = SNMPTree(self.oid)

    def __SIGHUP__(self, signum, frame):
        """
        Signal handler to reload configuration. Note this requires also the
        IOError processing in main input loop below
        """
        self.log.debug('Reloading from signal')
        self.reload()

    def GET(self, oid):
        try:
            return self.tree.GET(oid)
        except SNMPError:
            return None

    def NEXT(self, oid):
        try:
            return self.tree.NEXT(oid)
        except SNMPError, emsg:
            print emsg
            return None

    def SET(self, key, value):
        return self.tree.SET(oid, value)

    def reload(self):
        """
        This method must be implemented in a child class. It is used to
        reload the SNMP tree data from files, if possible.

        The method is called for every GET and NEXT: you must implement some
        kind of check if the reload is actually needed or not (like, check
        source file mtime and only reload if file is modified).

        For NEXT you should check if self.last_reload_ts is too recent, see example
        in SNMPAgentTest reload class
        """
        raise NotImplementedError('You must implement reload in child class')

    def main(self, opts=None):
        """
        Main loop to execute for agent. You can either run this in:

        - 'pass' mode: get/next for single OID by passing in OptionParser
          'options' value 'get' or 'next' (snmpd.conf 'pass' agent)
        - 'pass_persist' mode: without any options, in which case the loop
           acts as permanent snmpd pass_persist agent.
        """
        signal.signal(signal.SIGHUP, self.__SIGHUP__)

        args = self.parse_args()
        if args.tree:
            print '.%s' % '.'.join(map(lambda x: str(x), self.oid))

        elif args.get:
            v = self.GET(args.get)
            if v is not None:
                print v

        elif args.next:
            v = self.NEXT(args.next)
            if v is not None:
                print v

        if args.tree or args.get or args.next:
            self.exit(0)

        # Just a marker to indicate where we detect EOF
        EOF = ''
        self.log.debug('Starting agent main loop')
        while True:
            try:
                # Read a line of input from snmpd
                cmd = sys.stdin.readline()
                if cmd == EOF:
                    break
                cmd = cmd.rstrip().lower()

                if cmd == 'ping':
                    sys.stdout.write('PONG\n')
                if cmd == 'reload':
                    self.reload()
                if cmd == 'quit':
                    return

                if cmd in ('set', 'get', 'getnext'):
                    oid = sys.stdin.readline()
                    if oid == EOF:
                        break
                    oid = oid.rstrip()

                if cmd == 'set':
                    sys.stdout.write('not-writable\n')

                elif cmd == 'get':
                    self.reload()
                    value = self.GET(oid)
                    sys.stdout.write('%s' % value and value or 'NONE')
                    sys.stdout.write('\n')

                elif cmd == 'getnext':
                    self.reload()
                    value = self.NEXT(oid)
                    sys.stdout.write('%s' % value and value or 'NONE')
                    sys.stdout.write('\n')

                sys.stdout.flush()

            except IOError, emsg:
                # we get EINTR with SIGHUP and we can ignore it
                if emsg[0]==errno.EINTR:
                    continue
                self.log.debug('IOError: %s' % emsg[1])
                return

            except KeyboardInterrupt:
                # Interactive mode, user interrupted
                self.log.debug('Quitting...')
                return
