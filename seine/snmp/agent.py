#!/usr/bin/env python
"""
SNMP agent base class for net-snmp pass/pass_persist agents.

See the SNMPAgentTest class below how to use the SNMPAgent class.
"""

import sys,os,signal,errno,select
import re,time,logging
from optparse import OptionParser

# Valid SNMP data types
SNMP_DATA_TYPES = [
    'integer',
    'gauge',
    'counter',
    'timeticks',
    'ipaddress',
    'objectid',
    'string',
]

class SNMPAgent(list):
    def __init__(self,oid):
        self.last_next_ts = None
        self.log = logging.getLogger('agent')
        self.oid = self.__validate_oid(oid)

    def __getitem__(self,oid):
        oid = self.__validate_oid(oid)
        if len(oid) <= len(self.oid):
            raise KeyError('Too short OID')
        if oid[:len(self.oid)] != self.oid:
            raise KeyError('Tree index does not match')

        path = oid[len(self.oid):]
        if path[0] >= len(self):
            raise KeyError('Index out of tree')

        entry = self
        try:
            for i in path: 
                entry = entry[i]
        except IndexError:
            raise KeyError('No such oid entry')
        return entry

    def __validate_oid(self,oid):
        if oid is None:
            raise TypeError('OID is none')
        try:
            if type(oid) != list:
                oid = oid.strip('.').split('.') 
            return [int(x) for x in oid]
        except ValueError:
            raise ValueError('Invalid OID value %s (%s)' % (oid,e))

    def __response(self,oid,entry):
        return '\n'.join(
            '.'+'.'.join(str(x) for x in oid),
            entry['type'],
            entry['value']
        )

    def __SIGHUP__(self,signum,frame):
        """
        Signal handler to reload configuration. Note this requires also the 
        IOError processing in main input loop below 
        """
        self.log.debug('Reloading from signal')
        self.reload()

    def append(self,data):
        def verify_tree(self,tree):
            if type(tree) != list:
                raise ValueError('You can only append lists')
            if len(tree)>0 and tree[0] is not None:
                tree.insert(0,None)
            for entry in tree[1:]:
                if type(entry) == dict:
                    for k in entry.keys():
                        if k == 'type' and entry[k] not in SNMP_DATA_TYPES:
                            raise ValueError('Invalid type %s' % entry[k])
                        elif k == 'value':
                            # TODO check values
                            continue
                        else:
                            raise ValueError('Unknown key %s in tree' % k)
                if type(entry) == list:
                    verify_tree(entry)
                else:
                    raise ValueError('Unknown data in tree')

        if self == []: 
            list.append(self,None)
        verify_tree(data)
        list.append(self,data)

    def GET(self,oid):
        self.reload()
        oid = self.__validate_oid(oid)
        try:
            entry = self[oid]
        except KeyError,e:
            return None
        if type(entry) == list:
            return None
        return self.__response(oid,entry)
        
    def NEXT(self,oid):
        self.reload()
        self.last_next_ts = long(time.time())

        # Return first entry, requested tree root  
        oid = self.__validate_oid(oid)
        if oid == self.oid:
            while True:
                oid.append(1)
                try:
                    entry = self[oid]
                except KeyError,e:
                    return None
                if type(entry) == list:
                    continue
                return self.__response(oid,entry)
                
        # Check given OID is valid
        try: 
            current = self[oid]
            if type(current) == list:
                oid.append(1)
                entry = self[oid]
                while type(entry) == list:
                    oid.append(1)
                    entry = entry[1]
                return self.__response(oid,entry)
            path = oid[len(self.oid):]
            if path[0] >= len(self):
                return None
        except KeyError,e:
            self.log.debug(e)
            return None

        oid = list(self.oid)
        oid.extend(path)
        oid[-1] += 1
        try:
            entry = self[oid]
            oid = '.'+'.'.join(map(lambda x: str(x), oid))
            return self.__response(oid,entry)
        except KeyError:
            pass

        # Try returning next subtree's first entry
        i = 1
        while i<len(path):
            oid = list(self.oid)
            oid.extend(path[:-i])
            oid[-1] += 1
            try:
                entry = self[oid]
                while type(entry) == list:
                    oid.append(1)
                    entry = self[oid]
                return self.__response(oid,entry)
            except KeyError:
                pass
            i+=1
        return None    

    def reload(self):
        """
        This method must be implemented in a child class. It is used to 
        reload the SNMP tree data from files, if possible.

        The method is called for every GET and NEXT: you must implement some
        kind of check if the reload is actually needed or not (like, check
        source file mtime and only reload if file is modified). 
         
        For NEXT you should check if self.last_next_ts is too recent, see example
        in SNMPAgentTest reload class
        """
        raise NotImplementedError('You must implement reload in child class')

    def main(self,opts=None):
        """
        Main loop to execute for agent. You can either run this in:
        
        - 'pass' mode: get/next for single OID by passing in OptionParser 
          'options' value 'get' or 'next' (snmpd.conf 'pass' agent)
        - 'pass_persist' mode: without any options, in which case the loop 
           acts as permanent snmpd pass_persist agent.
        """
        signal.signal(signal.SIGHUP, self.__SIGHUP__)

        if hasattr(opts,'tree'):
            opt = getattr(opts,'tree')
            if opt is not None:
                print '.%s' % '.'.join(map(lambda x: str(x), self.oid))
                return

        if hasattr(opts,'get'):
            opt = getattr(opts,'get')
            if opt is not None:
                v = self.GET(opt)
                if v is not None: 
                    print v
                return

        if hasattr(opts,'next'):
            opt = getattr(opts,'next')
            if opt is not None:
                v = self.NEXT(opt)
                if v is not None: 
                    print v
                return

        # Just a marker to indicate where we detect EOF
        EOF = ''
        while True:
            try:
                # Read a line of input from snmpd
                cmd = sys.stdin.readline()
                if cmd == EOF: break
                cmd = cmd.rstrip().lower()

                if cmd == 'ping':
                    sys.stdout.write('PONG\n')
                if cmd == 'reload':
                    self.reload()
                if cmd == 'quit':
                    return

                if cmd in ['set','get','getnext']:
                    oid = sys.stdin.readline()
                    if oid == EOF: break
                    oid = oid.rstrip() 

                if cmd == 'set':
                    sys.stdout.write('not-writable\n')
                elif cmd == 'get':
                    value = self.GET(oid)
                    sys.stdout.write('%s' % value and value or 'NONE')
                    sys.stdout.write('\n')
                elif cmd == 'getnext':
                    value = self.NEXT(oid)
                    sys.stdout.write('%s' % value and value or 'NONE')
                    sys.stdout.write('\n')

                sys.stdout.flush()

            except IOError,e:
                # we get EINTR with SIGHUP and we can ignore it
                if e[0] == errno.EINTR: 
                    continue
                self.log.debug('IOError: %s' % e[1])
                return

            except KeyboardInterrupt:
                # Interactive mode, user interrupted
                self.log.debug('Quitting...')
                return

class SNMPAgentTest(SNMPAgent):
    def __init__(self,oid='1.2.3.4'):
        super(SNMPAgentTest,self).__init__(oid)

        self.intvalue = 0
        self.reload()

    def reload(self):
        """
        Child class example method to reload SNMP data from sources.
        """
        if self.last_next_ts and self.last_next_ts >= long(time.time())-1:
            return
        
        self.__delslice__(0,len(self))

        # Here you should check if the source has been modified and
        # quit if it is not: for example, os.stat().st_mtime for the
        # source file.
        
        # Insert a list of example OIDs as 1.2.3.4.1 subtree. You need
        # to call append for each oid root subtree once.
        list.append(self, [
            # this creates oids 1.2.3.4.1.1.1 and 1.2.3.4.1.1.2
            [
            { 'type': 'string', 'value': 'test tree name', },
            { 'type': 'integer', 'value': 'test tree reload count', },
            ],

            # this creates oids 1.2.3.4.1.2.1 and 1.2.3.4.1.2.2
            [
            { 'type': 'string', 'value': 'test', },
            { 'type': 'integer', 'value': self.intvalue, },
            ],
        ])

        # Increate reload counter: just for this example ... 
        self.intvalue+=1

if __name__ == '__main__':

    parser = OptionParser()
    parser.add_option('-g','--get',dest='get',help='SNMP GET request')
    parser.add_option('-n','--next',dest='next',help='SNMP GET request')
    parser.add_option('-t','--tree',dest='tree',action='store_true',help='Show OID tree')
    parser.add_option('-d','--debug',dest='debug',action='store_true',help='Show debug messages')
    (opts,args) = parser.parse_args()
    if opts.debug: 
        logging.basicConfig(level=logging.DEBUG) 

    t = SNMPAgentTest()
    t.main(opts)

