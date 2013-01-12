#!/usr/bin/env python
"""
Common wrapper for snmp command line query scripts
"""

import sys,os,logging

from systematic.shell import Script,ScriptError
from seine.snmp import SNMPError,SNMP_VERSIONS
from seine.snmp.client import SNMPClient,SNMPv1Auth,SNMPv2cAuth,SNMPv3Auth
from seine.snmp.devices.process import SNMPProcessStatus

class SNMPScript(Script):
    def __init__(self,oid_map={},index_cache_path=None):
        Script.__init__(self)

        self.oid_map = oid_map
        self.add_argument('-H','--host',help='SNMP host to connect')
        self.add_argument('-p','--port',type=int,default=161,help='SNMP server port')
        self.add_argument('-1',dest='snmpv1',action='store_true',help='Use SNMP v1')
        self.add_argument('-2',dest='snmpv2c',action='store_true',help='Use SNMP v2c')
        self.add_argument('-3',dest='snmpv3',action='store_true',help='Use SNMP v3')
        self.add_argument('-C','--community',help='SNMP v1/v2c community')
        self.add_argument('-U','--username',help='SNMP v3 username')
        self.add_argument('-a','--authProtocol',help='SNMP v3 auth protocol')
        self.add_argument('-A','--authPass',help='SNMP v3 auth password')
        self.add_argument('-x','--privProtocol',help='SNMP v3 priv protocol')
        self.add_argument('-X','--privPass',help='SNMP v3 priv password')
        self.add_argument('-t','--timeout',type=int,default=1,help='SNMP query timeout')
        self.add_argument('-r','--retries',type=int,default=5,help='SNMP query retries')
        self.add_argument('-f','--cache-path',default=index_cache_path,help='Result index cache path')

    @property
    def client_kwargs(self):
        return {
            'address': self.address, 'port': self.port, 'auth': self.auth,
            'timeout': self.timeout, 'retries': self.retries,
            'index_cache_path': self.index_cache_path,
        }

    def parse_args(self):
        args = Script.parse_args(self)
        self.address = args.host
        self.port = args.port
        self.timeout = args.timeout
        self.retries = args.retries
        self.index_cache_path = args.cache_path

        if args.snmpv3 and args.username and args.authPass:
            self.auth = SNMPv3Auth(args.username,args.authPass,args.privPass,args.authProtocol,args.privProtocol)
        elif args.snmpv2c and args.community:
            self.auth = SNMPv2cAuth(args.community)
        elif args.snmpv1 and args.community:
            self.auth = SNMPv1Auth(args.community)
        else:
            raise ScriptError('No SNMP authentication method provided')

        return args


