#!/usr/bin/env python
"""
Common wrapper for snmp command line query scripts
"""

import sys,os,logging
from optparse import OptionParser

from seine.snmp import SNMPError,SNMP_VERSIONS 
from seine.snmp.client import SNMPClient,SNMPv1Auth,SNMPv2cAuth,SNMPv3Auth
from seine.snmp.devices.process import SNMPProcessStatus 

class SNMPScriptError(Exception):
    def __str__(self):
        return self.args[0]

class SNMPScript(object):
    def __init__(self,port=161,timeout=1,retries=5,oid_map={},index_cache_path=None):
        self.address = None
        self.port = int(port)
        self.timeout = int(timeout)
        self.retries = int(retries)
        self.oid_map = oid_map
        self.index_cache_path = index_cache_path

        self.parser = OptionParser()
        self.parser.add_option('-H','--host',help='SNMP host to connect')
        self.parser.add_option(
            '-1',dest='snmpv1',action='store_true',help='Use SNMP v1'
        )
        self.parser.add_option(
            '-2',dest='snmpv2c',action='store_true',help='Use SNMP v2c'
        )
        self.parser.add_option(
            '-3',dest='snmpv3',action='store_true',help='Use SNMP v3'
        )
        self.parser.add_option('-N','--username',help='SNMP v3 username')
        self.parser.add_option('-P','--password',help='SNMP v3 password')
        self.parser.add_option('-C','--community',help='SNMP v1/v2c community')
        self.parser.add_option('-p','--port',help='SNMP server port')
        self.parser.add_option('-t','--timeout',help='SNMP query timeout')
        self.parser.add_option('-r','--retries',help='SNMP query retries')
        self.parser.add_option('-f','--cache-path',help='Result index cache path')
        self.parser.add_option(
            '-d','--debug',action='store_true',help='Show debug messages'
        )

    def __getattr__(self,attr):
        if attr == 'client_kwargs':
            return {
                'address': self.address,
                'auth': self.auth,
                'port': self.port,
                'timeout': self.timeout,
                'retries': self.retries,
                'index_cache_path': self.index_cache_path,
            }
        raise AttributeError('No such SNMPScript attribute: %s' % attr)

    def add_option(self,*args,**kwargs):
        self.parser.add_option(*args,**kwargs)

    def set_defaults(self,*args,**kwargs):
        self.parser.set_defaults(*args,**kwargs)

    def set_usage(self,*args,**kwargs):
        self.parser.set_usage(*args,**kwargs)

    def get_usage(self,*args,**kwargs):
        self.parser.get_usage(*args,**kwargs)

    def parse_args(self,*args,**kwargs):
        (opts,args) = self.parser.parse_args(*args,**kwargs)
        if opts.debug:
            logging.basicConfig(level=logging.DEBUG)
        if not opts.host:
            raise SNMPScriptError('No target host given as argument')
        self.address = opts.host

        if opts.snmpv3 and opts.username and opts.password:
            self.auth = SNMPv3Auth(opts.username,opts.password)
        elif opts.snmpv2c and opts.community:
            self.auth = SNMPv2cAuth(opts.community)
        elif opts.snmpv1 and opts.community:
            self.auth = SNMPv1Auth(opts.community)
        else:
            raise SNMPScriptError('No SNMP authentication method provide')

        for arg in ['port','timeout','retries']:
            value = getattr(opts,arg)
            if value is not None:
                setattr(self,arg,value)

        if opts.cache_path is not None:
            self.index_cache_path = opts.cache_path

        return (opts,args)

    def exit(self,code=0,message=None):
        if message is not None: 
            print message
        sys.exit(code)


