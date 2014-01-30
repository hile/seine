#!/usr/bin/env python
"""
HP printer statistics and control module.

Setting of variables not implemented, because my printer does not support
them MIB oids for the ones I was interested about setting.

See example in __main__ how this is used.
"""

import re
import logging

from pysnmp.proto import rfc1902

from seine.snmp import SNMPError, SNMP_VERSIONS
from seine.snmp.client import SNMPClient, SNMPv1Auth, SNMPv2cAuth, SNMPv3Auth

PRINTER_MIB_OID = '.1.3.6.1.2.1.43'
HP_LASERJET_MIB_OID = '.1.3.6.1.4.1.11.2.3.9'

ONLINE_STATUS_VALUES = { 1: 'online', 2: 'offline', 3: 'offline end of job' }

DEVICE_INFO_MAP = {
    'COMMENT':  'comment',
    'DES':      'design',
    'MDL':      'model',
    'MFG':      'manufacturer',
    'MEM':      'memory',
    'CMD':      'languages',
    'CLS':      'class',
    'SN':       'serialnumber',
}

TESTPAGE_MAP = {
    'configuration':    3,
    'errorlog':         7,
    'directorylisting': 8,
    'menumap':          9,
    'usagereport':      10,
    'pcl-fontlist':     350,
    'ps-fontlist':      450,
}
DEFAULT_TESTPAGE = 'configuration'

RESET_TYPE_MAP = {
    'powercycle':       4,
    'reset2nvram':      5,
    'factorydefaults':  6,
}
DEFAULT_RESET_TYPE = 'powercycle'

HP_PRINTER_OID_MAP = {
    'total_pages': {
        'oid': HP_LASERJET_MIB_OID+'.4.2.1.4.1.2.5.0',
        'decode': lambda x: int(x),
    },
    'color_pages': {
        'oid': HP_LASERJET_MIB_OID+'.4.2.1.4.1.2.7.0',
        'decode': lambda x: int(x),
    },
    'duplex_pages': {
        'oid': HP_LASERJET_MIB_OID+'.4.2.1.4.1.2.22.0',
        'decode': lambda x: int(x),
    },
    'config_changes': {
        'oid': PRINTER_MIB_OID + '.5.1.1.1.1',
        'decode': lambda x: int(x),
    },
    'localization': {
        'oid': PRINTER_MIB_OID + '.5.1.1.2.1',
        'decode': lambda x: str(x),
    },
    'reset_status': {
        'oid': PRINTER_MIB_OID + '.5.1.1.3.1',
        'decode': lambda x: int(x),
    },
    'operator_name': {
        'oid': PRINTER_MIB_OID + '.5.1.1.4.1',
        'decode': lambda x: str(x),
    },
    'consolelines': {
        'oid': PRINTER_MIB_OID + '.5.1.1.11.1',
        'decode': lambda x: int(x),
    },
    'consolechars': {
        'oid': PRINTER_MIB_OID + '.5.1.1.12.1',
        'decode': lambda x: int(x),
    },
    'name': {
        'oid': PRINTER_MIB_OID + '.5.1.1.16.1',
        'decode': lambda x: str(x),
    },
    'serialnumber': {
        'oid': PRINTER_MIB_OID + '.5.1.1.16.1',
        'decode': lambda x: str(x),
    },
    'energy_star': {
        'oid': HP_LASERJET_MIB_OID+'.4.2.1.1.1.1.0',
        'decode': lambda x: str(x),
    },
    'sleep_mode': {
        'oid': HP_LASERJET_MIB_OID+'.4.2.1.1.1.2.0',
        'decode': lambda x: int(x),
    },
    'default_copies': {
        'oid': HP_LASERJET_MIB_OID+'.4.2.1.3.3.1.4.0',
        'decode': lambda x: int(x),
    },
    'default_quality': {
        'oid': HP_LASERJET_MIB_OID+'.4.2.1.4.1.6.7.0',
        'decode': lambda x: int(x),
    },
    'res_horizontal': {
        'oid': HP_LASERJET_MIB_OID+'.4.2.1.3.3.1.8.0',
        'decode': lambda x: int(x),
    },
    'res_vertical': {
        'oid': HP_LASERJET_MIB_OID+'.4.2.1.3.3.1.9.0',
        'decode': lambda x: int(x),
    },
    'lines_per_page': {
        'oid': HP_LASERJET_MIB_OID+'.4.2.1.3.3.1.11.0',
        'decode': lambda x: int(x),
    },
    'online_status': {
        'oid': HP_LASERJET_MIB_OID+'.4.2.1.1.2.5.0',
        'decode': lambda x: ONLINE_STATUS_VALUES[int(x)],
    },
    'device_info': {
        'oid': HP_LASERJET_MIB_OID+'.1.1.7.0',
        'decode': lambda x: dict(
            (k in DEVICE_INFO_MAP.keys() and DEVICE_INFO_MAP[k] or k, v.strip()) \
            for k, v in
            [s.split(':') for s in str(x).strip(';').split(';')]
         )
    },
    'supply_names': {
        'oid': PRINTER_MIB_OID + '.11.1.1.6',
        'type': 'tree',
        'decode': lambda k, v: (k,str(v)),
    },
    'supply_max_levels': {
        'oid': PRINTER_MIB_OID + '.11.1.1.8',
        'type': 'tree',
        'decode': lambda k, v: (k,int(v)),
    },
    'supply_levels': {
        'oid': PRINTER_MIB_OID + '.11.1.1.9',
        'type': 'tree',
        'decode': lambda k, v: (k,int(v)),
    },
}

class LaserjetSNMPControl(dict):
    def __init__(self, snmp_client):
        self.client = snmp_client

    def __getattr__(self, attr):
        if attr in HP_PRINTER_OID_MAP.keys():
            d = HP_PRINTER_OID_MAP[attr]
            oid = d['oid']
            dtype = d.get('type', 'get')
            if dtype == 'get':
                value = self.client.get(oid)[1]
                if value == '':
                    return None
                return d['decode'](value)
            elif dtype == 'tree':
                return [d['decode'](k, v) for k, v in self.client.walk(oid).items()]
        raise AttributeError('No such LaserjetSNMPControl attribute: %s' % attr)

    def supply_level_details(self):
        levels = dict(getattr(self, 'supply_names'))
        details = dict((k.split('.')[-1], {'name':levels[k]}) for k, v in levels.items() )
        for oid, maxlevel in getattr(self, 'supply_max_levels'):
            index = oid.split('.')[-1]
            details[index]['max'] = maxlevel
        for oid, level in getattr(self, 'supply_levels'):
            index = oid.split('.')[-1]
            details[index]['level'] = level
        return dict(
            (details[i]['name'], {
                'index': i,
                'max': details[i]['max'],
                'level': details[i]['level'],
                'percent': int(
                    float(details[i]['level'])/float(details[i]['max'])*100
                ),
            }) for i in details.keys()
        )

    def reset(self, resettype=DEFAULT_RESET_TYPE):
        try:
            resettype = rfc1902.Integer(RESET_TYPE_MAP[resettype])
        except KeyError:
            raise ValueError('Invalid reset type: %s' % resettype)
        oid = PRINTER_MIB_OID + '.5.1.1.3.1'
        return self.client.set(oid, resettype)

    def testpage(self, pagetype=DEFAULT_TESTPAGE):
        try:
            pagetype = rfc1902.Integer(TESTPAGE_MAP[pagetype])
        except KeyError:
            raise ValueError('Invalid testpage type: %s' % pagetype)
        oid = HP_LASERJET_MIB_OID + '.4.2.1.1.5.2.0'
        return self.client.set(oid, pagetype)

if __name__ == '__main__':
    import sys

    ljclient = LaserjetSNMPControl(
        SNMPClient(sys.argv[1], SNMPv1Auth(community=sys.argv[2]))
    )
    #ljclient.client.logger.set_level('DEBUG')
    #for k in sorted(HP_PRINTER_OID_MAP.keys()): print k, getattr(ljclient,k)

    for color,details in ljclient.supply_level_details().items():
        print '%12s %s %%' % (color,details['percent'])

