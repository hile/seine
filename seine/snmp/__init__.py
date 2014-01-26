"""
Wrappers related to net-snmp python tools, making it's usage much easier.
"""

__all__ = ['agent', 'client', 'script']

# Supported SNMP versions
SNMP_VERSIONS = ( '1', '2c', '3' )

class SNMPError(Exception):
    pass

def cmp_oid(v1, v2):
    """
    Compare function to compare two oids given as strings or lists of integers
    """
    try:
        if type(v1) == list:
            v1 = [int(i) for i in v1]
        else:
            v1 = [int(i) for i in v1.lstrip('.').split('.')]

        if type(v2) == list:
            v2 = [int(i) for i in v2]
        else:
            v2 = [int(i) for i in v2.lstrip('.').split('.')]

    except ValueError:
        raise SNMPError('Unsupported OID values to cmp_oid')

    for i in range( min(len(v1), len(v2)) ):
        r = cmp(v1[i], v2[i])
        if r != 0:
            return r

    if len(v1) < len(v2):
        return -1
    elif len(v2) > len(v1):
        return 1

    return 0

