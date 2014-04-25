"""
Various DNS query related utility classes
"""

all = [ 'authservers', 'delegation', 'tld', 'resolver', 'rootservers' ]

class DNSError(Exception):
    pass

