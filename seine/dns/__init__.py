"""
Various networking related utility classes.
"""

all = [ 'authservers', 'delegation', 'tld', 'resolver', 'rootservers' ]

class DNSError(Exception):
    def  __str__(self):
        return self.args[0]

