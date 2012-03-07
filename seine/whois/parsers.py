#!/usr/bin/env python
"""
Parser classes for various whois output formats
"""

import os

from seine.whois.servers import WhoisError

TLD_FORMAT_MAP = {
    'gtld':     [ 'com', 'edu', 'gov', 'mil', 'net', 'org', 'arpa' ],
    'ficora':   ['fi'],
    'saudinic': ['sa'],
    'nominet':  ['uk'],
}

class WhoisData(dict):
    def __init__(self,domain,data):
        self.domain = domain 

        tld = self.domain.split('.')[-1]
        self.parser = None
        for fmt,tlds in TLD_FORMAT_MAP.items():
            if tld not in tlds:
                continue
            path = 'seine.whois.formats.%s' % fmt
            try:
                m = __import__(path,globals(),fromlist=[fmt])
                self.parser = getattr(m,'parse')
            except ImportError,emsg:
                raise WhoisError(
                    'Error importing whois data parser for %s: %s' % 
                    (fmt,emsg)
                )
            except AttributeError,emsg:
                raise WhoisError(
                    'Error importing whois data parser for %s: %s' % 
                    (fmt,emsg)
                )
        if self.parser is None:
            raise WhoisError('No parser defined for TLD %s' % tld)
        self.update(self.parser(domain,data))

if __name__ == '__main__':
    import sys
    for domain in sys.argv[1:]:
        path = '/tmp/whois-%s.txt' % domain
        if not os.path.isfile(path):
            print 'No such file: %s' % path
            continue
        wd = WhoisData(domain,open(path,'r').readlines())
        for k in sorted(wd.keys()):
            v = wd[k]
            print k
            if type(v) == list:
                print '\t%s' % '\n\t'.join(v)
            else:
                print '\t%s' % v

