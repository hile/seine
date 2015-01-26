"""
Module to update and process the list of valid TLD domains from IANA.
"""

import os
import re

from seine.url import HTTPRequest, HTTPRequestError

IANA_TLD_URL = 'http://data.iana.org/TLD/tlds-alpha-by-domain.txt'

CACHE_DIRECTORIES = [
    '/var/cache/tld',
    '/tmp/tld-%s' % os.geteuid(),
]

CACHE_FILES = map(lambda d:
    os.path.join(d, os.path.basename(IANA_TLD_URL)),
    CACHE_DIRECTORIES
)

RE_TLDNAME = re.compile(r'^[a-z0-9-]+$')


class DNSCacheError(Exception):
    pass


class TLD(object):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        if self.unicode != self.name:
            return '%s (%s)' % (self.name, self.unicode)
        else:
            return self.name

    def __cmp__(self, other):
        if isinstance(other, TLD):
            return cmp(self.unicode, other.unicode)

        if other == self.name or other == self.unicode:
            return 0

        return cmp(self.unicode, other)

    @property
    def unicode(self):
        return unicode(self.name).decode('idna')

    @property
    def is_idn(self):
        return self.name != self.unicode


class TLDCache(list):
    """
    Abstratction for TLD domain names: you can
    - update the list from IANA with updateCache() method
    - check if a given value is valid TLD with has_key
    - iterate all valid TLDs by iteraing the class itself
    """
    def __init__(self, path=None):
        """
        You can pass alternative file path to be used in all operations,
        or use the default file.
        """

        self.__next = 0
        self.path = path

        if self.path is None:
            for f in CACHE_FILES:
                if os.path.isfile(f) and os.access(f, os.W_OK):
                    self.path = f
                    break

                fdir = os.path.dirname(f)
                if not os.path.isdir(fdir):
                    try:
                        os.makedirs(os.path.dirname(f))
                    except IOError, (ecode, emsg):
                        continue
                    except OSError, (ecode, emsg):
                        continue

                if not os.path.isfile(f):
                    try:
                        open(f, 'w').write('\n')
                        os.unlink(f)
                        self.path = f
                        break
                    except IOError, (ecode, emsg):
                        continue
                    except OSError, (ecode, emsg):
                        continue

        self.sort()

    def __repr__(self):
        return 'TLDCache %d entries' % len(self)

    def __getitem__(self, item):
        if len(self) == 0:
            self.update()
        try:
            return list.__getitem__(self, self.index(item))
        except ValueError:
            raise KeyError('No such TLDCache item: %s' % item)

    @property
    def is_downloaded(self):
        return len(self) > 0

    def load(self):
        """Load saved file

        Load saved TLD mapping cache information file

        """

        self.__delslice__(0, len(self))

        if not os.path.isfile(self.path):
            return

        try:
            fd = open(self.path, 'r')
            for l in map(lambda x: x.strip(), fd.readlines()):
                if l.strip() == '' or l.startswith('#'):
                    continue
                if not re.match(RE_TLDNAME, l.lower()):
                    continue
                self.append(TLD(l.lower()))

        except IOError, (ecode, emsg):
            raise TLDCacheError('Error loading cache: %s' % emsg)

        except OSError, (ecode, emsg):
            raise TLDCacheError('Error loading cache: %s' % emsg)

    def update(self):
        """Update cache

        Compatibility callback for self.download()

        """
        return self.download()

    def download(self):
        """Update TLD cache file

        Download a new TLD cache file from IANA and load new version
        with self.load()

        """

        cache_dir = os.path.dirname(self.path)

        if not os.path.isdir(cache_dir):
            try:
                os.mkdir(cache_dir)
            except OSError, (ecode, emsg):
                raise DNSCacheError('Error creating %s: %s' % (cache_dir, emsg))

        try:
            req = HTTPRequest()
            (code, data, headers) = req.GET(IANA_TLD_URL)
            fd = open(self.path, 'w')
            fd.write(data)
            fd.close()

        except IOError, emsg:
            raise DNSCacheError('Error updating %s: %s' % (self.path, emsg))

        except OSError, (ecode, emsg):
            raise DNSCacheError('Error updating %s: %s' % (self.path, emsg))

        self.load()

