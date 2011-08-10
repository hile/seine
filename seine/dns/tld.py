"""
Module to update and process the list of valid TLD domains from IANA.
"""

import os,re,logging

from seine.url import HTTPRequest,HTTPRequestError

IANA_TLD_URL = 'http://data.iana.org/TLD/tlds-alpha-by-domain.txt'

CACHE_DIRECTORIES = [
    '/var/cache/dns',
    os.path.join(os.getenv('HOME'),'.tldcache')
]
CACHE_FILES = map(lambda d:
    os.path.join(d,os.path.basename(IANA_TLD_URL)),
    CACHE_DIRECTORIES
)

RE_TLDNAME = re.compile(r'^[a-z0-9-]+$')

class DNSCacheError(Exception):
    def __str__(self):
        return self.args[0]

class TLDCache(list):
    """
    Abstratction for TLD domain names: you can 
    - update the list from IANA with updateCache() method
    - check if a given value is valid TLD with has_key
    - iterate all valid TLDs by iteraing the class itself
    """
    __slots__ = ['__next','log','names','path' ]
    def __init__(self,path=None):
        """
        You can pass alternative file path to be used in all operations, 
        or use the default file.
        """ 
        self.log = logging.getLogger('modules')
        self.__next = 0
        self.path = path
        if self.path is None:
            for f in CACHE_FILES:
                if os.path.isfile(f) and os.access(f,os.W_OK):
                    self.path = f
                    break
                fdir = os.path.dirname(f)
                if not os.path.isdir(fdir):
                    try:
                        os.makedirs(os.path.dirname(f))
                        open(f,'w').write('\n')
                        os.unlink(f)
                        self.path = f
                        break
                    except IOError,(ecode,emsg): 
                        continue
                    except OSError,(ecode,emsg): 
                        continue
            self.log.debug('Using cache file %s' % self.path)

    def __repr__(self):
        return 'TLDCache %d entries' % len(self)

    def __getitem__(self,item):
        if len(self) == 0:
            raise DNSCacheError('TLD data file %s not yet downloaded.' % self.path)
        try:
            return list.__getitem__(self,self.index(item))
        except ValueError:
            raise KeyError('No such TLDCache item: %s' % item)

    def load(self):
        self.log.debug('Loading TLD cache file %s' % self.path)
        self.__delslice__(0,len(self))
        if not os.path.isfile(self.path):
            self.log.info('TLD cache not loaded, no such file: %s' % self.path)
            return
        try:
            fd = open(self.path,'r')
            for l in map(lambda x: x.strip(), fd.readlines()):
                if l.strip() == '' or l.startswith('#'): 
                    continue
                if not re.match(RE_TLDNAME,l.lower()):
                    self.log.debug('Skipping invalid entry: %s' % l)
                    continue
                self.append(l.lower())
        except IOError,(ecode,emsg):
            raise TLDCacheError('Error loading cache: %s' % emsg)
        except OSError,(ecode,emsg):
            raise TLDCacheError('Error loading cache: %s' % emsg)

    def update(self):
        cache_dir = os.path.dirname(self.path)
        self.log.debug('Updating TLD cache file in %s' % self.path)
        if not os.path.isdir(cache_dir):
            try:
                os.mkdir(cache_dir)
            except OSError,(ecode,emsg):
                raise DNSCacheError('Error creating %s: %s' % (cache_dir,emsg))
        try:
            req = HTTPRequest()        
            (code,data,headers) = req.GET(IANA_TLD_URL)
            fd = open(self.path,'w')
            fd.write(data)
            fd.close()
        except IOError,e:
            raise DNSCacheError('Error updating %s: %s' % (self.path,e))
        except OSError,(ecode,emsg):
            raise DNSCacheError('Error updating %s: %s' % (self.path,emsg))
        self.load()

