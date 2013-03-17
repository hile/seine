#!/usr/bin/env python
"""
Proxy autoconfiguration processing, for both passing autoconfig URL
and retriving from WPAD DNS configured hosts.
"""

import StringIO

try:
    import pacparser
except ImportError:
    raise ImportError('Module pacparser is not installed.')

def ProxyAutoConfig(object):
    def __init__(self,pac_url=None):
        if pac_url is None:
            wpad_domain = '.'.join(socket.getfqdn('wpad').split('.')[1:])
            if wpad_domain == '':
                raise ProxyConfigError('No URL given and WPAD not available')
            else:
                pac_url = 'http://wpad.%s/wpad.dat' % wpad_domain
        self.pac_url = pac_url
        self.pac = None
        self.parser = pacparser.init()

    def read_pac(self):
        try:
            pac_opener = urllib2.build_opener()
            data = pac_opener.open(self.pac_url).read()
        except urllib2.HTTPError,e:
            logging.debug('Error etrieving WPAD configuration: %s' % e)
            return
        except urllib2.URLError,e:
            logging.debug('Error retrieving WPAD configuration: %s' % e)
            return
        self.pac = StringIO.StringIO()
        self.pac.write(data)
        self.pac.seek(0)

    def __str__(self):
        if self.pac is None:
            self.read_pac()
        self.pac.seek(0)
        return self.pac.read()

    def proxy_handler(self,url):
        self.parser.parse_pack(str(self))
        proxies = self.parser.find_proxy(url)
        self.parser.cleanup()

        if proxies.startswith('PROXY '):
            proxy_url = proxies.split()[1]
            return urllib2.ProxyHandler({'http': proxy_url,'https': proxy_url})
        else:
            return urllib2.ProxyHandler()

