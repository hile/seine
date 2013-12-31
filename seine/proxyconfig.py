"""
Proxy autoconfiguration processing, for both passing autoconfig URL
and retriving from WPAD DNS configured hosts.
"""

import requests
import urllib2
import socket
import StringIO

try:
    import pacparser
except ImportError:
    raise ImportError('Module pacparser is not installed.')

DEFAULT_QUERY_TIMEOUT = 3.0

class ProxyConfigError(Exception):
    pass


class ProxyAutoConfig(object):
    """Wrapper class for pacparser

    Wrap pacparser URL handling to a class

    """

    def __init__(self, pac_url=None, timeout=DEFAULT_QUERY_TIMEOUT):
        if pac_url is None:
            default_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            try:
                wpad_domain = '.'.join(socket.getfqdn('wpad').split('.')[1:])
            except socket.GAIError, emsg:
                raise ProxyConfigError('Error querying wpad hostname: %s' % emsg)
            socket.setdefaulttimeout(default_timeout)

            if wpad_domain == '':
                raise ProxyConfigError('No URL given and WPAD hostname not available')
            else:
                pac_url = 'http://wpad.%s/wpad.dat' % wpad_domain

        self.pac_url = pac_url
        self.data = None

    def __read_pac__(self):
        """Read PAC URL

        Read and parse wpad.dat data from configured URL

        """
        if self.pac_url is None:
            raise ProxyConfigError('PAC URL not configured')

        res = requests.get(self.pac_url)
        if res.status_code != 200:
            raise ProxyConfigError('Error retrieving PAC from %s' % self.pac_url)

        self.data = StringIO.StringIO()
        self.data.write(res.content)
        self.data.seek(0)

    def __repr__(self):
        return 'PAC: %s' % self.pac_url

    def __str__(self):
        """PAC as string

        Return PAC contents as string

        """

        if self.data is None:
            self.__read_pac__()

        self.data.seek(0)
        return self.data.read()

    def validate(self):
        """Validate PAC with pacparser

        Validate resolved PAC configuration with pacparser libarry

        """
        pacparser.init()
        pacparser.parse_pac_string(str(self))
        pacparser.cleanup()

    def find_proxies(self, url):
        """Parse proxy URL for provided URL

        Parse PAC and return proxy URL for given URL

        """

        try:
            protocol = url.split('://')[0]
        except ValueError:
            raise ProxyConfigError('Invalid URL: %s' % url)

        try:
            pacparser.init()
            pacparser.parse_pac_string(str(self))
            proxies = pacparser.find_proxy(url)
            pacparser.cleanup()
        except:
            raise ProxyConfigError('Error parsing PAC: %s' % self.pac_url)
        data = {}
        for v in [x.strip() for x in proxies.split(';')]:
            if v == 'DIRECT':
                continue

            if v[:6] == 'PROXY ':
                data[protocol] = v[6:]
        return data

    def proxy_handler(self, url):
        """Create proxyhandler for URL

        Create a urllib2 proxy handler from parser data for provided url

        """

        try:
            protocol = url.split('://')[0]
        except ValueError:
            raise ProxyConfigError('Invalid URL: %s' % url)

        proxies = self.find_proxies(url)

        if proxies:
            return urllib2.ProxyHandler(proxies)
        else:
            return urllib2.ProxyHandler()

