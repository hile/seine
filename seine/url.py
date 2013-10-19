"""
Wrapper for urllib2 to do some basic tasks with URLs.
Written by Ilkka Tuohela <hile@iki.fi>, 2007-2012.
Licensed under BSD license.

NOTE:
This module is a obsolete hack: please use 'requests' module.

"""

import os
import sys
import re
import socket
import urllib
import urllib2
import cookielib

from seine.address import IPv4Address, IPv6Address

# Default socket timeout for requests,  can be overriden with 'timeout' keyword
DEFAULT_RETRIES = 1
DEFAULT_TIMEOUT = 30
DEFAULT_USERAGENT='Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.8) Gecko/2009032609 Firefox/3.0.8'
DEFAULT_PROTOCOL = 'http'

class HTTPRequestError(Exception):
    def __str__(self):
        return ' '.join(str(x) for x in self.args)

class HTTPRequest(object):
    """
    URL requests
    Arguments:
    proxy_url   URL to proxy, or environment http_proxy
    user_agent  User-Agent header or DEFAULT_USERAGENT
    """
    def __init__(self, **kwargs):
        self.req = None
        self.headers = {
            'User-Agent': kwargs.get('user_agent', DEFAULT_USERAGENT),
        }
        self.cookies = cookielib.LWPCookieJar()

        self.proxy_url= kwargs.get('http_proxy', os.getenv('http_proxy'))
        self.timeout = kwargs.get('timeout', DEFAULT_TIMEOUT)
        self.retries = kwargs.get('retries', DEFAULT_RETRIES)
        self.auth_realm = kwargs.get('auth_realm', None)
        self.auth_user = kwargs.get('auth_user', None)
        self.auth_pass = kwargs.get('auth_pass', None)

        if self.auth_realm is not None:
            self.auth = urllib2.ProxyBasicAuthHandler()
            self.auth.add_password(
                self.auth_realm,
                self.proxy_url,
                self.auth_user,
                self.auth_pass
            )
        else:
            self.auth = None

    def __getattr__(self, attr):
        if attr == 'url':
            return self.get_url()
        if attr == 'proxy_handler':
            return self.get_proxy_handler()
        if attr == 'opener':
            return self.get_opener()
        raise AttributeError('No such HTTPRequest attribute: %s' % attr)

    @property
    def get_url(self):
        return self.req is not None and self.req.get_full_url() or None

    def get_proxy_handler(self):
        if self.proxy_url is not None:
            handler = (
                urllib2.ProxyHandler(
                    {'http':self.proxy_url, 'https':self.proxy_url
                }),
                self.auth
            )
        else:
            handler = (urllib2.ProxyHandler(), None)
        return handler

    def get_opener(self):
        (proxy, auth) = self.get_proxy_handler()
        if auth:
            return urllib2.build_opener(auth, proxy)
        else:
            return urllib2.build_opener(proxy)

    def request(self, url, method='GET', **kwargs):
        """
        Send a HTTP GET or POST request.
        Returns tuple (code, data, headers)
        """
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(kwargs.get('timeout', self.timeout))

        h = dict(self.headers)
        h.update(kwargs.get('headers', {}))
        form = kwargs.get('form', None)
        data = form is not None and urllib.urlencode(form) or None

        try:
            retries = 0
            opener = self.get_opener()
            while retries<=self.retries:
                retries+=1
                try:
                    req = opener.open(urllib2.Request(url, data, h))
                except urllib2.URLError, e:
                    raise HTTPRequestError(str(e))
                try:
                    code = 200
                    data = req.read()
                    headers = req.info()
                except urllib2.HTTPError, e:
                    code = e.code
                    data = e.read()
                    headers = {}
                except urllib2.URLError, e:
                    msg = e.reason[1]
                    if self.proxy_url:
                        msg += ' (using proxy %s)' % self.proxy_url
                    raise HTTPRequestError(msg)
                except socket.timeout:
                    if retries >= self.retries:
                        raise HTTPRequestError('Request timeout')
                return (code, data, headers)
        finally:
            socket.setdefaulttimeout(old_timeout)

    def GET(self, url, headers={}, timeout=None):
        return self.request(url, method='GET', form=None,
            headers=headers, timeout=timeout
        )

    def POST(self, url, form):
        return self.request(url, method='POST', form=form,
            headers=headers, timeout=timeout
        )

