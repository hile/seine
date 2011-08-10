"""
Wrapper for urllib2 to do some basic tasks with URLs.
Written by Ilkka Tuohela <hile@iki.fi>, 2007-2011.
Licensed under BSD license.
"""

import os,sys,re,socket,tempfile,logging
import urllib,urllib2,cookielib

from seine.address import IPv4Address,IPv6Address 

# Default socket timeout for requests, can be overriden with 'timeout' keyword
DEFAULT_TIMEOUT = 30
DEFAULT_USERAGENT='Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.8) Gecko/2009032609 Firefox/3.0.8'
DEFAULT_PROTOCOL = 'http'

class HTTPRequestError(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return self.parameter

class HTTPRequest(object):
    def __init__(self,headers={},proxy_url=None,timeout=DEFAULT_TIMEOUT,retries=1,auth_realm=None,auth_user=None,auth_pass=None):
        self.req = None
        self.cookies = cookielib.LWPCookieJar()
        self.headers = headers
        self.retries = retries

        if not self.headers.has_key('User-Agent'):
            self.headers['User-Agent'] = DEFAULT_USERAGENT
        try:
            self.timeout = int(timeout)
        except ValueError:
            raise ValueError('Invalid timeout value: %s' % timeout)
        if proxy_url is None:
            proxy_url = os.getenv('http_proxy')
        self.proxy_url = proxy_url 

        if auth_realm is not None:
            self.auth = urllib2.ProxyBasicAuthHandler()
            self.auth.add_password(auth_realm,self.proxy_url,auth_user,auth_pass)
        else:
            self.auth = None

    def __getattr__(self,attr):
        if attr == 'url':
            if self.req is None: 
                return None
            return self.req.get_full_url()
        if attr == 'proxy_handler':
            if self.proxy_url is None:
                return (urllib2.ProxyHandler(),None)
            return (
                urllib2.ProxyHandler({'http':self.proxy_url,'https':self.proxy_url}),
                self.auth
            )
        if attr == 'opener':
            (proxy,auth) = self.proxy_handler 
            if auth:    
                return urllib2.build_opener(auth,proxy)
            else:
                return urllib2.build_opener(proxy)
        raise AttributeError('No such HTTPRequest attribute: %s' % attr)

    def request(self,url,method='GET',form=None,headers={},timeout=None):
        """
        Send a HTTP GET or POST request
        """
        if timeout is None:
            timeout = self.timeout
        socket.setdefaulttimeout(timeout)

        h = dict(self.headers)
        h.update(headers)
        data = form is not None and urllib.urlencode(form) or None

        retries = 0
        while retries<=self.retries:
            retries+=1
            try:
                req = self.opener.open(urllib2.Request(url,data,h))
            except urllib2.URLError, e:
                raise HTTPRequestError(str(e))
        
            try:
                code = 200
                data = req.read()
                headers = req.info()
            except urllib2.HTTPError,e:
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
            return (code,data,headers)

    def GET(self,url,headers={},timeout=None):
        return self.request(url,method='GET',form=None,
            headers=headers,timeout=timeout
        )

    def POST(self,url,form):
        return self.request(url,method='POST',form=form,
            headers=headers,timeout=timeout
        )

