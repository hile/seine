#!/usr/bin/env python
"""
Classes to parse different whois output formats
"""

import sys,os,re,time

from netutils.dns.tld import TLDCache,DNSCacheError

class WhoisFormatError(Exception):
    def __str__(self):
        return str(self.args[0])

class WhoisDataTemplate(object):
    def __init__(self,domain,data):
        self.status = []
        self.name = domain.strip('=')
        self.nameservers = []
        self.domain = {}
        self.admin = {}
        self.billing = {}
        self.technical = {}
        self.registrant = {}

class WhoisFormatSaudiNIC(WhoisDataTemplate):
    def __init__(self,domain,data):
        super(WhoisFormatSaudiNIC,self).__init__(domain,data)

        re_info = re.compile(r'^([a-z-]*):\s*(.*)$')
        for l in data:
            m = re.match(re_info,l)
            if not m: continue
            key = m.group(1)
            value = m.group(2)
            if value == '':
                continue

            if key == 'admin-c': 
                self.admin['contact'] = value
            elif key == 'tech-c': 
                self.technical['contact'] = value
            elif key == 'reg-c': 
                self.registrant['contact'] = value
            elif key == 'source':
                self.registrant[key] = value
            elif key in ['organization','contact']:
                self.admin[key] = value
            elif key == 'address':
                if not self.admin.has_key('address'):
                    self.admin['address'] = []
                self.admin['address'].append(value)
            elif key == 'req-date':
                self.domain['requested'] = value
            elif key == 'reg-date':
                self.domain['created'] = value
            elif key == 'domain':
                self.domain['domain'] = value
            elif key == 'nserver':
                self.nameservers.append(value)
            else:
                raise WhoisFormatError('Received unknown key %s' % (key))

class WhoisFormatFicora(WhoisDataTemplate):
    def __init__(self,domain,data):
        super(WhoisFormatFicora,self).__init__(domain,data)

        re_info = re.compile(r'^([a-z0-9]*):\s*(.*)$')
        for l in data:
            m = re.match(re_info,l)
            if not m: continue
            key = m.group(1)
            value = m.group(2)
            if value == '':
                continue

            if key in ['descr','address','phone']: 
                if not self.admin.has_key(key):
                    self.admin[key] = []
                self.admin[key].append(value)
            elif key == 'created':
                value = value.strip()
                try:
                    self.domain['created'] = time.strptime(value,'%d.%m.%Y')
                except ValueError:
                    raise WhoisFormatError('Invalid create date format: %s' % value)
            elif key == 'expires':
                value = value.strip()
                try:
                    self.domain['expires'] = time.strptime(value,'%d.%m.%Y')
                except ValueError:
                    raise WhoisFormatError('Invalid expire date format: %s' % value)
            elif key == 'status':
                self.status.append(value)
            elif key == 'domain':
                self.domain['domain'] = value
            elif key == 'nserver':
                self.nameservers.append(value.split()[0])
            else:
                raise WhoisFormatError('Received unknown key %s' % (key))

class WhoisFormatComTLD(WhoisDataTemplate):
    def __init__(self,domain,data):
        super(WhoisFormatComTLD,self).__init__(domain,data)

        re_info = re.compile(r'^\s+([A-Za-z0-9 ]*): (.*)$')
        skip = False
        for l in data:
            m = re.match(re_info,l)
            if not m: continue
            key = m.group(1)
            value = m.group(2)
            if value == '': 
                if skip: 
                    skip == False
                continue
            try:
                (group,field) = key.split(None,1)
            except ValueError:
                group = key
                field = None
        
            if key == 'Server Name':
                if value.lower() == self.name:
                    skip = False
                else:
                    skip = True
                continue

            if key == 'Domain Name': 
                if value.lower() == self.name:
                    self.domain['domain'] = value.lower()
                    skip = False
            elif skip: 
                continue
            elif key == 'Creation Date': 
                try:
                    self.domain['created'] = time.strptime(value,'%d-%b-%Y')
                except ValueError:
                    raise WhoisFormatError('Invalid create date format: %s' % value)
            elif key == 'Updated Date': 
                try:
                    self.domain['updated'] = time.strptime(value,'%d-%b-%Y')
                except ValueError:
                    raise WhoisFormatError('Invalid update date format: %s' % value)
            elif key == 'Expiration Date': 
                 try:
                    self.domain['expires'] = time.strptime(value,'%d-%b-%Y')
                 except ValueError:
                    raise WhoisFormatError('Invalid expire date format: %s' % value)
            elif key == 'Registrar': 
                self.domain['registrar'] = value
            elif key == 'Referral URL': 
                self.domain['url'] = value
            elif key == 'Whois Server': 
                self.domain['whois-server'] = value
            elif key == 'Status':
                self.status.append(value)
            elif key == 'Name Server':
                self.nameservers.append(value.lower())
            else:
                #print '"%s", "%s"' % (key,value)
                raise WhoisFormatError('Received unknown key %s' % (key))

class WhoisFormatInfoTLD(WhoisDataTemplate):
    def __init__(self,domain,data):
        super(WhoisFormatInfoTLD,self).__init__(domain,data)

        re_info = re.compile(r'^([A-Za-z0-9 ]*):(.*)$')
        for l in data:
            m = re.match(re_info,l)
            if not m: continue
            key = m.group(1)
            value = m.group(2)
            if value == '': 
                continue
            try:
                (group,field) = key.split(None,1)
            except ValueError:
                group = key
                field = None

            if group == 'Admin':
                if self.admin.has_key(field):
                    raise WhoisFormatError('Duplicate Admin field %s' % field)
                self.admin[field] = value
            elif group == 'Billing':
                if self.billing.has_key(field):
                    raise WhoisFormatError('Duplicate Billing field %s' % field)
                self.billing[field] = value
            elif group == 'Tech':
                if self.technical.has_key(field):
                    raise WhoisFormatError('Duplicate Tech field %s' % field)
                self.technical[field] = value
            elif group == 'Registrant':
                if self.registrant.has_key(field):
                    raise WhoisFormatError('Duplicate Tech field %s' % field)
                self.registrant[field] = value
            elif key == 'Domain ID': 
                self.domain['id'] = value
            elif key == 'Domain Name': 
                self.domain['domain'] = value.lower()
            elif key == 'Created On': 
                try:
                    value = value.strip()
                    self.domain['created'] = time.strptime(value,'%d-%b-%Y %H:%M:%S %Z')
                except ValueError,e:
                    raise WhoisFormatError('Invalid .info create date %s' % value)
            elif key == 'Last Updated On': 
                try:
                    value = value.strip()
                    self.domain['updated'] = time.strptime(value,'%d-%b-%Y %H:%M:%S %Z')
                except ValueError:
                    raise WhoisFormatError('Invalid .info update date %s' % value)
            elif key == 'Expiration Date': 
                try:
                    value = value.strip()
                    self.domain['expires'] = time.strptime(value,'%d-%b-%Y %H:%M:%S %Z')
                except ValueError:
                    raise WhoisFormatError('Invalid .info expire date %s' % value)
            elif key == 'Sponsoring Registrar': 
                self.domain['registrar'] = value
            elif key == 'Status':
                self.status.append(value)
            elif key == 'Name Server':
                self.nameservers.append(value.lower())
            else:
                raise WhoisFormatError('Received unknown key %s' % (key))

WHOIS_TLD_FORMATS = {
    'com':      WhoisFormatComTLD,
    'fi':       WhoisFormatFicora,
    'info':     WhoisFormatInfoTLD,
    'net':      WhoisFormatComTLD,
    'sa':       WhoisFormatSaudiNIC,
}

class WhoisFormatParser(object):
    def __init__(self,domain,data):
        tld = TLDCache()[domain.split('.')[-1]]
        if WHOIS_TLD_FORMATS.has_key(tld):
            self.data = WHOIS_TLD_FORMATS[tld](domain,data) 
        else:
            raise WhoisFormatError('No parser defined for TLD %s' % tld)

if __name__ == '__main__':
    try:
        path = sys.argv[1]
        domain = os.path.basename(path).split('.')[-1]
    except IndexError:
        print 'Usage: %s <whois-output-file>' % sys.argv[0]
        sys.exit(1)
    if not os.path.isfile(path):
        print 'No such file: %s' % path
        sys.exit(1)
    try:
        data = map(lambda x: x.rstrip(), open(path).read().split('\n'))
        w = WhoisFormatParser(domain,data)
        #for k,v in w.data.domain.items(): print k,v
        now = long(time.time())
        expires = long(time.mktime(w.data.domain['expires']))
        print 'Nameservers:', ','.join(w.data.nameservers)
        if expires >= now:
            print 'Domain expires in %d days' % ((expires-now)/86400)
        else:
            print 'Domain has expired!'
    except WhoisFormatError,e:
        print e
        sys.exit(1)


