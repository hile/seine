"""
Parsers for various whois text data formats
"""

from seine.whois import WhoisError

class WhoisDataParser(dict):
	tlds = ()
	def __init__(self):
		self.domain = None
		self.data = None

	@property
	def name(self):
		return __class__

	def __repr__(self):
		return 'whois data for %s' % self.domain

	def matches_domain(self, domain):
		tld = domain.rstrip('.').split('.')[-1]
		return tld in self.tlds

	def set(self, key, value):
		if key in self.keys():
			if not isinstance(self[key], list):
				self[key] = [self[key]]
			self[key].append(value)
		else:
			self[key] = value

		return value

	def parse(self, domain, data):
		self.clear()
		self.domain = domain

		if isinstance(data, basestring):
			data = data.replace('\r\n', '\n').split('\n')
		self.data = data

		return data
