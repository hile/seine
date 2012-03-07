"""
Whois server and domain data query tools
"""

__all__ = ['client','parsers','servers']

class WhoisError(Exception):
    def __str__(self):
        return self.args[0]

