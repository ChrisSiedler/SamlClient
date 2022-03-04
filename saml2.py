#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Web client for SAML login.
Make SAML2 protected webpage accesable for scripts.
Working with Apache mod_auth_mellon webserver and Win ADFS server
"""

__author__ = "Chris Siedler"
__contact__ = "mail@chris-siedler.at"
__date__ = "2022/03/04"
__license__ = "MIT"
__status__ = "Production"
__version__ = "0.1.0"


import requests
from requests_ntlm import HttpNtlmAuth
from urllib.parse  import urlparse
import re

assertion_url_regex = re.compile('<form method="POST".*action="(.*?)"')
relay_state_regex   = re.compile('<input type="hidden" name="RelayState" value="(.*?)" ?\/>')
saml_response_regex = re.compile('<input type="hidden" name="SAMLResponse" value="(.*?)" ?\/>')


class Client:
	#-----------------------
	def __init__(self, username=None, password=None):
		self.username = username
		self.password = password
		self.rs = requests.Session()

		self.headers = {
			"Upgrade-Insecure-Requests": '1',
			"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
		}

	#-----------------------
	@staticmethod
	def _printdata(r):
		print("URL:   ", r.url)
		print("Status:", r.status_code)
		print("Header:", r.headers)
		print("Text:\n", r.text)

	#-----------------------
	def login(self, url):

		r = self.rs.get(url, headers=self.headers, auth=HttpNtlmAuth(self.username, self.password))
#		self._printdata(r)

		u = urlparse(r.url)
		assertion_url = assertion_url_regex.search(r.text).group(1)
		saml_data = {
			'RelayState': 	relay_state_regex.search(r.text).group(1),
			'SAMLResponse': saml_response_regex.search(r.text).group(1),
		}

#		print(f"assertion_url: {assertion_url}")
#		print(f"SAML Data: {saml_data}")

		self.headers["Referer"] = f"{u.scheme}://{u.hostname}"

		r = self.rs.post(assertion_url, headers=self.headers, data=saml_data)
#		self._printdata(r)
		return r

	#-----------------------
	def _get(self, url):
		r = self.rs.get(url, headers=self.headers)
		
		if r.status_code == 401:
			return self.login(r.url)

		return r


	#----------------------------
	def get(self, url):
		r = self._get(url)
		return r.status_code, r.text


#==============================================================================================
if __name__ == '__main__':

	# test example:
	c1 = Client('user', 'SecretPW')
	print(c1.get('https://mysaml.secured.webpage.com/sauerkraut'))


