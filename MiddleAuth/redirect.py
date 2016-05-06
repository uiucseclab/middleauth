#!/usr/bin/env python

import httplib
import urllib, urllib2

httplib.HTTPConnection.debuglevel = 1

page = urllib.urlopen('http://130.126.136.112')
print page.read()

'''
import functools
import httplib
import urllib2

class BoundHTTPHandler(urllib2.HTTPHandler):

    def __init__(self, source_address=None, debuglevel=0):
        urllib2.HTTPHandler.__init__(self, debuglevel)
        self.http_class = functools.partial(httplib.HTTPConnection,
                source_address=source_address)

    def http_open(self, req):
        return self.do_open(self.http_class, req)

handler = BoundHTTPHandler(source_address=("192.168.1.1", 0))
opener = urllib2.build_opener(handler)
urllib2.install_opener(opener)

page = urllib2.urlopen('http://130.126.136.112')
'''
