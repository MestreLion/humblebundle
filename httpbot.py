#!/usr/bin/python
# -*- coding: utf-8 -*-
#
#    Copyright (C) 2012 Rodrigo Silva (MestreLion) <linux@rodrigosilva.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. See <http://www.gnu.org/licenses/gpl.html>
#
# urllib2 wrapper for a simpler, higher-level API

import os.path
import urllib
import urllib2
import urlparse
import logging
from urlparse import urlsplit

# Debian/Ubuntu: python-lxml
from lxml import html
try:
    # Debian/Ubuntu: python-progressbar
    import progressbar
except ImportError:
    progressbar = None


log = logging.getLogger(__name__)

class HttpBot(object):
    """ Base class for other handling basic http tasks like requesting a page,
        download a file and cache content. Not to be used directly
    """
    def __init__(self, base_url="", tag="", cookiejar=None, debug=False):
        hh  = urllib2.HTTPHandler( debuglevel=1 if debug else 0)
        hsh = urllib2.HTTPSHandler(debuglevel=1 if debug else 0)
        cp  = urllib2.HTTPCookieProcessor(cookiejar)
        self._opener = urllib2.build_opener(hh, hsh, cp)
        scheme, netloc, path, q, f  = urlparse.urlsplit(base_url, "http")
        if not netloc:
            netloc, _, path = path.partition('/')
        self.base_url = urlparse.urlunsplit((scheme, netloc, path, q, f))

    def get(self, url, postdata=None):
        """ Send an HTTP request, either GET (if no postdata) or POST
            Keeps session and other cookies.
            postdata is a dict with name/value pairs
            url can be absolute or relative to base_url
        """
        url = urlparse.urljoin(self.base_url, url)
        if postdata:
            return self._opener.open(url, urllib.urlencode(postdata))
        else:
            return self._opener.open(url)

    def download(self, url, path=None, total=0, progress=True, CHUNK=0):
        download = self.get(url)

        path = os.path.expanduser(path or ".")

        # If save name is not set, use the downloaded file name
        # "Not set" means either path is an existing dir or ends with a trailing '/'
        if os.path.isdir(path) or not os.path.basename(path):
            path = os.path.join(path, os.path.basename(urlsplit(download.geturl()).path))
        log.info("Downloading to %s", path)

        # Handle dir
        dirname, _ = os.path.split(path)
        try:
            os.makedirs(dirname)
        except OSError as e:
            if e.errno != 17:  # File exists
                raise

        CHUNK = CHUNK or 32*1024
        show = progress and progressbar
        if show:
            size = total or int(download.info().get('Content-Length', 0))
            pbar = progressbar.ProgressBar(widgets=[
                ' ', progressbar.Percentage(), ' of %.1f MiB' % (size/1024.0**2),
                ' ', progressbar.Bar('.'),
                ' ', progressbar.FileTransferSpeed(),
                ' ', progressbar.ETA(),
                ' '],maxval=size).start()
        with open(path,'wb') as f:
            while True:
                chunk = download.read(CHUNK)
                if not chunk:
                    break
                f.write(chunk)
                if show:
                    pbar.update(min([size, pbar.currval + CHUNK]))
        if show:
            pbar.finish()

        return path

    def quote(self, text):
        """ Quote a text for URL usage, similar to urllib.quote_plus.
            Handles unicode and also encodes "/"
        """
        if isinstance(text, unicode):
            text = text.encode('utf-8')
        return urllib.quote_plus(text, safe=b'')

    def parse(self, url, postdata=None):
        """ Parse an URL and return an etree ElementRoot.
            Assumes UTF-8 encoding
        """
        return html.parse(self.get(url, postdata),
                          parser=html.HTMLParser(encoding='utf-8'))
