#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# humblebundle - Manager for Humble Bundle games and bundles
#
#    Copyright (C) 2013 Rodrigo Silva (MestreLion) <linux@rodrigosilva.com>
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

HB_USERNAME = ""
HB_PASSWORD = ""
HB_AUTH = ""

import os
import os.path as osp
import sys
import re
import json
import logging
import argparse
import xdg.BaseDirectory as xdg
import time
import cookielib
from urlparse import urljoin, urlsplit, parse_qs
import Queue
import threading

try:
    import keyring
except ImportError:
    keyring = None

import httpbot

log = logging.getLogger(__name__)
myname = __name__
configdir = None

class HumbleBundleError(Exception):
    pass

class HumbleBundle(httpbot.HttpBot):

    name = "Humble Bundle"
    url = "https://www.humblebundle.com"

    def __init__(self, username=None, password=None, auth=None, debug=False):
        self.username = username
        self.password = password
        self.auth     = auth

        self.cookiejar = cookielib.MozillaCookieJar(filename=osp.join(configdir, "cookies.txt"))
        try:
            self.cookiejar.load()
        except (IOError, cookielib.LoadError) as e:
            log.error('Error reading cookies: %s', e)

        if auth:
            log.info("Injecting authenticated cookie")
            expires = int(auth.split('|')[1]) + 730 * 24 * 60 * 60
            cookie = cookielib.Cookie(version = 0,
                                      name = '_simpleauth_sess',
                                      value = self.auth,
                                      port = None,
                                      port_specified = False,
                                      domain = urlsplit(self.url)[1],
                                      domain_specified = False,
                                      domain_initial_dot = False,
                                      path = '/',
                                      path_specified = False,
                                      secure = True,
                                      expires = expires,
                                      discard = False,
                                      comment = None,
                                      comment_url = None,
                                      rest={},)
            self.cookiejar.set_cookie(cookie)

        super(HumbleBundle, self).__init__(self.url,
                                           tag=myname,
                                           cookiejar=self.cookiejar,
                                           debug=debug)

        self.bundles = {}  # "purchases" in website. May not be technically a bundle, like Store Purchases
        self.games   = {}  # "subproducts" in json. May not be a game, like Soundtracks and eBooks

        try:
            with open(osp.join(configdir, "bundles.json")) as fp1:
                with open(osp.join(configdir, "games.json")) as fp2:
                    self.bundles = json.load(fp1)
                    self.games   = json.load(fp2)
                    log.info("Loaded %d games from %d bundles" % (len(self.games), len(self.bundles)))
                    return
        except IOError:
            self.update()


    def update(self):
        ''' Fetch all bundles and games from the server, rebuilding the cache '''
        self.bundles = {}
        self.games   = {}

        # Get the keys
        log.info("Retrieving keys from '%s/home'", self.url)
        match = re.search(r'^\s*new window.Gamelist\s*\(.*,\s*gamekeys\s*:\s*(\[.*\])',
                          self.get('/home').read(), re.MULTILINE)
        if not match:
            raise HumbleBundleError("GameKeys list not found")

        # Loop the bundles
        queue = Queue.Queue()
        keys = json.loads(match.groups()[0])
        for key in keys:
            t = threading.Thread(target=self._load_key, args=(key, True, queue))
            t.daemon = True
            t.start()

        for _ in xrange(len(keys)):
            bundle, games = queue.get()
            self.bundles.update(bundle)
            self.games.update(games)

        log.info("Updated %d games from %d bundles" % (len(self.games), len(self.bundles)))
        self._save_data()


    def _save_data(self):
        for obj in ['bundles', 'games']:
            path = osp.join(configdir, "%s.json" % obj)
            try:
                with open(path, 'w') as f:
                    json.dump(getattr(self, obj), f,
                              indent=2, separators=(',', ': '), sort_keys=True)
                os.chmod(path, 0600)
            except IOError as e:
                log.error("Error saving cache data: %s", e)


    def _load_key(self, key, batch=False, queue=None):

        url = "/api/v1/order/%s" % key
        log.info("Retrieving purchase info from '%s%s'", self.url, url)
        bundle = json.load(self.get(url))
        bundle['games'] = []  # made-up field: list of games it contains
        bundlekey = bundle['product']['machine_name']

        # Loop each game in the bundle
        games = {}
        for game in bundle['subproducts']:
            gamekey = game['machine_name']

            # Add game name to its bundle game list
            bundle['games'].append(gamekey)

            # Add custom fields and insert game in games dict (overwriting)
            game['bundle'] = bundlekey  # made-up field: bundle it was retrieved from
            games[gamekey] = game

        # remove the now redundant "subproducts" list, and the useless "subscriptions"
        del bundle['subproducts']
        del bundle['subscriptions']

        # Move 'products' sub-dict to root
        for k, v in bundle['product'].iteritems():
            bundle[k] = v
        del bundle['product']

        # Sort games list
        bundle['games'].sort()

        # Batch-processing: do not update nor save bundles and games dict
        if batch:
            out = ({bundlekey:bundle}, games)
            if queue:
                queue.put(out)
                return
            else:
                return out

        # Add bundle to bundles list
        self.games.update(games)
        self.bundles[bundlekey] = bundle
        self._save_data()


    def download(self, name, path=None, type=None, arch=None, platform=None,
                 bittorrent=False, type_pref=".deb", arch_pref="64", retry=True):

        def download_info(d):
            a = "\t(%s-bit)" % d['arch'] if d.get('arch', None) else ""
            return "'%s'%s\t%s\t%s" % (d['name'], a, d['human_size'],
                                        urlsplit(d['url']['web']).path[1:])

        def do_download(d):
            url = d['url']['bittorrent' if bittorrent else 'web']

            # Check if URL has expired
            try:
                ttl = int(parse_qs(urlsplit(url).query)['ttl'][0])
            except (KeyError, IndexError, ValueError):
                ttl = 0
            if ttl < time.time():
                if not retry:
                    raise HumbleBundleError("Game data for '%s' expired %s." %
                                            (name, time.ctime(ttl)))

                log.warn("Game data for '%s' expired %s, will update and retry.",
                         name, time.ctime(ttl))
                self._load_key(self.bundles.get(game.get('bundle', ''),
                                                {}).get('gamekey', ''))
                return self.download(name=name,
                                     path=path,
                                     type=type,
                                     arch=arch,
                                     platform=platform,
                                     bittorrent=bittorrent,
                                     type_pref=type_pref,
                                     arch_pref=arch_pref,
                                     retry=False)

            log.info("Downloading '%s' [%s]\t%s",
                     game['human_name'], game['machine_name'], download_info(d))
            try:
                return super(HumbleBundle, self).download(url, path)
            except httpbot.urllib2.HTTPError as e:
                if e.code == 403:
                    # Unauthorized. Most likely outdated download URL
                    raise HumbleBundleError(
                        "Download error: %d %s. URL may be outdated, try --update" %
                        (e.code, e.reason))
                else:
                    raise

        game = self.get_game(name)
        candidates = []
        finalists = []

        # Eliminate the ones that do not match the explicit request
        for plat in game.get('downloads', []):
            if plat.get('platform', '') == platform:
                for download in plat.get('download_struct', []):
                    if not download.get('url', ''):
                        continue
                    if type and type.lower() not in download.get('name', '').lower():
                        continue
                    if not download.get('arch', ''):
                        if re.search('(?:32|64)[- ]?bit|i386|x86_64', download.get('name','')):
                            if '64' in download['name']:
                                download['arch'] = "64"
                            else:
                                download['arch'] = "32"
                    if arch and download.get('arch', '') and download['arch'] != arch:
                        continue

                    candidates.append(download)

        if len(candidates) == 1:
            return do_download(candidates[0])

        if len(candidates) == 0:
            log.error("No valid downloads for game '%s' [%s], criteria %r",
                      game['human_name'], game['machine_name'], {'type':type, 'arch':arch})
            return

        log.debug("Many download candidates for '%s' [%s], criteria %r: \n%s",
                  game['human_name'], game['machine_name'], {'type':type, 'arch':arch},
                  json.dumps(candidates, indent=2))

        # Try type (download name) preference
        if not type:
            for download in candidates:
                if type_pref.lower() in download.get('name', '').lower():
                    finalists.append(download)

        if len(finalists) == 1:
            return do_download(finalists[0])

        # Multiple finalists. Set them as next candidates
        # If no finalists, candidates remain the same
        if len(finalists) > 1:
            candidates = finalists  # be careful
        finalists = []  # must NOT be .clear(), see above

        # Try arch preference
        if not arch:
            for download in candidates:
                if download.get('arch', '') and download['arch'] == arch_pref:
                    finalists.append(download)

        if len(finalists) == 1:
            return do_download(finalists[0])

        # Give up
        log.error("Too many download candidates for '%s' [%s]. Improve criteria to narrow it down.%s",
                  game['human_name'], game['machine_name'],
                  "".join(["\n\t%s" % download_info(x) for x in finalists or candidates]))
        #log.debug("\n%s", json.dumps(finalists or candidates, indent=2))
        return


    def get_game(self, name):
        # Get game, if exists
        log.info("Retrieving game info for '%s'", name)
        try:
            return self.games[name]
        except KeyError:
            raise HumbleBundleError("Game not found: %s" % name)


    def get(self, url, postdata=None):

        def urlabspath(url):
            return urlsplit(urljoin('/', url)).path.lower()

        def save_cookies(url, res):
            if (urlabspath(url) == "/login" or
                res.info().has_key('Set-Cookie')):
                log.debug("Saving cookies to '%s'", self.cookiejar.filename)
                try:
                    self.cookiejar.save()
                    os.chmod(self.cookiejar.filename, 0600)
                except IOError as e:
                    log.error("Error saving cookies: %s", e)

        try:
            res = super(HumbleBundle, self).get(url, postdata)
            save_cookies(url, res)
            # Was it successful? (intended to be /login or not redirected to /login)
            if (    urlabspath(       url  ) == "/login" or
                not urlabspath(res.geturl()) == '/login'):
                return res
        except httpbot.urllib2.HTTPError as e:
            # Unauthorized (requires login) or something else?
            if not e.code == 401:
                raise

        if not (self.username and self.password):
            raise HumbleBundleError(
                "Username or password are blank. "
                "Set with --username and --password and try again")

        log.info("Authenticating at '%s/login'", self.url)
        res = super(HumbleBundle, self).get("/login",
                                            {'goto'    : url,
                                             'username': self.username,
                                             'password': self.password})
        save_cookies("/login", res)

        # Was it successfully redirected to the page requested?
        if urlabspath(res.geturl()) == urlabspath(url):
            return res

        raise HumbleBundleError(
            "Could not log in. Either username/password are not correct, "
            "or a ReCaptcha validation is required. "
            "Log in using a real browser, inspect the cookies created "
            "and provide the value of _simpleauth_sess with --auth")




def main(args):

    config = read_config(args)

    username = args.username or config['username'] or HB_USERNAME
    password = args.password or config['password'] or HB_PASSWORD
    auth     = args.auth                           or HB_AUTH

    hb = HumbleBundle(username, password, auth, debug=args.debug)

    if args.update:
        hb.update()

    if args.list:
        for game in sorted(hb.games.keys()):
            print "%s" % game
        return

    if args.show:
        def print_key(key, alias=None, obj=None):
            print "%-10s: %s" % (alias or key, getattr(obj or game, 'get')(key, ''))

        game = hb.get_game(args.show)
        print_key('machine_name', 'Game')
        print_key('human_name', 'Name')
        print_key('human_name', 'Developer', obj=game.get('payee',{}))
        print_key('url', 'URL')
        print_key('', 'Bundles')
        for bundle in hb.bundles.itervalues():
            if game.get('machine_name', '') in bundle.get('games', []):
                print "\t%s [%s]" % (bundle['human_name'], bundle['machine_name'])
        print_key('', 'Downloads')
        platform_prev = None
        for download in sorted(game.get('downloads', []), key=lambda k: k['platform']):
            platform = download.get('platform', '')
            if platform_prev != platform:
                print "\t%s" % platform
                platform_prev = platform
            for d in download.get('download_struct', []):
                a = " %s-bit" % d['arch'] if d.get('arch', None) else ""
                print "\t\t%-20s%s\t%8s\t%s" % (d['name'], a, d['human_size'],
                                                urlsplit(d['url']['web']).path[1:])
        return

    if args.list_bundles:
        for bundle in sorted(hb.bundles.items()):
            print ("%s\t%s" % (bundle[1]['machine_name'], bundle[1]['human_name'])).encode('utf-8')
        return

    if args.download:
        hb.download(name=args.download, path=args.path, type=args.type, arch=args.arch,
                    bittorrent=args.bittorrent, platform=args.platform)
        return

    if False:
        for game in sorted(hb.games.items()):
            if (game[1]['machine_name'].endswith('_soundtrack') or
                game[1]['machine_name'].endswith('_android')):
                continue
            hb.download(game[1]['machine_name'], osp.join(configdir, 'packages'))


def read_config(args):
    config = osp.join(configdir, "login.conf")

    username = ""
    password = ""

    # read
    if keyring:
        log.debug("Reading credentials from keyring")
        username, password = (keyring.get_password(myname, '').split('\n') + ['\n'])[:2]
    else:
        log.debug("Reading credentials from '%s'" % config)
        try:
            with open(config, 'r') as fd:
                username, password = (fd.read().splitlines() + ['\n'])[:2]
        except IOError as e:
            log.error(e)

    # save
    if args.username or args.password:
        log.info("Saving credentials")
        if keyring:
            keyring.set_password(myname, '',
                                 '%s\n%s' % (args.username or username,
                                             args.password or password,))
        else:
            try:
                with open(config, 'w') as fd:
                    fd.write("%s\n%s\n" % (args.username or username,
                                           args.password or password,))
                os.chmod(config, 0600)
            except IOError as e:
                log.error(e)

    return dict(username=username,
                password=password,)


def parseargs(args=None):
    parser = argparse.ArgumentParser(
        description="Humble Bundle Manager.",)

    loglevels = ['debug', 'info', 'warn', 'error', 'critical']
    logdefault = 'debug'
    parser.add_argument('--loglevel', '-g', dest='loglevel',
                        default=logdefault, choices=loglevels,
                        help="set logging level, default is '%s'" % logdefault)

    parser.add_argument('--username', '-U', dest='username',
                        help="Account login, the user's email")

    parser.add_argument('--password', '-P', dest='password',
                        help="Account password")

    parser.add_argument('--auth', '-A', dest='auth',
                        help="Account _simpleauth_sess cookie")

    parser.add_argument('--download', '-d', dest='download',
                        help="Machine Name of the game to download. See --list")

    parser.add_argument('--type', '-t', dest='type',
                        help="Type (name) of the download, for example '.deb', 'mojo', 'flash', etc")

    parser.add_argument('--arch', '-a', dest='arch', choices=['32', '64'],
                        help="Download architecture: '32' or '64'")

    parser.add_argument('--platform', '-p', dest='platform',
                        default="linux", choices=['windows', 'mac', 'linux', 'android', 'audio'],
                        help="Download platform")

    parser.add_argument('--bittorrent', '-b', dest='bittorrent', default=False, action="store_true",
                        help="Download via bittorrent")

    parser.add_argument('--path', '-f', dest='path',
                        help="Path to download. If directory, default download basename will be used")

    parser.add_argument('--update', '-u', dest='update', default=False, action="store_true",
                        help="Fetch all games and bundles data from the server, rebuilding the cache")

    parser.add_argument('--list', '-l', dest='list', default=False, action="store_true",
                        help="List all available Games (Products), including Soundtracks and eBooks")

    parser.add_argument('--list-bundles', '-L', dest='list_bundles', default=False, action="store_true",
                        help="List all available Bundles (Purchases), "
                            "including Store Front (single product) purchases")

    parser.add_argument('--show', '-s', dest='show',
                        help="Show all info about selected game")

    return parser.parse_args(args)




if __name__ == '__main__':
    myname = osp.basename(osp.splitext(__file__)[0])
    configdir = xdg.save_config_path(myname)
    args = parseargs()
    args.debug = args.loglevel=='debug'
    logging.basicConfig(level=getattr(logging, args.loglevel.upper(), None),
                        format='%(asctime)s\t%(levelname)-8s\t%(message)s')

    try:
        sys.exit(0 if main(args) else 1)

    except HumbleBundleError as e:
        log.critical(e)
    except Exception as e:
        log.critical(e, exc_info=True)
        sys.exit(1)
