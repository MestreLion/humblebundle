#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# humblebundle - Manager for Humble Bundle games and bundles
#
#    Copyright (C) 2014 Rodrigo Silva (MestreLion) <linux@rodrigosilva.com>
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

# TODO:
# - INI-format config file for non-auth settings like arch-pref, debug level
# - Log to file, with debug or info level
# - Add --clear-cache, --clear-credentials, --clear-data, and --purge

HB_USERNAME = ""
HB_PASSWORD = ""

import os
import os.path as osp
import sys
import re
import json
import logging
import argparse
import time
import threading
import subprocess
import shlex
import shutil

try:
    import cookielib
    from urlparse import urljoin, urlsplit, parse_qs
    import Queue
except ImportError:  # Python 3
    import http.cookiejar as cookielib
    from urllib.parse import urljoin, urlsplit, parse_qs
    import queue as Queue


import xdg.BaseDirectory as xdg  # Debian/Ubuntu: python-xdg
try:
    import keyring  # Debian/Ubuntu: python-keyring
except ImportError:
    keyring = None


import httpbot


log = logging.getLogger(__name__)


# Defaults are suitable for usage as a library (imported module)
# They're changed when used as a script to adjust for __name__
APPNAME   = __name__
DATADIR   = osp.dirname(osp.realpath(__file__))
CONFIGDIR = osp.join(xdg.xdg_config_home, APPNAME)
CACHEDIR  = osp.join(xdg.xdg_cache_home, APPNAME)
AUTHFILE  = osp.join(CONFIGDIR, "login.auth")
COOKIEJAR = osp.join(CONFIGDIR, "cookies.txt")


class HumbleBundleError(Exception):
    pass

class HumbleBundle(httpbot.HttpBot):

    name = "Humble Bundle"
    url = "https://www.humblebundle.com"
    auth_urls = ("/login", "/user/humbleguard")

    def __init__(self, username=None, password=None, auth=None, code=None,
                 datadir=None, configdir=None, cachedir=None, cookiejar=None,
                 debug=False):
        self.username = username
        self.password = password

        self.datadir   = datadir   or DATADIR
        self.configdir = configdir or CONFIGDIR
        self.cachedir  = cachedir  or CACHEDIR

        if not os.path.isdir(self.configdir):
            # Create the config dir as xdg would. Let exceptions bubble up
            os.makedirs(self.configdir, 0o700)

        self.cookiejar = cookielib.MozillaCookieJar(filename=(cookiejar or
                                                              COOKIEJAR))
        try:
            self.cookiejar.load()
        except (IOError, cookielib.LoadError) as e:
            log.error('Error reading cookies: %s', e)

        if auth:
            log.info("Injecting authenticated cookie")
            expires = int(auth.split('|')[1]) + 730 * 24 * 60 * 60
            cookie = cookielib.Cookie(version = 0,
                                      name = '_simpleauth_sess',
                                      value = auth,
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
                                           tag=APPNAME,
                                           cookiejar=self.cookiejar,
                                           debug=debug)

        if code:
            log.info("Validating browser code at '%s/user/humbleguard'",
                     self.url)
            try:
                # Load coockies in unlikely case that cookies.txt was not present
                self.get("/")
                token = None
                for cookie in self.cookiejar:
                    if cookie.name == 'csrf_cookie':
                        token = cookie.value
                if token is None:
                    raise HumbleBundleError("Missing CSRF token")
                self.get("/user/humbleguard",
                               {'goto': "/home",
                                'qs'  : "",
                                '_le_csrf_token'  : token,
                                'code': code.upper()})
            except httpbot.HTTPError as e:
                raise HumbleBundleError("Incorrect browser verification code")

        # "purchases" in the website. May be non-bundle like Store Purchases
        self.bundles = {}
        # "subproducts" in json. May be not a game, like Soundtracks and eBooks
        self.games   = {}

        # Load bundles and games
        try:
            with open(osp.join(self.configdir, "bundles.json")) as fp1:
                with open(osp.join(self.configdir, "games.json")) as fp2:
                    self.bundles = json.load(fp1)
                    self.games   = json.load(fp2)
                    log.info("Loaded %d games from %d bundles",
                             len(self.games),
                             len(self.bundles))
            self._merge()
        except IOError:
            self.update()


    def _merge(self):
        # Merge extras
        extras = osp.join(self.datadir, "extras.json")
        log.debug("Merging extras from %s", extras)
        try:
            with open(extras) as fp:
                games = json.load(fp)
            self.games.update(games)
        except (IOError, ValueError) as e:
            log.warning("Error merging extras: %s", e)

        # Merge install instructions
        self.gamedata = osp.join(self.datadir, "gamedata.json")
        log.debug("Merging games install data from %s", self.gamedata)
        try:
            with open(self.gamedata) as fp:
                games = json.load(fp)
            for game in self.games:
                self.games[game].update(games.get(game, {}))
        except (IOError, ValueError) as e:
            log.warning("Error merging games install data: %s", e)


    def update(self):
        '''Fetch all bundles and games from the server, rebuilding the cache'''
        self.bundles = {}
        self.games   = {}

        # Get the keys
        log.info("Retrieving keys from '%s/home/keys'", self.url)
        match = re.search(r'^.*gamekeys\s*=\s*(\[.*\])',
                          self.get('/home/keys').read().decode('utf-8'),
                          re.MULTILINE)
        if not match:
            raise HumbleBundleError("GameKeys list not found")

        # Loop the bundles
        queue = Queue.Queue()
        keys = json.loads(match.groups()[0])
        for key in keys:
            t = threading.Thread(target=self._load_key, args=(key, True, queue))
            t.daemon = True
            t.start()

        for _ in range(len(keys)):
            bundle, games = queue.get()
            self.bundles.update(bundle)
            self.games.update(games)

        log.info("Updated %d games from %d bundles",
                 len(self.games),
                 len(self.bundles))
        self._merge()
        self._save_data()


    def _save_data(self):
        for obj in ['bundles', 'games']:
            path = osp.join(self.configdir, "%s.json" % obj)
            try:
                with open(path, 'w') as f:
                    json.dump(getattr(self, obj), f,
                              indent=2, separators=(',', ': '), sort_keys=True)
                os.chmod(path, 0o600)
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

        # remove the now redundant "subproducts" list
        del bundle['subproducts']

        # Remove useless fields, that may not be present anyway
        bundle.pop('subscriptions', None)

        # Move 'products' sub-dict to root
        for k, v in bundle['product'].items():
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


    def download(self, name, path=None, bittorrent=False,
                 dtype=None, arch=None, platform=None, serverfile=None,
                 type_pref=".deb", arch_pref="64",
                 retry=True):

        game = self.get_game(name)
        d = self._choose_download(name=name, dtype=dtype, arch=arch,
                                  platform=platform, serverfile=serverfile,
                                  type_pref=type_pref, arch_pref=arch_pref)
        if not d:
            return

        # MD5 sum matches direct download files, not .torrent ones.
        if bittorrent:
            md5 = None
        else:
            md5 = d.get('md5', '').lower() or None

        url = d['url'].get('bittorrent' if bittorrent else 'web','')
        if not url:
            log.error("Selected download has no URL")
            return

        # Check if URL has expired
        try:
            ttl = int(parse_qs(urlsplit(url).query)['ttl'][0])
        except KeyError:
            ttl = 0  # No TTL
        except (IndexError, ValueError) as e:
            ttl = -1  # Invalid TTL
        if ttl and ttl < time.time():
            if not retry:
                raise HumbleBundleError("Game data for '%s' expired %s." %
                                        (name, time.ctime(ttl)))

            log.debug("Game data for '%s' expired %s, will update and retry.",
                      name, time.ctime(ttl))
            self._load_key(self.bundles.get(game.get('bundle', ''),
                                            {}).get('gamekey', ''))
            return self.download(name=name,
                                 path=path,
                                 dtype=dtype,
                                 arch=arch,
                                 platform=platform,
                                 bittorrent=bittorrent,
                                 type_pref=type_pref,
                                 arch_pref=arch_pref,
                                 serverfile=serverfile,
                                 retry=False)

        print("Downloading '%s' [%s]\t%s" % (
            game['human_name'], game['machine_name'], self._download_info(d)))
        try:
            return super(HumbleBundle, self).download(url, path, md5)
        except httpbot.HTTPError as e:
            # Handle Unauthorized/Not Found (most likely outdated download URL)
            if not e.code in (403, 404):
                raise
            raise HumbleBundleError(
                "Download error: %d %s. URL may be outdated, try --update." %
                (e.code, e.reason))

    def _download_basename(self, d):
        basename = osp.basename(urlsplit(d.get('url', {}).get('web', "")).path)
        return basename

    def _download_info(self, d):
        a = "\t(%s-bit)" % d['arch'] if d.get('arch', None) else ""
        return "\t\t%-20s%s\t%8s\t%s" % (d['name'], a, d['human_size'],
                                         self._download_basename(d))


    def _choose_download(self, name, dtype=None, arch=None, platform=None,
                         serverfile=None, type_pref=None, arch_pref=None):

        game = self.get_game(name)
        candidates = []
        finalists = []

        # Eliminate the ones that do not match the explicit request
        for plat in game.get('downloads', []):
            if plat.get('platform', '') == platform:
                for download in plat.get('download_struct', []):
                    if download in candidates:
                        continue
                    if not download.get('url', ''):
                        continue
                    if (serverfile and
                        serverfile.lower() !=
                            self._download_basename(download).lower()):
                        continue
                    if (dtype and
                        dtype.lower() not in download.get('name','').lower()):
                        continue
                    if not download.get('arch', ''):
                        if re.search('(?:32|64)[- ]?bit|i386|x86_64',
                                     download.get('name','')):
                            if '64' in download['name']:
                                download['arch'] = "64"
                            else:
                                download['arch'] = "32"
                    if (arch and
                        download.get('arch', '') and
                        download['arch'] != arch):
                        continue

                    candidates.append(download)

        if len(candidates) == 1:
            return candidates[0]

        if len(candidates) == 0:
            log.error("No valid downloads for game '%s' [%s]\n\t criteria %r",
                      game['human_name'], game['machine_name'],
                      {'dtype':dtype,
                       'arch':arch,
                       'serverfile':serverfile,
                       'platform':platform})
            return

        log.debug("Many download candidates for '%s' [%s]\n\tcriteria %r:\n%s",
                  game['human_name'], game['machine_name'],
                  {'dtype':dtype,
                   'arch':arch,
                   'serverfile':serverfile,
                   'platform':platform},
                  json.dumps(candidates, indent=2))

        # Try type (download name) preference
        if not dtype and type_pref:
            for download in candidates:
                if type_pref.lower() in download.get('name', '').lower():
                    finalists.append(download)

        if len(finalists) == 1:
            return finalists[0]

        # Multiple finalists. Set them as next candidates
        # If no finalists, candidates remain the same
        if len(finalists) > 1:
            candidates = finalists[:]
        finalists = []

        # Try arch preference
        if not arch and arch_pref:
            for download in candidates:
                if download.get('arch', '') and download['arch'] == arch_pref:
                    finalists.append(download)

        if len(finalists) == 1:
            return finalists[0]

        # Try type again, with more restrictive matching
        if dtype:
            for rule in ('starts', 'is'):
                if finalists:
                    candidates = finalists[:]
                    finalists = []
                for download in candidates:
                    name = download.get('name', '').lower()
                    if ((rule == 'is'     and name == dtype.lower()) or
                        (rule == 'starts' and name.startswith(dtype.lower()))):
                        finalists.append(download)
                if len(finalists) == 1:
                    return finalists[0]

        # Give up
        log.error("Too many download candidates for '%s' [%s]."
                  " Improve criteria to narrow it down.%s",
                  game['human_name'], game['machine_name'],
                  "".join(["\n%s" % self._download_info(x)
                           for x in finalists or candidates]))
        #log.debug("\n%s", json.dumps(finalists or candidates, indent=2))
        return


    def install(self, name, method=None):
        # References:
        # Steam: https://developer.valvesoftware.com/wiki/Steam_browser_protocol
        # USC:   https://software-center.ubuntu.com/subscriptions/
        # Mojo:  scripts/mojosetup_mainline.lua

        game = self.get_game(name)
        method = method or game.get('install', "").lower()

        def execute(command, cwd=None):
            return executecmd(shlex.split(command), cwd)

        def executecmd(command, cwd=None):
            try:
                log.debug("Executing: %s", command)
                subprocess.check_call(command, cwd=cwd)
            except (subprocess.CalledProcessError, OSError) as e:
                if getattr(e, 'errno', 0) == 2:  # OSError, No such file or directory
                    log.error("Error installing '%s': %s: %s",
                              name, e.strerror, shlex.split(command)[0])
                else:
                    log.error("Error installing '%s': %s", name, e)

        def download(specs):
            for spec in specs:
                specs[spec] = game.get(spec, specs[spec])
            specs['dtype'] = specs.pop('download', None)
            # make sure cachedir ends with a trailing slash, see HttpBot.download()
            return self.download(name, path=osp.join(self.cachedir, ''), **specs)

        if not method:
            raise HumbleBundleError("No install data for '%s', please check '%s'"
                                    " or use --method" %
                                    (name, self.gamedata))

        elif method == "deb":
            specs = dict(download=None, arch=None, platform="linux",
                         type_pref=".deb", arch_pref="64")
            deb = download(specs)
            if deb:
                execute("sudo dpkg --force-depends --install '%s'" % deb)
                execute("sudo apt-get --yes --fix-broken install")

        elif method == "apt":
            package = game.get("package", name)
            execute('sudo apt-get install --yes "%s"' % package)

        elif method == "steam":
            try:
                execute("steam steam://install/%d" % game['steamid'])
            except KeyError:
                raise HumbleBundleError(
                    "No steamid for steam-installable game '%s'" % name)

        elif method == "mojo":
            specs = dict(download=None, arch=None, platform="linux",
                         type_pref="sh", arch_pref="64")
            installer = download(specs)
            if not installer:
                raise HumbleBundleError(
                    "Could not download installer for game '%s'" % name)

            path = osp.join(osp.expanduser("~/.local/opt"),
                            game.get('mojoname', name.split("_", 1)[0].title()))
            execute("chmod +x '%s'" % installer)
            execute("'%s' -- --destination '%s' --noreadme --noprompt"
                    " --nooptions --i-agree-to-all-licenses" %
                    (installer, path))

        elif method == "air":
            specs = dict(download=None, arch=None, platform="linux",
                         type_pref="air", arch_pref="64")
            installer = download(specs)
            if not installer:
                raise HumbleBundleError(
                    "Could not download installer for game '%s'" % name)

            adobeair = "/usr/bin/Adobe AIR Application Installer"
            if not osp.isfile(adobeair):
                self.install('adobeair')
            execute("'%s' '%s'" % (adobeair, installer))

        elif method == "custom":
            specs = dict(download=None, arch=None, platform="linux",
                         type_pref=None, arch_pref="64")
            archive = download(specs)
            if not archive:
                raise HumbleBundleError(
                    "Could not download installer for game '%s'" % name)

            hookdir = osp.join(self.datadir, "hooks", name)
            hookfile = osp.join(hookdir, "%s.install.hook" % name)
            basename = game.get('basename', name.split("_", 1)[0])
            # FIXME: Make sure basename is valid: single word, no punc, etc
            installdir = osp.join(osp.expanduser("~"), '.local', 'opt',
                                  game.get('dirname', basename))
            executecmd([hookfile,
                        basename,
                        installdir,
                        osp.abspath(archive),
                        name,
                        game.get('human_name', ''),
                        game.get('icon', '')],
                       cwd=hookdir)

        else:
            log.error("Invalid install method for '%s': '%s'", name, method)


    def uninstall(self, name, method=None):
        game = self.get_game(name)
        method = method or game.get('install', "").lower()
        command = ""
        installdir = ""
        popenargs = {}

        if not method:
            raise HumbleBundleError("No install data for '%s',"
                                    " please check '%s'" %
                                    (name, self.gamedata))

        elif method in ["deb", "apt", "air"]:
            package = game.get("package", name)
            command = 'sudo apt-get remove --auto-remove --yes "%s"' % package

        elif method == "steam":
            try:
                command = "steam steam://uninstall/%d" % game['steamid']
            except KeyError:
                raise HumbleBundleError(
                    "No steamid for steam-installable game '%s'" % name)

        elif method == "mojo":
            mojoname = game.get('mojoname', name.split("_", 1)[0].title())
            installdir = osp.join(osp.expanduser("~"), '.local', 'opt', mojoname)
            uninstaller = osp.join(installdir, "uninstall-%s.sh" % mojoname)
            command = "'%s' --noprompt" % uninstaller
            # "Disable" install dir removal as user can cancel uninstall in GUI
            installdir = ""

        elif method == "custom":
            basename = game.get('basename', name.split("_", 1)[0])
            uninstaller = osp.join(osp.expanduser("~"), '.local', 'opt',
                                  game.get('dirname', basename), "uninstall")
            if not osp.isfile(uninstaller):
                hookdir = osp.join(self.datadir, "hooks", name)
                uninstaller = osp.join(hookdir, "%s.uninstall.hook" % name)
                popenargs['cwd'] = hookdir
            command = "'%s'" % uninstaller

        else:
            log.error("Invalid uninstall method for '%s': '%s'", name, method)

        if not command:
            return

        try:
            log.debug("Executing: %s", command)
            subprocess.check_call(shlex.split(command), **popenargs)
            if installdir:
                log.debug("Removing '%s'", installdir)
                shutil.rmtree(installdir, ignore_errors=True)
        except (subprocess.CalledProcessError, OSError) as e:
            if getattr(e, 'errno', 0) == 2:  # OSError, No such file or directory
                log.error("Error uninstalling '%s': %s: %s",
                          name, e.strerror, shlex.split(command)[0])
            else:
                log.error("Error uninstalling '%s': %s", name, e)


    def get_game(self, name):
        # Get game, if exists
        log.info("Retrieving game info for '%s'", name)
        try:
            return self.games[name]
        except KeyError:
            raise HumbleBundleError("Game not found: %s" % name)


    def get_bundle(self, name):
        # Get bundle, if exists
        log.info("Retrieving bundle info for '%s'", name)
        try:
            return self.bundles[name]
        except KeyError:
            raise HumbleBundleError("Bundle not found: %s" % name)


    def get(self, url, postdata=None):

        def urlabspath(url):
            return urlsplit(urljoin('/', url)).path.lower()

        def save_cookies(res, force=False):
            if force or 'Set-Cookie' in res.info():
                log.debug("Saving cookies to '%s'", self.cookiejar.filename)
                try:
                    self.cookiejar.save()
                    os.chmod(self.cookiejar.filename, 0o600)
                except IOError as e:
                    log.error("Error saving cookies: %s", e)

        requested_url = urlabspath(url)
        current_url = ""
        try:
            res = super(HumbleBundle, self).get(url, postdata)
            save_cookies(res)
            # Was it successful? That is, not redirected TO an authorization
            # page that requires special handling.
            current_url = urlabspath(res.geturl())
            if (current_url == requested_url or
                current_url not in self.auth_urls):
                return res
        except httpbot.HTTPError as e:
            # Unauthorized (requires login) or something else?
            if not e.code == 401:
                raise

        # Humble Guard (Browser Verification Code sent via email)
        if current_url == "/user/humbleguard":
            raise HumbleBundleError(
                    "Browser verification code required."
                    " Check your email and retry with --code")

        # Login form
        if not (self.username and self.password):
            raise HumbleBundleError(
                "Username or password are blank. "
                "Set with --username and --password and try again")

        log.info("Authenticating at '%s/processlogin'", self.url)

        try:
            # Could also get the token from res.headers.get("Set-Cookie")
            token = re.search(r"\s+value=['\"]([^'\"]+)['\"]",
                              re.search(r"(<input\s+[^>]*\s+name\s*=\s*"
                                        "['\"]_le_csrf_token['\"][^>]*>)",
                                        res.read()).groups()[0]).groups()[0]
        except Exception as e:
            raise HumbleBundleError("Could not retrieve token: %r", e)

        try:
            res = super(HumbleBundle, self).get("/processlogin",
                                                {'goto'    : url,
                                                 'username': self.username,
                                                 'password': self.password,
                                                 '_le_csrf_token': token})
            save_cookies(res, force=True)

        except httpbot.HTTPError as e:
            # 'Bad Request', 'Unauthorized' or 'Forbidden' are expected
            # in case of wrong passwords
            if e.code in [400, 401, 403]:
                raise HumbleBundleError(
                    "Could not log in. Either username/password are"
                    " not correct, or a ReCaptcha validation is required."
                    " Log in using a real browser, inspect the cookies created"
                    " and provide the value of _simpleauth_sess with --auth")
            raise

        # Was it already redirected to the page requested?
        if requested_url == urlabspath(res.geturl()):
            return res

        return self.get(url, postdata)



def main(argv=None):
    args, parser = parseargs(argv)
    logging.basicConfig(level=getattr(logging, args.loglevel.upper(), None),
                        format='%(asctime)s\t%(levelname)-8s\t%(message)s')
    log.debug(args)
    config = read_config(args)

    username = args.username or config['username'] or HB_USERNAME
    password = args.password or config['password'] or HB_PASSWORD

    hb = HumbleBundle(username, password,
                      args.auth, args.code,
                      debug=args.debug)

    if args.update:
        hb.update()

    if args.clear:
        clear_auth()

    if args.list is not None:
        games = hb.games
        if isinstance(args.list, str):
            games = {k: v for k, v in hb.games.items() if re.search(args.list, k)}

        if args.platform is not None:
            hasPlatform = lambda v, p: any(_ for _ in v['downloads'] if _['platform'] == p)
            games = {k: v for k, v in games.items() if hasPlatform(v, args.platform)}

        for key in sorted(games.keys()):
            print("%s" % key)

    elif args.list_human is not None:
        games = hb.games
        if isinstance(args.list, str):
            games = {k: v for k, v in hb.games.items() if re.search(args.list, k)}

        if args.platform is not None:
            has_platform = lambda v, p: any(_ for _ in v['downloads'] if _['platform'] == p)
            games = {k: v for k, v in games.items() if has_platform(v, args.platform)}

        for key in sorted(games.keys()):
            print('%s' % hb.games[key]['human_name'])

    elif args.show:
        def print_key(key, alias=None, obj=None):
            print("%-10s: %s" % (alias or key,
                                 getattr(obj or game, 'get')(key.lower(), '')))

        game = hb.get_game(args.show)
        if args.json:
            print(json.dumps(game, indent=2, separators=(',', ': '),
                             sort_keys=True))
            return
        print_key('machine_name', 'Game')
        print_key('human_name', 'Name')
        print_key('human_name', 'Developer', obj=game.get('payee',{}))
        print_key('URL')
        print_key('', 'Bundles')
        for bundle in hb.bundles.itervalues():
            if game.get('machine_name', '') in bundle.get('games', []):
                print("\t%s [%s]" % (bundle['human_name'],
                                     bundle['machine_name']))
        print_key('', 'Downloads')
        platform_prev = None
        for download in sorted(game.get('downloads', []),
                               key=lambda k: k['platform']):
            platform = download.get('platform', '')
            if platform_prev != platform:
                print("\t%s" % platform)
                platform_prev = platform
            for d in download.get('download_struct', []):
                if 'url' not in d:
                    continue
                print(hb._download_info(d))

    elif args.show_bundle:
        def print_key(key, alias=None, obj=None):
            print("%-10s: %s" % (alias or key,
                                 getattr(obj or bundle, 'get')(key.lower(), '')))

        bundle = hb.get_bundle(args.show_bundle)
        if args.json:
            print(json.dumps(bundle, indent=2, separators=(',', ': '),
                             sort_keys=True))
            return
        print_key('machine_name', 'Bundle')
        print_key('human_name', 'Name')
        print_key('Category')
        print_key('familyamount', 'Price US$')
        print_key('', 'Games')
        for name in sorted(bundle['games']):
            game = hb.get_game(name)
            print("\t%s\t[%s]" % (game['human_name'], game['machine_name']))

    elif args.list_bundles:
        for bundle in sorted(hb.bundles.items()):
            print ("%s\t%s" % (bundle[1]['machine_name'],
                               bundle[1]['human_name'])).encode('utf-8')

    elif args.download:
        if not hb.download(name=args.download,
                           path=args.path,
                           dtype=args.type,
                           arch=args.arch,
                           bittorrent=args.bittorrent,
                           platform=args.platform,
                           serverfile=args.serverfile):
            return 1

    elif args.install:
        hb.install(args.install, args.method)

    elif args.uninstall:
        hb.uninstall(args.uninstall, args.method)

    else:
        if not (args.update or args.clear):
            parser.print_usage()


def clear_auth(appname=None, authfile=None, cookiejar=None):
    '''Clear all authentication data and delete related files'''

    appname   = appname   or APPNAME
    authfile  = authfile  or AUTHFILE
    cookiejar = cookiejar or COOKIEJAR

    authfiles = [cookiejar]

    log.info("Clearing all authentication data")

    if keyring:
        try:
            log.debug("Removing credentials from keyring")
            keyring.delete_password(appname, appname)
        except AttributeError as e:
            log.warning("Error removing keyring credentials. Outdated library? (%s)", e)
    else:
        authfiles.append(authfile)

    for auth in authfiles:
        try:
            log.debug("Deleting '%s'", auth)
            os.remove(auth)
        except OSError as e:
            log.debug(e)

    log.info("Finished clearing authentication")


def read_config(args, appname=None, authfile=None):
    appname   = appname   or APPNAME
    authfile  = authfile  or AUTHFILE

    username = ""
    password = ""

    # read
    if keyring:
        log.debug("Reading credentials from keyring")
        try:
            username, password = (
                keyring.get_password(appname, appname).split('\n') +
                ['\n']
            )[:2]
        except AttributeError as e:
            # Check for old keyring format and migrate before throwing warning
            data = keyring.get_password(appname, '')
            if data:
                log.info("Migrating credentials to new keyring format")
                keyring.set_password(appname, appname, data)
                try:
                    keyring.delete_password(appname, '')
                except AttributeError as e:
                    log.warning("Error deleting old keyring. Outdated library? (%s)", e)
            else:
                log.warning("Credentials not found in keyring. First time usage?")
        except IOError as e:  # keyring sometimes raises this
            log.error(e)
    else:
        log.debug("Reading credentials from '%s'" % authfile)
        try:
            with open(authfile, 'r') as fd:
                username, password = (fd.read().splitlines() + ['\n'])[:2]
        except IOError as e:
            if e.errno == 2:  # No such file or directory
                log.warning("Credentials file not found. First time usage?")
            else:
                log.error(e)

    # save
    if args.username or args.password:
        log.info("Saving credentials")
        if keyring:
            keyring.set_password(appname, appname,
                                 '%s\n%s' % (args.username or username,
                                             args.password or password,))
        else:
            try:
                with open(authfile, 'w') as fd:
                    fd.write("%s\n%s\n" % (args.username or username,
                                           args.password or password,))
                os.chmod(authfile, 0o600)
            except IOError as e:
                log.error(e)

    return dict(username=username,
                password=password,)


def parseargs(argv=None):
    parser = argparse.ArgumentParser(
        description="Humble Bundle Manager",)

    parser.add_argument('-v', '--verbose', dest='loglevel',
                        action="store_const",
                        const="info", default="warn",
                        help="Output informative messages")
    parser.add_argument('-D', '--debug', dest='loglevel',
                        action="store_const", const="debug",
                        help="Output debug information")
    parser.add_argument('-u', '--update', dest='update',
                        default=False, action="store_true",
                        help="Fetch all games and bundles data from the server,"
                            " rebuilding the cache")

    group = parser.add_argument_group("Authentication Options")
    group.add_argument('-U', '--username', dest='username',
                        help="Account login, the user's email")
    group.add_argument('-P', '--password', dest='password',
                        help="Account password")
    group.add_argument('-A', '--auth', dest='auth',
                        help="Account _simpleauth_sess cookie value")
    group.add_argument('-c', '--code',
                       help="Browser verification code sent by email")
    group.add_argument('-C', '--clear',
                       default=False, action="store_true",
                       help="Clear all authentication data, deleting related files")

    group = parser.add_argument_group("Commands")
    group.add_argument('-l', '--list', dest='list',
                        const=True, nargs='?', metavar="REGEX",
                        help="List all available Games (Products),"
                            " including Soundtracks and eBooks,"
                            " optionally filtered by REGEX. If --platform is given,"
                            " filter by platform also.")
    group.add_argument('--list-human', dest='list_human', default=False, action='store_true', help='List human names for games')
    group.add_argument('-L', '--list-bundles', dest='list_bundles',
                        default=False, action="store_true",
                        help="List all available Bundles (Purchases), "
                            "including Store Front (single product) purchases")
    group.add_argument('-s', '--show', dest='show', metavar="GAME",
                        help="Show all info about selected game")
    group.add_argument('-S', '--show-bundle', dest='show_bundle',
                        metavar="BUNDLE",
                        help="Show all info about selected bundle")
    group.add_argument('-d', '--download', dest='download', metavar="GAME",
                        help="Download the selected game")
    group.add_argument('-i', '--install', dest='install', metavar="GAME",
                        help="Install selected game")
    group.add_argument('-I', '--uninstall', dest='uninstall', metavar="GAME",
                        help="Uninstall selected game")

    group = parser.add_argument_group("Show Options")
    group.add_argument('-j', '--json', dest='json',
                        default=False, action="store_true",
                        help="Output --show/--show-bundle in machine-readable,"
                            " JSON format")

    group = parser.add_argument_group("Download Options")
    group.add_argument('-t', '--type', dest='type', metavar="NAME",
                        help="Type (name) of the download,"
                            " for example '.deb', 'mojo', 'flash', etc")
    group.add_argument('-a', '--arch', dest='arch', choices=['32', '64'],
                        help="Download architecture: 32-bit (also known as i386)"
                            " or 64-bit (amd64, x86_64, etc)")
    default = "linux"
    group.add_argument('-p', '--platform', dest='platform',
                        default=default,
                        choices=['windows', 'mac', 'linux', 'android', 'audio',
                                 'ebook', 'comedy', 'video'],
                        help="Download platform. Default is '%s'" % default)
    group.add_argument('-F', '--server-file', dest='serverfile', metavar="FILE",
                        help="Basename of the server file to download."
                            " Useful when no combination of --type, --arch"
                            " and --platform is enough to narrow down choices"
                            " to a single download.")
    group.add_argument('-b', '--bittorrent', dest='bittorrent',
                        default=False, action="store_true",
                        help="Download bittorrent file instead of direct download")
    group.add_argument('-f', '--path', dest='path',
                        help="Path to download. If PATH is a directory,"
                            " default download basename will be used."
                            " If omitted, download to current directory.")

    group = parser.add_argument_group("Install Options")
    group.add_argument('-m', '--method', dest='method',
                        choices=['custom', 'deb', 'apt', 'mojo', 'air', 'steam'],
                        help="Use this method instead of the default"
                            " for (un-)installing a game")

    args = parser.parse_args(argv)
    args.debug = args.loglevel=='debug'
    return args, parser


def cli():
    global APPNAME, CONFIGDIR, CACHEDIR, AUTHFILE, COOKIEJAR

    APPNAME   = osp.basename(osp.splitext(__file__)[0])
    CONFIGDIR = xdg.save_config_path(APPNAME)  # creates the dir
    CACHEDIR  = osp.join(xdg.xdg_cache_home, APPNAME)
    AUTHFILE  = osp.join(CONFIGDIR, "login.conf")
    COOKIEJAR = osp.join(CONFIGDIR, "cookies.txt")
    # No changes in DATADIR

    try:
        sys.exit(main())

    except KeyboardInterrupt:
        pass
    except HumbleBundleError as e:
        log.critical(e)
        sys.exit(1)
    except Exception as e:
        log.critical(e, exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
