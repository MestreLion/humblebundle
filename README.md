Humble Bundle Manager
=====================

Python library and command line tool to manage Humble Bundle games

List your bundles and games, Show their info, Download, Install and Uninstall them!
It's like `apt-get` for Humble Bundle :)


---


Requirements
------------

- **Python** (tested in Python 2.7, can easily be ported to Python 3)
- **Bash** (for the install hooks. Some may require version 4+)

Python and Bash are already installed by default in virtually all GNU/Linux distros.


Dependencies
------------

- [lxml](http://lxml.de)
- [Progressbar](https://code.google.com/p/python-progressbar)
- [Python Keyring Lib](https://github.com/jaraco/keyring)
- [PyXDG](https://freedesktop.org/wiki/Software/pyxdg/)

The above can be installed in any modern Debian-like distros (like Ubuntu/Mint) with:

	sudo apt-get install python-{lxml,progressbar,keyring,xdg}


Install
-------

Clone the repository and install as an editable package:

	cd ~/some/dir
	git clone https://github.com/MestreLion/humblebundle.git
	pip install -e humblebundle

This installs both the main script `humblebundle` and the library `humblebundle`.

Uninstall
---------

Remove authentication files:

	humblebundle --clear

Uninstall and delete the directory:

	pip uninstall humblebundle-manager
	rm -rf ~/some/dir/humblebundle

There may be additional files in the config folder, such as `bundles.json` and
`games.json`, that are downloaded while using the app, as well as downloaded
files in the cache folder. The default config folder on Unix-like systems is
`~/.config/humblebundle`, and the default cache folder is
`~/.cache/humblebundle`

---


Usage as a command-line tool
----------------------------

Adapted from `--help`:

	Usage: humblebundle [general options] [command] [command options]

	Optional arguments:
	  -h|--help
		                show this help message and exit
	  -g|--loglevel {debug,info,warn,error,critical}
		                set logging level, default is 'warn'
	  -D|--debug
		                alias for --loglevel debug

	  -u|--update
		                Fetch all games and bundles data from the server,
		                rebuilding the cache

	Login options:
	  -U|--username USERNAME
		                Account login, the user's email
	  -P|--password PASSWORD
		                Account password
	  -A|--auth AUTH
		                Account _simpleauth_sess cookie


	Commands:
	  -l|--list [REGEX]
		                List all available Games (Products), including
		                Soundtracks and eBooks, optionally filtering
		                by REGEX (Regular Expression)
	  -L|--list-bundles
		                List all available Bundles (Purchases), including
		                Store Front (single product) purchases

	  -s|--show GAME
		                Show all info about selected game
	  -S|--show-bundle BUNDLE
		                Show all info about selected bundle

	  -d|--download GAME
		                Name of the game to download. See --list

	  -i|--install GAME
		                Install selected game
	  -I|--uninstall GAME
		                Uninstall selected game


	Download options:
	  -t|--type NAME
		                Type (name) of the download, for example '.deb',
		                'mojo', 'flash', etc
	  -a|--arch {32,64}
		                Download architecture: 32-bit (also known as i386) or
		                64-bit (amd64, x86_64, etc)
	  -p|--platform {windows,mac,linux,android,audio,ebook,comedy}
		                Download platform. Default is 'linux'
	  -F|--server-file FILE
		                Basename of the server file to download. Useful when
		                no combination of --type, --arch and --platform is
		                enough to narrow down choices to a single download.
	  -b|--bittorrent
		                Download bittorrent file instead of direct download
	  -f|--path PATH
		                Path to download. If PATH is a directory, default
		                download basename will be used. By if omitted,
		                download to current directory.

	Show options:
	  -j|--json
		                Output --show/--show-bundle in machine-readable, JSON
		                format

	Install options:
	  -m|--method {custom,deb,apt,mojo,air,steam}
		                Use this method instead of the default for
		                (un-)installing a game


Command line interface is heavily inspired on `apt` workflow:

- List games and bundles to get their humble bundle `id`

- Show info on a particular game or bundle (similar to `apt-cache show`)

- Download a game archive (similar to `apt-get download`, and as such not needed for install)

- Install and Uninstall a game (as easy as `apt-get install`)


Examples and sample output:
---------------------------

Authenticating (only needed once, it stores credentials in keyring):

	$ humblebundle --username 'user@gmail.com' --password '1234' --update --list


Show bundle and game info:

	$ humblebundle --show-bundle androidbundle5

	Bundle    : androidbundle5
	Name      : Humble Bundle with Android 5
	Category  : bundle
	Price US$ :
	Games     :
		Beat Hazard Ultra	[beathazardultra]
		Beat Hazard Ultra	[beathazardultra_android]
		Beat Hazard Ultra	[beathazardultra_soundtrack]
		Crayon Physics Deluxe	[crayonphysicsdeluxe_android_pc_soundtrack]
		Dungeon Defenders + All DLC	[dungeondefenders_dlc_android_pc]
		Dynamite Jack	[dynamitejack_android_pc]
		NightSky	[nightsky_android_pc]
		NightSky	[nightsky_soundtrack]
		Solar 2	[solar_android_pc]
		Splice	[splice]
		Splice	[splice_android]
		Splice Soundtrack	[splice_soundtrack]
		Super Hexagon	[superhexagon_android_pc]
		Super Hexagon	[superhexagon_asm]
		Superbrothers: Sword & Sworcery EP	[swordandsworcery_android_pc_soundtrack]


	$ humblebundle --list solar

	solar_android_pc
	solarflux
	solarflux_android


	$ humblebundle --show solar_android_pc

	Game      : solar_android_pc
	Name      : Solar 2
	Developer : Murudai
	URL       : http://murudai.com
	Bundles   :
		Humble Bundle with Android 5 [androidbundle5]
		Humble Bundle: PC and Android 8 [androidbundle8]
	Downloads :
		android
			Download            	 45.3 MB	Solar2_Android_1.13_1388267491.apk
		audio
			MP3                 	 53.5 MB	solar2_ost_mp3_1409159048.zip
			FLAC                	179.9 MB	solar_2_ost_flac_1409159048.zip
		linux
			.deb                	101.3 MB	solar2_1.10_i386_1409159048.deb
			.tar.gz             	101.3 MB	solar2-linux-1.10_1409159048.tar.gz
		mac
			Download            	 69.5 MB	solar2-mac-1.10_1409159048.dmg
		windows
			Download            	 41.2 MB	solar2-windows-1.10_1409159048.exe

Download a file:

	$ humblebundle --download solar_android_pc --platform audio --type mp3

	Downloading 'Solar 2' [solar_android_pc] 'MP3' 53.5 MB solar2_ost_mp3_1409159048.zip
	  27% of 53.5 MiB |................                       |   1.23 M/s ETA:  00:00:3


Install a game (may require an entry in `gamedata.json` or manual options):

	$ humblebundle --install dontmove

	Downloading "Don't Move" [dontmove]  (64-bit)  4.7 MB  DontMove_v1-3_Linux-64.tar
	Installing Don't Move
	Done!


Usage as a library
------------------

    import humblebundle

    hb = HumbleBundle('user@gmail.com', '1234')

    hb.update()

    for name in hb.games:
        game = hb.get_game(name)
          # or simply hb.games[name] - It's a dictonary! (for now)
        print game['human_name']

        # Blame Humble Bundle for their weird dictionary structure, not me!
        for platforms in game.get('downloads', []):
            for download in platforms.get('download_struct', []):
                url = download.get('url', {}).get('web', '')
                if url:
                   print url


    filename = hb.download('dontmove', platform='linux', arch=64)

---


Building the `humblebundle-manager` package
-------------------------------------------

Due to an earlier package called `humblebundle`, the package is called `humblebundle-manager`. To build the package:

    pip install build twine
    python -m build
    twine check dist/*

Contributing
------------

Patches are welcome! Fork, hack, request pull! Here is my current to-do list:

- **Better documentation**: Improve this `README`, document `installers/` usage, custom `hooks/` interface, explain how credentials are used and stored, `gamedata.json` format and usage, config dir structure. And, most important, describe the install mechanics in more detail.

- **Classes**: convert the games and bundles dictionaries to classes with attributes and methods. `HumbleBundle.get_game()` would return a `Game` instance, methods `.install()`, `.download()` etc would be there and not on the "main" HumbleBundle class.

If you find a bug or have any enhancement request, please to open a [new issue](https://github.com/MestreLion/humblebundle/issues/new)


Written by
----------

Rodrigo Silva (MestreLion) <linux@rodrigosilva.com>

Licenses and Copyright
----------------------

Copyright (C) 2014 Rodrigo Silva (MestreLion) <linux@rodrigosilva.com>.

License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.

This is free software: you are free to change and redistribute it.

There is NO WARRANTY, to the extent permitted by law.
