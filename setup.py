import sys

from distutils.core import setup
from setuptools import find_packages

install_requires = [
    'lxml',
    'progressbar',
    'keyring',
    'pyxdg',
]

if sys.platform.startswith('linux'):
    install_requires += [
        'dbus-python',   # requires libdbus-glib-1-dev
        'secretstorage',
    ]

setup(
    name='humblebundle',
    version='0.0.0',
    url='https://github.com/MestreLion/humblebundle',
    packages=find_packages(exclude=['tests']),
    setup_requires=['setuptools-git'],
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'humblebundle = humblebundle:cli',
        ],
    },
)
