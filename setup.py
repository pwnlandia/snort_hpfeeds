#!/usr/bin/env python

from distutils.core import setup

setup(
	name='snort_hpfeeds',
	version='1.0',
	description='snort_hpfeeds',
	url='https://github.com/Pwnlandia/snort_hpfeeds',
	license='GPLv3',
	package_dir = {'': 'src'},
	py_modules = ['snort_hpfeeds'],
	scripts=['src/snort_hpfeeds.py'],
	install_requires=[
		"docopt",
		"pyparsing",
		"requests",
		"sqlalchemy",
		"watchdog",
		"hpfeeds==1.0"		
	],
	dependency_links=[
		"git+https://github.com/Pwnlandia/hpfeeds.git#egg=hpfeeds-1.0"
	]
)
