#!/usr/bin/env python

from distutils.core import setup

setup(
	name='snort_hpfeeds',
	version='1.0',
	description='snort_hpfeeds',
	author='Jason Trost, Sergio Pulgarin',
	author_email='jason.trost@threatstream, sergio@threatstream.com',
	url='https://github.com/threatstream/snort_hpfeeds',
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
		"git+https://github.com/threatstream/hpfeeds.git#egg=hpfeeds-1.0"
	]
)
