#!/usr/bin/env python3

from distutils.core import setup

setup(name='ImmutableWeb',
      version='0.1',
      description='Python modules for creating immutable web streams',
      long_description=open('README.md').read(),
      author='Robert Kaye',
      author_email='mayhem@gmail.com',
      url='https://github.com/immutableweb/immutableweb-core',
      packages=['immutableweb'],
      scripts=['bin/iw']
     )
