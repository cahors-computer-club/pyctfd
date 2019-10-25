#!/usr/bin/env python

from distutils.core import setup

setup(
      name='pyctfd',
      version='0.1',
      description='CTFd API python wrapper',
      author='Quentin POIRIER',
      author_email='quentin.poirier@opus-solutions.eu',
      url='https://github.com/swagcurity/pyctfd',
      packages=['pyctfd'],
      scripts=["bin/ctfd-upsert-challenge", "bin/ctfd-setup"]
)