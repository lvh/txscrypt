#!/usr/bin/env python
from setuptools import find_packages, setup

setup(name='txscrypt',
      version='20121015',
      description='Twisted wrapper for scrypt',
      url='https://github.com/lvh/txscrypt',

      author='Laurens Van Houtven',
      author_email='_@lvh.cc',

      packages=find_packages(),

      install_requires=['twisted', 'scrypt'],

      license='ISC',
      classifiers=[
        "Development Status :: 3 - Alpha",
        "Framework :: Twisted",
        "License :: OSI Approved :: ISC License (ISCL)",
        ])

