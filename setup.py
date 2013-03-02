#!/usr/bin/env python
from setuptools import find_packages, setup

import re
versionLine = open("txscrypt/_version.py", "rt").read()
match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", versionLine, re.M)
versionString = match.group(1)

setup(name='txscrypt',
      version=versionString,
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
