# coding:utf-8

import sys
import os
from setuptools import setup

py_version = sys.version_info[:2]
if py_version < (2, 4):
    print("ERROR: this package requires Python 2.4 or later!")
    sys.exit(1)
version = "0.0.1"


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as f:
        return f.read()


setup(
    name="py_snmp",
    version=version,
    author="neohu",
    author_email="9656951@qq.com",
    description=("This is python snmp", ),
    license="BSD",
    keywords="snmp",
    url="http://ip8.me:8888/#/",
    packages=['py_snmp'],
    install_requires=[
    ],
    long_description=read('README.md'),
    classifiers=[
    ],
    zip_safe=False
)