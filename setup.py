import os
from setuptools import setup

# Any code, applications, scripts, templates, proofs of concept, documentation
# and other items provided by OBLCC under this SOW are 'OBLCC Content,'' as defined
# in the Agreement, and are provided for illustration purposes only. All such
# OBLCC Content is provided solely at the option of OBLCC, and is subject to the
# terms of the Addendum and the Agreement. Customer is solely responsible for
# using, deploying, testing, and supporting any code and applications provided
# by OBLCC under this SOW.
#
# (c) 2016 Oblivion Cloud Control
# Author: S. Huizinga <steyn@oblcc.com>


def read(filename):
    with open(os.path.join(os.path.dirname(__file__), filename)) as f:
        long_description = f.read()
    return long_description

setup(
    name='opvault',
    version='0.2.3',
    author='Steyn Huizinga',
    author_email='steyn@oblcc.com',
    description='Python library to access 1Password OPVault stores',
    license='GPLv3',
    keywords='opvault',
    url='https://github.com/OblivionCloudControl/opvault',
    provides=['opvault'],
    packages=['opvault'],
    install_requires=['pycrypto'],
    long_description=read('README'),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: Utilities',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Topic :: Security :: Cryptography',
    ],
)
