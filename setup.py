import os
from setuptools import setup

# Any code, applications, scripts, templates, proofs of concept, documentation
# and other items provided by OBLCC under this SOW are 'OBLCC Content' as
# defined in the Agreement, and are provided for illustration purposes only.
# All such OBLCC Content is provided solely at the option of OBLCC, and is
# subject to the terms of the Addendum and the Agreement. Customer is solely
# responsible for using, deploying, testing, and supporting any code and
# applications provided by OBLCC under this SOW.
#
# (c) 2018 Oblivion Cloud Control
# Author: S. Huizinga <steyn@oblcc.com>


def read(filename):
    with open(os.path.join(os.path.dirname(__file__), filename)) as file_descr:
        long_description = file_descr.read()
    return long_description


VERSION = os.environ['CI_COMMIT_TAG'] if 'CI_COMMIT_TAG' in os.environ \
    else os.environ['CI_COMMIT_SHA']

setup(
    name='opvault',
    version=VERSION,
    author='Steyn Huizinga',
    author_email='steyn@oblcc.com',
    description='Python library to access 1Password OPVault stores',
    license='GPLv3',
    keywords='opvault',
    url='https://github.com/OblivionCloudControl/opvault',
    provides=['opvault'],
    packages=['opvault'],
    install_requires=['pycryptodome'],
    long_description=read('README'),
    entry_points={
        'console_scripts': [
            'opvault-cli = opvault.cli:main',
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: Utilities',
        ('License :: OSI Approved :: GNU General Public License v3'
         ' or later (GPLv3+)'),
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
