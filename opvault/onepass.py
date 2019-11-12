# -*- coding: utf-8 -*-
"""opvault library"""
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
# Author: S. Huizinga <steyn@oblcc.com>
#
# See https://support.1password.com/opvault-design/ for OPVault
# Design documentation
# See https://cache.agilebits.com/security-kb/ for sample data
# Inspired by https://github.com/sethvoltz/one_pass


from __future__ import print_function

import base64
import glob
import hashlib
import hmac
import json
import os
import platform
import struct
from collections import defaultdict

from Crypto.Cipher import AES

from .exceptions import OpvaultException


class OnePass():
    # pylint: disable=R0902
    """Opvault class"""

    def __init__(self, path=None, profile='default'):
        self._path = path
        if not self._path:
            home_dir = os.getenv('HOME')
            self._path = '{0}/1Password.opvault'.format(home_dir)

        self._profile = profile
        self._profile_path = '{0}/{1}/profile.js'.format(
            self._path, self._profile)

        self._master_key = self._master_mac_key = None
        self._overview_key = self._overview_mac_key = None

        self._items = None
        self._item_index = defaultdict(list)

        self._validate_vault()
        self._validate_profile()

    def get_items(self):
        """Get all items from index"""
        return self._item_index

    def __del__(self):
        self.lock()

    def _validate_vault(self):
        if not os.path.isdir(self._path) and not os.path.islink(self._path):
            except_msg = 'Vault not found in {0}'.format(self._path)
            raise OpvaultException('VaultNotFound', except_msg)

        if not os.access(self._path, os.R_OK):
            except_msg = 'Vault not readable {0}'.format(self._path)
            raise OpvaultException('VaultNotFound', except_msg)

        return True

    def _validate_profile(self):
        if not os.path.isfile(self._profile_path):
            except_msg = 'Profile not readable {0}'.format(self._profile_path)
            raise OpvaultException('ProfileNotFound', except_msg)

        try:
            with open(self._profile_path, 'r') as profile_file:
                profile_content = profile_file.read().strip()
        except (IOError, AttributeError):
            except_msg = 'Cannot open profile file {0}'.format(
                self._profile_path)
            raise OpvaultException('ProfileNotFound', except_msg)

        if not profile_content.startswith('var profile=') or \
                not profile_content.endswith(';'):
            except_msg = 'Invalid syntax in {0}'.format(self._profile_path)
            raise OpvaultException('ProfileNotFound', except_msg)

        try:
            self._profile_json = json.loads(profile_content[12:-1])
        except ValueError as profile_error:
            except_msg = 'Cannot parse profile {0}'.format(str(profile_error))
            raise OpvaultException('ProfileNotFound', except_msg)

        return True

    @staticmethod
    def is_python31_or_newer():
        """Check if python version >= 3.1"""
        major_str, minor_str, _patch_str = platform.python_version_tuple()
        major = int(major_str)
        minor = int(minor_str)
        return bool((major == 3 and minor > 1) or major > 3)

    def decode_function(self, *args, **kwargs):
        """Decode b64 encoded data"""
        if self.is_python31_or_newer():
            # pylint: disable=E1101
            return base64.decodebytes(*args, **kwargs)
        # pylint: disable=W1505
        return base64.decodestring(*args, **kwargs)

    def unlock(self, master_password):
        """Unlock the opvault vault with password"""
        salt = bytes(self.decode_function(self._profile_json['salt'].encode()))
        iterations = self._profile_json['iterations']

        key, mac_key = self._derive_keys(master_password.encode(),
                                         salt, iterations)

        try:
            self._master_key, self._master_mac_key = self.master_keys(
                key, mac_key)
            self._overview_key, self._overview_mac_key = self.overview_keys(
                key, mac_key)
        except OpvaultException as opvault_exception:
            except_msg = 'Incorrect password: "{0}"'.format(
                str(opvault_exception))
            raise OpvaultException('DecryptError', except_msg)

        return True

    def lock(self):
        """Lock the vault by resetting master key information"""
        self._master_key = self._master_mac_key = None

        return True

    def is_unlocked(self):
        """Is master password information present"""
        return bool(self._master_key and self._overview_key)

    @staticmethod
    def _derive_keys(master_password, salt, iterations):
        derived_key = hashlib.pbkdf2_hmac(
            'sha512', master_password, salt, iterations)
        key = derived_key[:32]
        hmac_key = derived_key[32:64]

        return key, hmac_key

    def master_keys(self, derived_key, derived_mac_key):
        """Get the master keys from vault"""
        encrypted = self.decode_function(
            self._profile_json['masterKey'].encode())

        return self.decrypt_keys(encrypted, derived_key, derived_mac_key)

    def overview_keys(self, derived_key, derived_mac_key):
        """List all keys"""
        encrypted = self.decode_function(
            self._profile_json['overviewKey'].encode())

        return self.decrypt_keys(encrypted, derived_key, derived_mac_key)

    def decrypt_keys(self, encrypted_key, derived_key, derived_mac_key):
        """Decrypt all encrypted keys"""
        key_base = self.decrypt_opdata(
            encrypted_key, derived_key, derived_mac_key)

        keys = hashlib.sha512(bytes(key_base))
        digest = keys.digest()

        key_from_digest = digest[:32]
        hmac_from_digest = digest[32:64]

        return key_from_digest, hmac_from_digest

    def decrypt_opdata(self, cipher_text, cipher_key, cipher_mac_key):
        """Decrypt opvault data"""
        key_data = cipher_text[:-32]
        mac_data = cipher_text[-32:]

        self.check_hmac(key_data, cipher_mac_key, mac_data)

        plaintext = self.decrypt_data(
            cipher_key, key_data[16:32], key_data[32:])
        plaintext_size = int(struct.unpack('Q', key_data[8:16])[0])

        plaintext_start = plaintext_size*-1
        opdata = plaintext[plaintext_start:]

        return opdata

    @staticmethod
    def check_hmac(data, hmac_key, desired_hmac):
        """Check if hmac matches"""
        computed_hmac = hmac.new(
            hmac_key, msg=data, digestmod=hashlib.sha256).digest()

        if bytes(computed_hmac) != bytes(desired_hmac):
            except_msg = 'Error checking HMAC'
            raise OpvaultException('DecodeError', except_msg)

        return True

    def load_items(self, exclude_trashed=False):
        """Load all items from json files"""
        file_glob = os.path.join(self._path, self._profile, 'band_*.js')

        self._items = {}
        for item in glob.glob(file_glob):
            with open(item, 'r') as file_descriptor:
                content = file_descriptor.read()[3:-2]
                try:
                    band = json.loads(content)
                    self._items.update(band)
                except ValueError:
                    pass

        self._item_index = defaultdict(list)
        for uuid, item in self._items.items():
            overview = self.item_overview(item)
            if 'title' in overview:
                if exclude_trashed and 'trashed' in item and item['trashed']:
                    continue
                self._item_index[overview['title']].append(uuid)

        return self._items

    def item_keys(self, item):
        """Get all keys for item"""
        item_key = self.decode_function(item['k'].encode())
        key_data = item_key[:-32]
        key_hmac = item_key[-32:]

        self.check_hmac(key_data, self._master_mac_key, key_hmac)
        plaintext = self.decrypt_data(
            self._master_key, key_data[0:16], key_data[16:])

        decrypted_key = plaintext[0:32]
        decrypted_hmac = plaintext[32:64]

        return decrypted_key, decrypted_hmac

    def item_overview(self, item):
        """Overview the item"""
        overview_data = self.decode_function(item['o'].encode())

        try:
            overview = self.decrypt_opdata(
                overview_data, self._overview_key, self._overview_mac_key)
            item_data = json.loads(overview)

        except OpvaultException as opvault_exception:
            except_msg = 'Cannot decrypt item: {0}, error: "{1}"'.format(
                item['uuid'], opvault_exception.error)
            raise OpvaultException('DecodeError', except_msg)

        except ValueError as value_error:
            except_msg = 'Cannot parse item: {0}, error: "{1}"'.format(
                item['uuid'], str(value_error))
            raise OpvaultException('DecodeError', except_msg)

        item_data.update({u'uuid': item['uuid']})

        return item_data

    def item_detail(self, item):
        """Get item details"""
        data = self.decode_function(item['d'].encode())

        try:
            item_key, item_mac_key = self.item_keys(item)
            detail = self.decrypt_opdata(data, item_key, item_mac_key)
            item_detail = json.loads(detail)

        except OpvaultException as opvault_exception:
            except_msg = 'Cannot decrypt item: {0}, error: "{1}"'.format(
                item['uuid'], opvault_exception.error)
            raise OpvaultException('DecodeError', except_msg)

        except ValueError as value_error:
            except_msg = 'Cannot parse item: {0}, error: "{1}"'.format(
                item['uuid'], str(value_error))
            raise OpvaultException('DecodeError', except_msg)

        return item_detail

    def get_item(self, title):
        """Get item from vault"""
        try:
            uuids = self._item_index[title]
            items = [self._items[uuid] for uuid in uuids]
        except KeyError:
            except_msg = 'Item with title {0} does not exists'.format(title)
            raise OpvaultException('ItemNotFound', except_msg)

        return [(self.item_overview(item), self.item_detail(item))
                for item in items]

    @staticmethod
    def decrypt_data(key, initialization_vector, data):
        """Decrypt data"""
        cipher = AES.new(key, AES.MODE_CBC, initialization_vector)
        return cipher.decrypt(data)
