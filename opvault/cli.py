#!/usr/bin/env python
"""opvault-cli tool to access locally stored Opvault vaults"""
# -*- coding: utf-8 -*-

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

from __future__ import print_function

import getpass
import sys

from opvault.onepass import OnePass
from opvault import exceptions
from opvault import designation_types


def main():
    """Run opvault-cli"""
    def usage():
        """Print usage"""
        return 'Usage: {0} <path_to_opvault> <item_title>'.format(sys.argv[0])

    def get_field_items(title, designation_field):
        """Get field values from item"""
        # fetch from first match
        _overview, details = vault.get_item(title)[0]

        fields = [field['value'] for field in details['fields']
                  if 'designation' in field and
                  field['designation'] == designation_field]

        # Only return username if 1 match is found. Raise exception if not
        if not fields:
            except_msg = 'Field {} found for item'.format(designation_field)
            raise exceptions.OpvaultException('FieldNotFound', except_msg)

        return fields

    def get_field_item(title, designation_field):
        """Get exactly one field from item"""
        fields = get_field_items(title, designation_field)

        if len(fields) > 1:
            except_msg = 'Multiple fields found for item'
            raise exceptions.OpvaultException(
                'MultipleResultsFound', except_msg)

        return fields[0]

    def get_username(title):
        """Get username from item"""
        return get_field_item(title,
                              designation_types.DesignationTypes.USERNAME)

    def get_password(title):
        """Get password from item"""
        return get_field_item(title,
                              designation_types.DesignationTypes.PASSWORD)

    # Init Vault
    try:
        vault = OnePass(sys.argv[1])
        title = sys.argv[2]
    except exceptions.OpvaultException as opvault_exception:
        print('{0}: {1}'.format(opvault_exception, opvault_exception.error))
        sys.exit(1)
    except IndexError:
        print(usage())
        sys.exit(1)

    try:
        # Unlocking vault
        master_password = getpass.getpass(prompt='1Password master password: ')
        vault.unlock(master_password=master_password)

        # Load all items (not details) and return match for 'title'
        vault.load_items()
        if title == '-l':  # List items
            items = vault.get_items()
            for item in items:
                print(item)
        else:
            item_title = get_username(title)
            item_password = get_password(title)
            print('')
            print('Username: {0}'.format(item_title))
            print('Password: {0}'.format(item_password))

    except exceptions.OpvaultException as opvault_exception:
        # Ooops, could possibly not decrypt/decode vault
        print('ERROR: {0}'.format(opvault_exception.error))

    except IndexError:
        print('Item not found in vault')

    finally:
        # We're done, lock the vault
        vault.lock()


if __name__ == '__main__':
    main()
