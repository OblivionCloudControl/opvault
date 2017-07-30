#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

from __future__ import print_function

from opvault.onepass import OnePass
from opvault import exceptions
from opvault import designation_types
import sys
import getpass


def main():
    def usage():
        return 'Usage: {0} <path_to_opvault> <item_title>'.format(sys.argv[0])

    def get_username(title):
        overview, details = vault.get_item(title)

        usernames = [field['value'] for field in details['fields']
                     if field['designation'] == designation_types.DesignationTypes.USERNAME]

        # Only return username if 1 match is found. Raise exception if not
        if not usernames or len(usernames) == 0:
            except_msg = 'No usernames found for item'
            raise exceptions.OpvaultException('NoUsernameFound', except_msg)
        elif len(usernames) > 1:
            except_msg = 'Multiple usernames found for item'
            raise exceptions.OpvaultException('MultipleUsernamesFound', except_msg)

        return usernames[0]

    def get_password(title):
        overview, details = vault.get_item(title)

        passwords = [field['value'] for field in details['fields']
                     if field['designation'] == designation_types.DesignationTypes.PASSWORD]

        # Only return password if 1 match is found. Raise exception if not
        if not passwords or len(passwords) == 0:
            except_msg = 'No passwords found for item'
            raise exceptions.OpvaultException('NoPasswordFound', except_msg)
        elif len(passwords) > 1:
            except_msg = 'Multiple passwords found for item'
            raise exceptions.OpvaultException('MultiplePasswordsFound', except_msg)

        return passwords[0]

    # Init Vault
    try:
        vault = OnePass(sys.argv[1])
        title = sys.argv[2]
    except exceptions.OpvaultException as e:
        print('{0}: {1}'.format(e, e.error))
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
        if title == '-l': #List items
            items = vault.getItems()
            for x in items:
                print(x)
        else:
            item_password = get_password(title)
            print('\nUsername: {0}'.format(get_username(title)))
            print('\nPassword: {0}'.format(item_password))

    except exceptions.OpvaultException as e:
        # Ooops, could possibly not decrypt/decode vault
        print('ERROR: {0}'.format(e.error))
    finally:
        # We're done, lock the vault
        vault.lock()

if __name__ == '__main__':
    main()
