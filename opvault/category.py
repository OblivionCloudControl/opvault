# -*- coding: utf-8 -*-
"""Enum of all Opvault category types"""
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

from enum import Enum


class Category(Enum):
    """Opvault category types """
    LOGIN = 1
    CREDIT_CARD = 2
    SECURE_NOTE = 3
    IDENTITY = 4
    PASSWORD = 5
    TOMB_STONE = 99
    SOFTWARE_LICENSE = 100
    BANK_ACCOUNT = 101
    DATABASE = 102
    DRIVER_LICENSE = 103
    OUTDOOR_LICENSE = 104
    MEMBERSHIP = 105
    PASSPORT = 106
    REWARDS = 107
    SSN = 108
    ROUTER = 109
    SERVER = 100
    EMAIL = 111
