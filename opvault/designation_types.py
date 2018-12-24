# -*- coding: utf-8 -*-
""""Enum class for Opvault designation types"""

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


class DesignationTypes(Enum):
    """Define Opvault designation types"""
    USERNAME = 'username'
    PASSWORD = 'password'
    NONE = ''
