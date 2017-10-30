# Python library to read data from 1Password's OPVault databases

## Prerequisites
* Python >= 2.7
* Have a 1Password database
* Install Python dependencies (PyCrypto)

## Example
### Sample cli
Download the sample data (see below) and execute opvault-cli
```bash
$ opvault-cli test/onepassword_data YouTube
1Password master password:

Password: <password>
```

### Snippet
This example fetches the password for the item named 'MyApp':

```python
from opvault.onepass import OnePass
from opvault import exceptions
from opvault import designation_types

master_password = 'MyLittleSecret'

vault = OnePass()

vault.unlock(master_password=master_password)
vault.load_items()

title = 'MyApp'
overview, details = vault.get_item(title)

password = [field['value'] for field in details['fields']
            if field['designation'] == designation_types.DesignationTypes.PASSWORD][0]
 
print(password)
```

## Installation
### Installation from pip
Install from pip repository
```
$ pip install opvault
```

### Installation from source
Run from source directory:
```
$ python setup.py install
```

## Development
### Install sample data
AgileBits provides sample data which can be useful when building apps. To install the sample data execute:
```bash
$ mkdir -p test
$ cd test
$ curl https://cache.agilebits.com/security-kb/freddy-2013-12-04.tar.gz | tar xfz -
```