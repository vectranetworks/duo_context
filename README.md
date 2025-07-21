# Vectra Duo Context
This is meant to provide Duo Security context to accounts within the Vectra UI based on Duo authentication logs. This script **only runs once**. To make this script run continuously, configure something like `cron` for **Linux** or `task scheduler` for **Windows** to initiate the script processing.

## Requirements
- Python 3.10+
  - vectra-api-tools
  - keyring
  - keyrings.alt
  - questionary
  - requests

## Duo Authentication - Admin API
- Integration Key
- Secret Key

## Vectra Authentication
- v2.5 and below
  - Personal Access Token (optional in v2.5)
- v2.5+
  - API Client ID
  - API Secret Key
- **Note:** For v2.5, only use one authentication method.

## Configuration 
There are several ways to configure this script. The script will attempt to use Python's Keyring library to store keys to store secrets to the system's keyring. This can be overridden by utilizing the `--no_store_secrets` command line flag. The configuration can be a mixture of config file, environment variables, and command line arguments. Priority of given variables will be 

1. Command line arguments
1. Environment variables
1. Config File (only for Duo Host and Vectra URL)


### File - Optional
A configuration file for the Duo and Vectra urls. File must be named `duo_conf.py` and its contents will be:
```
duo_host=""
vectra_url=""
```
The secrets will be asked and stored in the system keyring unless `--no_store_secrets` is used.

### Environment Variables - Optional
Environment variables can be used for the different required variables.
```
DUO_HOST
DUO_IKEY
DUO_SKEY
VECTRA_URL
VECTRA_CLIENT_ID
VECTRA_SECRET_KEY
VECTRA_TOKEN
```

### Command Line Arguments - Optional
```
usage: duo_context.py [-h] [--duo_host DUO_HOST] [--ikey IKEY] [--skey SKEY] [--vectra_url VECTRA_URL] [--client_id CLIENT_ID] [--secret_key SECRET_KEY] [--token TOKEN] [--update_secrets] [--no_store_secrets] [--plaintext]

DUO Security Context to Vectra

options:
  -h, --help            show this help message and exit
  --duo_host DUO_HOST   Duo API host 
  --ikey IKEY           Duo integration key
  --skey SKEY           Duo secret key
  --vectra_url VECTRA_URL
                        Vectra API URL 
  --client_id CLIENT_ID
                        Vectra API Client ID v2.5+
  --secret_key SECRET_KEY
                        Vectra API Secret Key v2.5+
  --token TOKEN         Vectra API Token v2.5 and below
  --update_secrets      Update secrets in keyring if they are not set
  --no_store_secrets    Update secrets in keyring if they are not set
  --plaintext           Do not use keyring, store secrets in plaintext
  --minutes MINUTES     Number of minutes to look back for Duo logs (default: 20)
```

#### Examples
```
  $ python3 duo_context.py --duo_host <duo_api_host> --ikey <ikey> --skey <skey> --vectra_url <vectra_url> --client_id <clien_id> --secret_key <secret_key>

  $ python3 duo_context.py --duo_host <duo_api_host> --vectra_url <vectra_url>

  $ python3 duo_context.py --minutes 60
```

## Resources
- [Duo Admin API](https://duo.com/docs/adminapi)
- [Vectra v2.5 API](https://support.vectra.ai/vectra/article/KB-VS-1638)
- [Vectra v3.4 API](https://support.vectra.ai/vectra/article/KB-VS-1835)

### Author
- Brandon Wyatt, bwyatt@vectra.ai