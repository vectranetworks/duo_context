import argparse
import base64
import email.utils
import getpass
import hashlib
import hmac
import os
import re
import sys
import time
import urllib
from pathlib import Path

import keyring
import questionary
import requests
from keyrings.alt import file
from vat.platform import ClientV3_latest
from vat.vectra import ClientV2_latest


def set_plaintext():
    keyring.set_keyring(file.PlaintextKeyring())


def _get_password(system, key, **kwargs):
    env_value = os.environ.get(f"{system}_{key}")
    if env_value is not None:
        return env_value
    store_keys = kwargs["modify"][0]
    update_keys = kwargs["modify"][1]
    if not store_keys:
        password = getpass.getpass(f"Enter the {system} {key}: ")
    else:
        password = keyring.get_password(system, key)
        if update_keys:
            password = getpass.getpass(f"Enter the {system} {key}: ")
        elif password is None or password == "":
            password = getpass.getpass(f"Enter the {system} {key}: ")
        if password is not None:
            try:
                keyring.set_password(system, key, password)
            except keyring.errors.PasswordSetError:
                print("Failed to store password")

    return password


def _format_url(url):
    if ":/" not in url:
        url = "https://" + url
    else:
        url = re.sub("^.*://?", "https://", url)
    url = url[:-1] if url.endswith("/") else url
    return url


def sign(method, host, path, params, skey, ikey):
    """
    Return HTTP Basic Authentication ("Authorization" and "Date") headers.
    method, host, path: strings from request
    params: dict of request parameters
    skey: secret key
    ikey: integration key
    """
    # create canonical string
    now = email.utils.formatdate()
    canon = [now, method.upper(), host.lower(), path]
    args = []
    for key in sorted(params.keys()):
        val = params[key].encode("utf-8")
        args.append(
            "%s=%s" % (urllib.parse.quote(key, "~"), urllib.parse.quote(val, "~"))
        )
    canon.append("&".join(args))
    canon = "\n".join(canon)
    # sign canonical string
    sig = hmac.new(
        bytes(skey, encoding="utf-8"), bytes(canon, encoding="utf-8"), hashlib.sha1
    )
    auth = "%s:%s" % (ikey, sig.hexdigest())
    return {
        "Date": now,
        "Authorization": "Basic %s"
        % base64.b64encode(bytes(auth, encoding="utf-8")).decode(),
    }


def get_duo_context(ikey, skey, host, path, params, minutes):
    """
    Get context from Duo API.
    ikey: Duo integration key
    skey: Duo secret key
    host: Duo API host
    """
    maxtime = int(time.time() * 1000)
    minttime = maxtime - (1000 * 60 * minutes)
    params = {
        "mintime": str(minttime),
        "maxtime": str(maxtime),
    }
    headers = sign("GET", host, path, params, skey, ikey)
    url = f"https://{host}{path}?{urllib.parse.urlencode(params)}"
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code != 200:
        raise Exception(
            f"Failed to get context: {response.status_code} {response.text}"
        )

    return response.json()


def create_message(log):
    message = "## DUO Security Context\n"
    message += "|Property|Value |\n"
    message += "|:---|:---|\n"
    message += f"|Username|{log['user']['name']}|\n"
    message += f"|Result|{log['result']}|\n"
    message += f"|Reason|{log['reason']}|\n"
    message += f"|Factor|{log['factor']}|\n"
    message += f"|IP|{log['access_device']['ip']}|\n"
    message += f"|Time|{log["isotimestamp"].split(".")[0]}|\n"
    message += "|Location (City, State, Country)|"
    message += f"{log['access_device']['location']['city']}, "
    message += f"{log['access_device']['location']['state']}, "
    message += f"{log['access_device']['location']['country']}|"
    return message


def obtain_args():
    parser = argparse.ArgumentParser(
        description="DUO Security Context to Vectra",
        prefix_chars="--",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="",
    )
    parser.add_argument(
        "--duo_host",
        default=False,
        action="store",
        help="Duo API host",
    )

    parser.add_argument(
        "--ikey",
        default=False,
        action="store",
        help="Duo integration key",
    )

    parser.add_argument(
        "--skey",
        default=False,
        action="store",
        help="Duo secret key",
    )

    parser.add_argument(
        "--vectra_url",
        default=False,
        action="store",
        help="Vectra API URL",
    )

    parser.add_argument(
        "--client_id",
        default=False,
        action="store",
        help="Vectra API Client ID v2.5+",
    )

    parser.add_argument(
        "--secret_key",
        default=False,
        action="store",
        help="Vectra API Secret Key v2.5+",
    )

    parser.add_argument(
        "--token",
        default=False,
        action="store",
        help="Vectra API Token v2.5 and below",
    )

    parser.add_argument(
        "--update_secrets",
        default=False,
        action="store_true",
        help="Update secrets in keyring if they are not set",
    )

    parser.add_argument(
        "--no_store_secrets",
        default=False,
        action="store_true",
        help="Update secrets in keyring if they are not set",
    )

    parser.add_argument(
        "--plaintext",
        default=False,
        action="store_true",
        help="Do not use keyring, store secrets in plaintext",
    )

    parser.add_argument(
        "--minutes",
        default=20,
        action="store",
        help="Number of minutes to look back for Duo logs (default: 20)",
        type=int,
    )

    return parser.parse_args()


def main():
    params = {}

    conf = Path("duo_conf.py")
    if conf.exists():
        try:
            import duo_conf
        except ImportError:
            pass
    args = obtain_args()
    modify = (not args.no_store_secrets, args.update_secrets)
    if args.plaintext:
        set_plaintext()

    if not args.duo_host:
        args.duo_host = os.getenv("DUO_HOST", False)
        if not args.duo_host:
            try:
                args.duo_host = duo_conf.duo_host
            except UnboundLocalError:
                args.duo_host = questionary.text("Enter Duo API URL:").ask()

    if not args.vectra_url:
        args.vectra_url = os.getenv("VECTRA_URL", False)
        if not args.vectra_url:
            try:
                args.vectra_url = duo_conf.vectra_url
            except UnboundLocalError:
                args.vectra_url = questionary.text("Enter Vectra API URL").ask()
    args.vectra_url = _format_url(args.vectra_url)

    if not args.ikey or args.update_secrets:
        args.ikey = _get_password("DUO", "IKEY", modify=modify)
    if not args.skey or args.update_secrets:
        args.skey = _get_password("DUO", "SKEY", modify=modify)
    if not args.token:
        if not args.client_id or args.update_secrets:
            args.client_id = _get_password("Vectra", "CLIENT_ID", modify=modify)
        if not args.secret_key or args.update_secrets:
            args.secret_key = _get_password("VECTRA", "SECRET_KEY", modify=modify)
    else:
        if (not args.client_id and not args.secret_key) or args.update_secrets:
            args.token = _get_password("VECTRA", "TOKEN", modify=modify)
            if not args.token:
                args.token = questionary.text(
                    "Enter Vectra API Token v2.5 and below (leave blank for Client ID/Secret Key):"
                ).ask()
    if args.token and (args.client_id or args.secret_key):
        print("Cannot provide both token and Client ID/Secret Key. Exiting.")
        sys.exit(1)

    with open("duo_conf.py", "w") as f:
        f.write(f"duo_host='{args.duo_host}'\n")
        f.write(f"vectra_url='{args.vectra_url}'\n")

    logs = get_duo_context(
        args.ikey,
        args.skey,
        args.duo_host,
        "/admin/v2/logs/authentication",
        params,
        args.minutes,
    )["response"]["authlogs"]

    if logs != []:
        if "portal.vectra.ai" in args.vectra_url:
            client = ClientV3_latest(
                url=args.vectra_url,
                client_id=args.client_id,
                secret_key=args.secret_key,
            )
        elif args.token:
            client = ClientV2_latest(
                url=args.vectra_url,
                token=args.token,
            )
        elif args.client_id and args.secret_key:
            client = ClientV2_latest(
                url=args.vectra_url,
                client_id=args.client_id,
                secret_key=args.secret_key,
            )
        else:
            print("No valid Vectra API credentials provided.")
            sys.exit(1)

        vectra_accounts = []
        for accounts in client.get_all_accounts():
            vectra_accounts = vectra_accounts + accounts.json()["results"]

        new_count = 0
        update_count = 0
        for log in logs:
            for account in vectra_accounts:
                if log["user"]["name"] in account["name"]:
                    new_note = create_message(log)
                    duo_notes = False
                    for note in account["notes"]:
                        if note["note"].startswith("## DUO Security Context"):
                            duo_notes = True
                            if note["note"] != new_note:
                                update_count += 1
                                client.update_account_note(
                                    account_id=account["id"],
                                    note_id=note["id"],
                                    note=new_note,
                                )
                    if not duo_notes:
                        new_count += 1
                        client.set_account_note(account_id=account["id"], note=new_note)

        print(
            f"Added {new_count} new notes and updated {update_count} notes in Vectra."
        )
    else:
        print(f"There were no DUO Security logs in the last {args.minutes} minutes.")


if __name__ == "__main__":
    main()
