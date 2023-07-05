import os, sys

if os.path.basename(os.getcwd()) == "examples":
    base_dir = ".."
else:
    base_dir = "."

sys.path.append(base_dir)
sys.path.append(f"{base_dir}/at_client/common")
sys.path.append(f"{base_dir}/at_client/connections")
sys.path.append(f"{base_dir}/at_client/util")

from datetime import datetime
from argparse import ArgumentParser
from at_client import AtClient
from at_client.common import AtSign
from at_client.exception import *
from at_client.connections import Address
from at_client.common.keys import SharedKey


def share(args):
    parser = ArgumentParser()
    parser.add_argument("-u", "--url", help="Root URL (e.g., 'root.atsign.org:64')", default="root.atsign.org:64")
    parser.add_argument("-a", "--atsign", help="Your AtSign (e.g., '@alice')")
    parser.add_argument("-o", "--other_atsign", help="Other AtSign (e.g., '@bob')")
    parser.add_argument("-k", "--key_name", help="Name of the shared key, including namespace")
    parser.add_argument("-s", "--to_share", help="Value to share (a string)")
    parser.add_argument("-t", "--ttr", type=int, help="Time-to-refresh (TTR) value", default=-1)
    parser.add_argument("-v", "--verbose", help="Verbose == true|false", default="false")
    args = parser.parse_args(args)

    root_url = args.url
    key_name = args.key_name
    atsign = AtSign(args.atsign)
    other_atsign = AtSign(args.other_atsign)
    to_share = args.to_share
    ttr = args.ttr
    verbose = True if args.verbose.lower() == "true" else False

    at_client = None
    try:
        at_client = AtClient(atsign, root_address= Address.from_string(root_url), verbose=verbose)
    except AtException as e:
        print("Failed to create AtClient:", str(e))
        sys.exit(1)

    try:
        shared_key = SharedKey(key_name, atsign, other_atsign).cache(ttr, True)

        put_response = at_client.put(shared_key, to_share)
        print(datetime.now(), "| put response:", put_response)
    except AtException as e:
        print("Failed to share:", str(e))
        sys.exit(1)


if __name__ == "__main__":
    share(sys.argv[1:])
