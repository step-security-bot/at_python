import os, sys

if os.path.basename(os.getcwd()) == "examples":
    base_dir = ".."
else:
    base_dir = "."

sys.path.append(base_dir)
sys.path.append(f"{base_dir}/at_client/common")
sys.path.append(f"{base_dir}/at_client/connections")
sys.path.append(f"{base_dir}/at_client/util")

from argparse import ArgumentParser
from at_client import AtClient
from at_client.common import AtSign
from at_client.exception import *
from at_client.connections import Address
from at_client.common.keys import SharedKey

# Script to delete Previously SharedKey

def main(args):
    parser = ArgumentParser()
    parser.add_argument("-u", "--url", help="Root URL (e.g., 'root.atsign.org:64')", default="root.atsign.org:64")
    parser.add_argument("-a", "--atsign", help="Your AtSign (e.g., '@alice')")
    parser.add_argument("-o", "--other_atsign", help="Other AtSign (e.g., '@bob')")
    parser.add_argument("-k", "--key_name", help="Name of the shared key, including namespace")
    parser.add_argument("-v", "--verbose", help="Verbose == true|false", default="false")
    args = parser.parse_args(args)

    root_url = args.url
    key_name = args.key_name
    atsign = AtSign(args.atsign)
    other_atsign = AtSign(args.other_atsign)
    verbose = True if args.verbose.lower() == "true" else False

    if not key_name or not atsign or not other_atsign:
        parser.print_help()
        sys.exit(1)
    
    at_client = None
    try:
        at_client = AtClient(atsign, root_address= Address.from_string(root_url), verbose=verbose)
    except AtException as e:
        print("Failed to create AtClientImpl:", str(e))
        sys.exit(1)
    
    try:
        delete_response = at_client.delete(SharedKey(key_name, atsign, other_atsign))
        print("delete response:", delete_response)
    except AtException as e:
        print("Failed to get:", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
