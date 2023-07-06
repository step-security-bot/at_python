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


def main(args):
    parser = ArgumentParser()
    parser.add_argument("-u", "--url", help="root url of the server", default="root.atsign.org:64")
    parser.add_argument("-a", "--atsign", help="atsign to be activated")
    parser.add_argument("-v", "--verbose", help="Verbose == true|false", default="false")
    parser.add_argument("-r", "--regex", help="Scan Regex", default="")
    args = parser.parse_args(args)
    
    if not args.atsign:
        parser.print_help()
        sys.exit(1)

    root_url = args.url
    regex = args.regex
    atsign = AtSign(args.atsign)
    verbose = True if args.verbose.lower() == "true" else False
    
    what = None 

    at_client = None
    try:
        what = "initialize AtClient"
        at_client = AtClient(atsign, root_address=Address.from_string(root_url), verbose=verbose)
    except AtException as e:
        print(f"Failed to {what} {e}")
        sys.exit(1)

    # run scan
    at_keys = None
    try:
        what = f"getAtKeys({regex})"
        at_keys = at_client.get_at_keys(regex, fetch_metadata=True)
    except (AtException) as e:
        print(f"Failed to {what} - {e}")
        sys.exit(1)

    # CLI
    input_text = ""
    while input_text != "q":
        print()
        print("Enter index you want to lookup (l to list, q to quit):", end="")
        input_text = input()
        if input_text.isdigit():
            index = int(input_text)
            if index < len(at_keys):
                at_key = at_keys[index]
                _print_at_key_info(at_key)
            else:
                print("Index out of bounds")
        elif input_text == "l":
            _print_at_keys(at_keys)
        elif input_text != "q":
            print("Invalid input")
    print("Done")


def _print_at_keys(at_keys):
    print("atKeys: {")
    for i, at_key in enumerate(at_keys):
        print(f"  {i}:  {'cached:' if at_key.metadata.is_cached else ''}{at_key}")
    print("}")


def _print_at_key_info(at_key):
    print("======================")
    print("Full KeyName: " + str(at_key))
    print("KeyName: " + at_key.name)
    print("Namespace: " + str(at_key.namespace))
    print("SharedBy: " + at_key.shared_by.to_string())
    print(
        "SharedWith: "
        + (at_key.shared_with.to_string() if at_key.shared_with is not None else "null")
    )
    print("KeyType: " + at_key.__class__.__name__)
    print("Metadata -------------------")
    _print_metadata(at_key.metadata)
    print("======================")
    print()


def _print_metadata(metadata):
    print("ttl: " + str(metadata.ttl))
    print("ttb: " + str(metadata.ttb))
    print("ttr: " + str(metadata.ttr))
    print("ccd: " + str(metadata.ccd))
    print(
        "availableAt: "
        + (str(metadata.available_at) if metadata.available_at is not None else "null")
    )
    print(
        "expiresAt: "
        + (str(metadata.expires_at) if metadata.expires_at is not None else "null")
    )
    print(
        "refreshAt: "
        + (str(metadata.refresh_at) if metadata.refresh_at is not None else "null")
    )
    print(
        "createdAt: "
        + (str(metadata.created_at) if metadata.created_at is not None else "null")
    )
    print(
        "updatedAt: "
        + (str(metadata.updated_at) if metadata.updated_at is not None else "null")
    )
    print("dataSignature: " + str(metadata.data_signature))
    print("sharedKeyStatus: " + str(metadata.shared_key_status))
    print("isPublic: " + str(metadata.is_public))
    print("isEncrypted: " + str(metadata.is_encrypted))
    print("isHidden: " + str(metadata.is_hidden))
    print("namespaceAware: " + str(metadata.namespace_aware))
    print("isBinary: " + str(metadata.is_binary))
    print("isCached: " + str(metadata.is_cached))
    print("sharedKeyEnc: " + str(metadata.shared_key_enc))
    print("pubKeyCS: " + str(metadata.pub_key_cs))


if __name__ == "__main__":
    main(sys.argv[1:])
