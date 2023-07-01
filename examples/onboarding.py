import os, sys

if os.path.basename(os.getcwd()) == "examples":
    base_dir = ".."
else:
    base_dir = "."

sys.path.append(base_dir)
sys.path.append(f"{base_dir}/at_client/common")
sys.path.append(f"{base_dir}/at_client/connections")
sys.path.append(f"{base_dir}/at_client/util")

import sys
import time
from at_client.connections import Address, AtRootConnection, AtSecondaryConnection
from at_client.exception import AtException, AtSecondaryNotFoundException
from at_client.common import AtSign
from at_client.util import AuthUtil, OnboardingUtil, KeysUtil


def main():
    if len(sys.argv) != 4:
        print("Usage: Onboard <rootUrl> <atSign> <cramSecret>")
        sys.exit(1)

    root_url = sys.argv[1]  # e.g. "root.atsign.org:64";
    atsign = AtSign(sys.argv[2])  # e.g. "@alice";
    cram_secret = sys.argv[3]

    print("Looking up secondary server address for", atsign)
    try:
        root_address = Address.from_string(root_url)
        secondary_address = AtRootConnection.get_instance(root_address.host, root_address.port).find_secondary(atsign)
    except AtSecondaryNotFoundException:
        secondary_address = retry_secondary_connection(root_url, atsign)

    print("Got address:", secondary_address)

    print("Connecting to", secondary_address)
    conn = AtSecondaryConnection(secondary_address)
    try:
        conn.connect()
    except Exception:
        time.sleep(2)
        conn.connect()

    auth = AuthUtil()
    onboarding_util = OnboardingUtil()

    print("Authenticating with CRAM")
    auth.authenticate_with_cram(conn, atsign, cram_secret)
    print("Authenticating with CRAM succeeded")

    # We've authenticated with CRAM; let's generate and store the various keys we need
    keys = {}
    print("Generating symmetric 'self' encryption key")
    onboarding_util.generate_self_encryption_key(keys)

    print("Generating PKAM keypair")
    onboarding_util.generate_pkam_keypair(keys)

    print("Generating asymmetric encryption keypair")
    onboarding_util.generate_encryption_keypair(keys)

    # Finally, let's store all the keys to a .keys file
    print("Saving keys to file")
    KeysUtil.save_keys(atsign, keys)

    # we're authenticated, let's store the PKAM public key to the secondary
    print("Storing PKAM public key on cloud secondary")
    onboarding_util.store_pkam_public_key(conn, keys)

    # and now that the PKAM public key is on the server, let's auth via PKAM
    print("Authenticating with PKAM")
    keys1 = KeysUtil.load_keys(atsign)
    auth.authenticate_with_pkam(conn, atsign, keys1)
    print("Authenticating with PKAM succeeded")

    print("Storing encryption public key")
    onboarding_util.store_public_encryption_key(conn, atsign.without_prefix, keys)

    # and as we've successfully authenticated with PKAM, let's delete the CRAM secret
    print("Deleting CRAM secret")
    onboarding_util.delete_cram_key(conn)

    print("Onboarding complete")


def retry_secondary_connection(address, atsign):
    retry_count = 0
    max_retries = 50
    secondary_address = ""

    time.sleep(1)

    while retry_count < max_retries and secondary_address == "":
        try:
            secondary_address = AtRootConnection(address.host, address.port).find_secondary(atsign)
        except AtException:
            retry_count += 1
            print("Retrying fetching secondary address ... attempt", retry_count, "/", max_retries)

    return secondary_address


if __name__ == "__main__":
    main()