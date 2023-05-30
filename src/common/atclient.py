from src.common import AtSign
from src.util.verbbuilder import *
from src.util import EncryptionUtil, KeysUtil
from src.common.exception import AtException
from src.connections import AtRootConnection, AtSecondaryConnection

class AtClient:
    def __init__(self, atsign:AtSign, verbose:bool = False):
        self.atsign = atsign
        self.verbose = verbose
        secondary_address = AtRootConnection.get_instance(verbose=verbose).find_secondary(atsign)
        self.secondary_connection = AtSecondaryConnection(secondary_address, verbose=verbose)
        self.secondary_connection.connect()

    def pkam_authenticate(self, keys:dict):
        data_prefix = "data:"
        command = FromVerbBuilder().set_shared_by(self.atsign).build()
        from_response = self.secondary_connection.execute_command(command)

        if not from_response.startswith(data_prefix):
            raise AtException(f"Invalid response to 'from' command: {repr(from_response)}")

        from_response = from_response[len(data_prefix) :]

        try:
            signature = EncryptionUtil.sign_sha256_rsa(from_response, keys[KeysUtil.pkam_private_key_name])
        except:
            raise Exception("Failed to create SHA256 signature")

        command = PKAMVerbBuilder().set_digest(signature).build()
        pkam_response = self.secondary_connection.execute_command(command)

        if not pkam_response.startswith("data:success"):
            raise AtException(f"PKAM command failed: {repr(pkam_response)}")

        if self.verbose:
            print("Authentication Successful")

        return True
