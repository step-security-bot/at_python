from src.common import AtSign
from src.util.verbbuilder import *
from src.util import EncryptionUtil, KeysUtil
from src.common.exception import AtException
from src.connections import AtRootConnection, AtSecondaryConnection, Address

class AtClient(ABC):
    def __init__(self, atsign:AtSign, root_address:Address=Address("root.atsign.org", 64), secondary_address:Address=None, verbose:bool = False):
        self.atsign = atsign
        self.keys = KeysUtil.load_keys(atsign)
        self.verbose = verbose
        if secondary_address is None:
            self.root_connection = AtRootConnection.get_instance(host=root_address.host, 
                                                            port=root_address.port, 
                                                            verbose=verbose)
            secondary_address = self.root_connection.find_secondary(atsign)
        self.secondary_connection = AtSecondaryConnection(secondary_address, verbose=verbose)
        self.secondary_connection.connect()
        self.authenticated = self.pkam_authenticate()

    def pkam_authenticate(self):
        data_prefix = "data:"
        command = FromVerbBuilder().set_shared_by(self.atsign).build()
        from_response = self.secondary_connection.execute_command(command)

        if not from_response.startswith(data_prefix):
            raise AtException(f"Invalid response to 'from' command: {repr(from_response)}")

        from_response = from_response[len(data_prefix) :]

        try:
            signature = EncryptionUtil.sign_sha256_rsa(from_response, self.keys[KeysUtil.pkam_private_key_name])
        except:
            raise Exception("Failed to create SHA256 signature")

        command = PKAMVerbBuilder().set_digest(signature).build()
        pkam_response = self.secondary_connection.execute_command(command)

        if not pkam_response.startswith("data:success"):
            raise AtException(f"PKAM command failed: {repr(pkam_response)}")

        if self.verbose:
            print("Authentication Successful")

        return True
    
    def is_authenticated(self):
        return self.authenticated
    
    def __del__(self):
        if self.root_connection:
            self.root_connection.disconnect()
        if self.secondary_connection:
            self.secondary_connection.disconnect()
