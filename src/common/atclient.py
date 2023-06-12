import json
from src.common import AtSign
from src.util.verbbuilder import *
from src.util.encryptionutil import EncryptionUtil
from src.util.keysutil import KeysUtil
from src.common.keys import Keys
from src.common.metadata import Metadata
from src.common.exception.atexception import AtException
from src.connections.atrootconnection import AtRootConnection
from src.connections.atsecondaryconnection import AtSecondaryConnection
from src.connections.address import Address

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
        command = FromVerbBuilder().set_shared_by(self.atsign).build()
        from_response = self.secondary_connection.execute_command(command)

        try:
            signature = EncryptionUtil.sign_sha256_rsa(from_response, self.keys[KeysUtil.pkam_private_key_name])
        except:
            raise Exception("Failed to create SHA256 signature")

        command = PKAMVerbBuilder().set_digest(signature).build()
        pkam_response = self.secondary_connection.execute_command(command)

        if self.verbose:
            print("Authentication Successful")

        return True
    
    def get_at_keys(self, regex, fetch_metadata):
        scan_command = ScanVerbBuilder().set_regex(regex).set_show_hidden(True).build()
        try:
            scan_raw_response = self.secondary_connection.execute_command(scan_command)
        except Exception as e:
            raise AtException(f"Failed to execute : {scan_command} : {e}")
        
        keys_list = []
        if len(scan_raw_response) > 0:
            keys_list = json.loads(scan_raw_response)
        # print(keys_list)
        at_keys = []
        for at_key_raw in keys_list:
            at_key = Keys.from_string(at_key_raw)
            if fetch_metadata:
                llookup_command = "llookup:meta:" + at_key_raw
                try:
                    llookup_meta_response = self.secondary_connection.execute_command(llookup_command, read_the_response=True)
                except Exception as e:
                    raise AtException(f"Failed to execute : {llookup_command} : {e}")
                
                try:
                    at_key.metadata = Metadata.squash(at_key.metadata, Metadata.from_json(llookup_meta_response))
                except Exception as e:
                    raise AtException(f"Failed to parse JSON : {llookup_meta_response} : {e}")
            
            at_keys.append(at_key)
        
        return at_keys
    
    def is_authenticated(self):
        return self.authenticated
    
    def __del__(self):
        if self.secondary_connection:
            self.secondary_connection.disconnect()
