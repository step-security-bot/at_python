import json
from functools import singledispatch

from src.common import AtSign
from src.util.verbbuilder import *
from src.util.encryptionutil import EncryptionUtil
from src.util.keysutil import KeysUtil
from src.common.keys import Keys
from src.common.metadata import Metadata
from src.common.exception.atexception import *
from src.connections.atrootconnection import AtRootConnection
from src.connections.atsecondaryconnection import AtSecondaryConnection
from src.connections.address import Address
from src.common.keys import SharedKey, PrivateHiddenKey, PublicKey, SelfKey

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
        from_response = self.secondary_connection.execute_command(command).get_raw_data_response()

        try:
            signature = EncryptionUtil.sign_sha256_rsa(from_response, self.keys[KeysUtil.pkam_private_key_name])
        except:
            raise Exception("Failed to create SHA256 signature")

        command = PKAMVerbBuilder().set_digest(signature).build()
        pkam_response = self.secondary_connection.execute_command(command).get_raw_data_response()

        if self.verbose:
            print("Authentication Successful")

        return True
    
    def get_at_keys(self, regex, fetch_metadata):
        scan_command = ScanVerbBuilder().set_regex(regex).set_show_hidden(True).build()
        try:
            scan_raw_response = self.secondary_connection.execute_command(scan_command, True).get_raw_data_response()
        except Exception as e:
            raise AtSecondaryConnectException(f"Failed to execute : {scan_command} : {e}")
        
        keys_list = []
        if len(scan_raw_response) > 0:
            keys_list = json.loads(scan_raw_response)

        at_keys = []
        for at_key_raw in keys_list:
            at_key = Keys.from_string(at_key_raw)
            if fetch_metadata:
                llookup_command = "llookup:meta:" + at_key_raw
                try:
                    llookup_meta_response = self.secondary_connection.execute_command(llookup_command, read_the_response=True).get_raw_data_response()
                except Exception as e:
                    raise AtSecondaryConnectException(f"Failed to execute : {llookup_command} : {e}")
                
                try:
                    at_key.metadata = Metadata.squash(at_key.metadata, Metadata.from_json(llookup_meta_response))
                except Exception as e:
                    raise AtResponseHandlingException(f"Failed to parse JSON : {llookup_meta_response} : {e}")
            
            at_keys.append(at_key)
        
        return at_keys
    
    def is_authenticated(self):
        return self.authenticated
    
    def get_public_encryption_key(self, shared_with):
        raw_response = None

        command = "plookup:publickey" + shared_with.to_string()
        try:
            response = self.secondary_connection.execute_command(command)
        except Exception as e:
            raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")

        if response.is_error():
            if isinstance(response.get_exception(), AtKeyNotFoundException): return None
            else:
                raise response.get_exception()
        else:
            return response.get_raw_data_response()

    
    def create_shared_encryption_key(self, shared_key: SharedKey):
        their_public_encryption_key = self.get_public_encryption_key(shared_key.shared_with)
        if their_public_encryption_key is None:
            raise AtKeyNotFoundException(" public key " + shared_key.shared_with.to_string() + " not found but service is running - maybe that AtSign has not yet been onboarded")

        aes_key = ""
        try:
            aes_key = EncryptionUtil.generate_aes_key_base64()
        except Exception as e:
            raise AtEncryptionException("Failed to generate AES key for sharing with " + shared_key.shared_with) from e

        step = ""
        try:
            step = "encrypt new shared key with their public key"
            encrypted_for_other = EncryptionUtil.rsa_encrypt_to_base64(aes_key, their_public_encryption_key)

            step = "encrypt new shared key with our public key"
            encrypted_for_us = EncryptionUtil.rsa_encrypt_to_base64(aes_key, self.keys.get(KeysUtil.encryption_public_key_name))

            step = "save encrypted shared key for us"
            self.secondary_connection.execute_command("update:" + "shared_key." + shared_key.shared_with.without_prefix + shared_key.shared_by.to_string()
                                    + " " + encrypted_for_us, True)

            step = "save encrypted shared key for them"
            ttr = 24 * 60 * 60 * 1000
            self.secondary_connection.execute_command("update:ttr:" + str(ttr) + ":" + shared_key.shared_with.to_string() + ":shared_key" + shared_key.shared_by.to_string()
                                    + " " + encrypted_for_other, True)
        except Exception as e:
            raise AtEncryptionException(f"Failed to {step} - {e}")

        return aes_key
    
    def get_encryption_key_shared_by_me(self, key: SharedKey):
        # lookup:shared_key.bob@alice
        response = None
        to_lookup = "shared_key." + key.shared_with.without_prefix + self.atsign.to_string()

        command = "lookup:" + to_lookup
        try:
            response = self.secondary_connection.execute_command(command, False)
        except Exception as e:
            raise AtException(f"Failed to execute {command} - {e}")

        if response.is_error():
            if isinstance(response.get_exception(), AtKeyNotFoundException):
                # No key found - so we should create one
                return self.create_shared_encryption_key(key)
            else:
                raise response.get_exception()

        # When we stored it, we encrypted it with our encryption public key;
        # so we need to decrypt it now with our encryption private key
        try:
            return EncryptionUtil.rsa_decrypt_from_base64(response, self.keys[KeysUtil.encryption_private_key_name])
        except Exception as e:
            raise AtDecryptionException(f"Failed to decrypt {to_lookup} - e")

    def put(self, key, value):
        if isinstance(key, SharedKey):
            return self._put_shared_key(key, value)
        elif isinstance(key, SelfKey):
            return self._put_self_key(key, value)
        elif isinstance(key, PublicKey):
            return self._put_public_key(key, value)
        else:
            raise NotImplementedError(f"No implementation found for key type: {type(key)}")

    def _put_self_key(self, key: SelfKey, value: str):
        key.metadata.data_signature = EncryptionUtil.sign_sha256_rsa(value, self.keys[KeysUtil.encryption_private_key_name])

        try:
            cipher_text = EncryptionUtil.aes_encrypt_from_base64(value, self.keys[KeysUtil.self_encryption_key_name])
        except Exception as e:
            raise AtException(f"Failed to encrypt value with self encryption key - {e}")
        
        command = UpdateVerbBuilder().with_at_key(key, cipher_text).build()
        try:
            return self.secondary_connection.execute_command(command).get_raw_data_response()
        except Exception as e:
            raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")

    def _put_public_key(self, key: PublicKey, value: str):
        key.metadata.data_signature = EncryptionUtil.sign_sha256_rsa(value, self.keys[KeysUtil.encryption_private_key_name])

        command = UpdateVerbBuilder().with_at_key(key, value).build()

        try:
            return self.secondary_connection.execute_command(command).get_raw_data_response()
        except Exception as e:
            raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")
        
    def _put_shared_key(self, key: SharedKey, value: str):
        if self.atsign != key.shared_by:
            raise AtIllegalArgumentException(f"sharedBy is [{key.shared_by}] but should be this client's atSign [{self.atsign}]")

        what = ""
        cipher_text = None
        try:
            what = "fetch/create shared encryption key"
            share_to_encryption_key = self.get_encryption_key_shared_by_me(key)

            what = "encrypt value with shared encryption key"
            cipher_text = EncryptionUtil.aes_encrypt_from_base64(value, share_to_encryption_key)
        except Exception as e:
            raise AtEncryptionException(f"Failed to {what} - {e}")

        command = f"update{key.metadata}:{key} {cipher_text}"

        try:
            return self.secondary_connection.execute_command(command, True).get_raw_data_response()
        except Exception as e:
            raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")
        

    def __del__(self):
        if self.secondary_connection:
            self.secondary_connection.disconnect()
