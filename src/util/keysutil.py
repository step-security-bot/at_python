import os
import json
import base64
from typing import Dict, Tuple

# from src.common.atsign import AtSign
from src.util.encryptionutil import EncryptionUtil


class KeysUtil:
    expected_keys_files_location = os.path.expanduser("~/.atsign/keys/")
    legacy_keys_files_location = os.path.join(os.getcwd(), "keys")
    keys_file_suffix = "_key.atKeys"

    pkam_public_key_name = "aesPkamPublicKey"
    pkam_private_key_name = "aesPkamPrivateKey"
    encryption_public_key_name = "aesEncryptPublicKey"
    encryption_private_key_name = "aesEncryptPrivateKey"
    self_encryption_key_name = "selfEncryptionKey"

    @staticmethod
    def load_keys(at_sign: str) -> Dict[str, str]:
        
        file = KeysUtil.get_keys_file(at_sign, KeysUtil.expected_keys_files_location)
        if not os.path.exists(file):
            file = KeysUtil.get_keys_file(at_sign, KeysUtil.legacy_keys_files_location)
            if not os.path.exists(file):
                raise Exception(f"load_keys: No file called {at_sign}{KeysUtil.keys_file_suffix} at {KeysUtil.expected_keys_files_location} or {KeysUtil.legacy_keys_files_location}\n"
                                "\tKeys files are expected to be in ~/.atsign/keys/ (canonical location) or ./keys/ (legacy location)")

        with open(file) as f:
            encrypted_keys = json.load(f)

        self_encryption_key = encrypted_keys[KeysUtil.self_encryption_key_name]
        keys = {
            KeysUtil.self_encryption_key_name: self_encryption_key,
            KeysUtil.pkam_public_key_name: EncryptionUtil.aes_decrypt_from_base64(encrypted_keys[KeysUtil.pkam_public_key_name], self_encryption_key),
            KeysUtil.pkam_private_key_name: EncryptionUtil.aes_decrypt_from_base64(encrypted_keys[KeysUtil.pkam_private_key_name], self_encryption_key),
            KeysUtil.encryption_public_key_name: EncryptionUtil.aes_decrypt_from_base64(encrypted_keys[KeysUtil.encryption_public_key_name], self_encryption_key),
            KeysUtil.encryption_private_key_name: EncryptionUtil.aes_decrypt_from_base64(encrypted_keys[KeysUtil.encryption_private_key_name], self_encryption_key),
        }

        return keys

    @staticmethod
    def get_keys_file(at_sign: str, folder_to_look_in: str) -> str:
        return os.path.join(folder_to_look_in, "{}{}".format(at_sign, KeysUtil.keys_file_suffix))
