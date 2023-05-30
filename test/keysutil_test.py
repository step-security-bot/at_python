import unittest

from src.common import AtSign
from src.util import KeysUtil

class KeysUtilTest(unittest.TestCase):

    def test_load_keys(self):
        """Test atKeys Loading"""
        keys = KeysUtil.load_keys(AtSign("27barracuda"))
        self.assertIsNotNone(keys[KeysUtil.self_encryption_key_name])
        self.assertIsNotNone(keys[KeysUtil.pkam_private_key_name])
        self.assertIsNotNone(keys[KeysUtil.pkam_public_key_name])
        self.assertIsNotNone(keys[KeysUtil.encryption_private_key_name])
        self.assertIsNotNone(keys[KeysUtil.encryption_public_key_name])
    
    
if __name__ == '__main__':
    unittest.main()
    