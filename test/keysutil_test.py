import unittest
from configparser import ConfigParser

from src.common import AtSign
from src.util import KeysUtil

class KeysUtilTest(unittest.TestCase):
    atsign1 = ""
    atsign2 = ""

    @classmethod
    def setUpClass(cls) -> None:
        config = ConfigParser()
        config.read('config.ini')
        cls.atsign1 = config.get("test_atsigns", "atsign1", fallback="@27barracuda")
        return super().setUpClass()

    def test_load_keys(self):
        """Test atKeys Loading"""
        keys = KeysUtil.load_keys(self.atsign1)
        self.assertIsNotNone(keys[KeysUtil.self_encryption_key_name])
        self.assertIsNotNone(keys[KeysUtil.pkam_private_key_name])
        self.assertIsNotNone(keys[KeysUtil.pkam_public_key_name])
        self.assertIsNotNone(keys[KeysUtil.encryption_private_key_name])
        self.assertIsNotNone(keys[KeysUtil.encryption_public_key_name])
    
    
if __name__ == '__main__':
    unittest.main()
    