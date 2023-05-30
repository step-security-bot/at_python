import unittest

from src.common import AtSign, AtClient
from src.util import KeysUtil

class AtClientTest(unittest.TestCase):
    verbose = False

    def test_atsign_pkam_authenticate(self):
        """Test atKeys Loading"""
        atsign = AtSign("27barracuda")
        keys = KeysUtil.load_keys(atsign)
        atclient = AtClient(atsign, verbose=AtClientTest.verbose)
        authenticated = atclient.pkam_authenticate(keys)
        self.assertTrue(authenticated)
    
    
if __name__ == '__main__':
    unittest.main()
    