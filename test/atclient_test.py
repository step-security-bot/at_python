import unittest

from src.common import AtSign, AtClient
from src.util import KeysUtil

class AtClientTest(unittest.TestCase):
    verbose = False

    def test_atsign_pkam_authenticate(self):
        """Test atKeys Loading"""
        atsign = AtSign("27barracuda")
        atclient = AtClient(atsign, verbose=AtClientTest.verbose)
        self.assertTrue(atclient.is_authenticated())
    
    
if __name__ == '__main__':
    unittest.main()
    