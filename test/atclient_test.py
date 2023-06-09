import unittest

from src.common import AtSign, AtClient

class AtClientTest(unittest.TestCase):
    verbose = False

    def test_atsign_pkam_authenticate(self):
        """Test PKAM Authentication"""
        atsign = AtSign("27barracuda")
        atclient = AtClient(atsign, verbose=AtClientTest.verbose)
        self.assertTrue(atclient.is_authenticated())

    def test_get_at_keys(self):
        atsign = AtSign("@27barracuda")
        atclient = AtClient(atsign, verbose=AtClientTest.verbose)
        my_keys = atclient.get_at_keys("", fetch_metadata=True)

    
    
if __name__ == '__main__':
    unittest.main()
    