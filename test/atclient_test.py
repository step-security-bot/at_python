import unittest

from src.common import AtSign, AtClient
from src.common.keys import PublicKey, SelfKey, SharedKey, PrivateHiddenKey

class AtClientTest(unittest.TestCase):
    verbose = False

    def test_atsign_pkam_authenticate(self):
        """Test PKAM Authentication"""
        atsign = AtSign("27barracuda")
        atclient = AtClient(atsign, verbose=AtClientTest.verbose)
        self.assertTrue(atclient.is_authenticated())

    def test_get_at_keys(self):
        """Test Scan Verb using get_at_keys"""
        atsign = AtSign("@27barracuda")
        atclient = AtClient(atsign, verbose=AtClientTest.verbose)
        my_keys = atclient.get_at_keys("", fetch_metadata=True)
        self.assertTrue(len(my_keys)>0)

    def test_put_public_key(self):
        """Test Put Function with Public Key"""
        atsign = AtSign("@27barracuda")
        atclient = AtClient(atsign, verbose=AtClientTest.verbose)
        pk = PublicKey("test_public_key", atsign)
        response = atclient.put(pk, "test1")
        self.assertIsNotNone(response)

    def test_put_self_key(self):
        """Test Put Function with Self Key"""
        atsign = AtSign("@27barracuda")
        atclient = AtClient(atsign, verbose=AtClientTest.verbose)
        sk = SelfKey("test_self_key", atsign)
        response = atclient.put(sk, "test1")
        print(response)
        self.assertIsNotNone(response)

    
    
if __name__ == '__main__':
    unittest.main()
    