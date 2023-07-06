import unittest
from configparser import ConfigParser

from at_client import AtClient
from at_client.common import AtSign
from at_client.common.keys import PublicKey, SelfKey, SharedKey

class AtClientTest(unittest.TestCase):
    verbose = False
    atsign1 = ""
    atsign2 = ""

    @classmethod
    def setUpClass(cls) -> None:
        config = ConfigParser()
        config.read('config.ini')
        cls.atsign1 = config.get("test_atsigns", "atsign1", fallback="@27barracuda")
        cls.atsign2 = config.get("test_atsigns", "atsign2", fallback="@amateur93")
        return super().setUpClass()

    def test_atsign_pkam_authenticate(self):
        """Test PKAM Authentication"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        self.assertTrue(atclient.is_authenticated())

    def test_get_at_keys(self):
        """Test Scan Verb using get_at_keys"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        my_keys = atclient.get_at_keys("", fetch_metadata=True)
        self.assertTrue(len(my_keys)>0)

    def test_put_public_key(self):
        """Test Put Function with Public Key"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        pk = PublicKey("test_public_key", atsign)
        response = atclient.put(pk, "test1")
        self.assertIsNotNone(response)

    def test_put_self_key(self):
        """Test Put Function with Self Key"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        sk = SelfKey("test_self_key", atsign)
        response = atclient.put(sk, "test1")
        self.assertIsNotNone(response)

    def test_put_shared_key(self):
        """Test Put Function with Shared Key"""
        shared_by = AtSign(self.atsign1)
        shared_with = AtSign(self.atsign2)
        atclient = AtClient(shared_by, verbose=self.verbose)
        sk = SharedKey("test_shared_key", shared_by, shared_with)
        response = atclient.put(sk, "test1")
        self.assertIsNotNone(response)

        shared_with = AtSign(self.atsign1)
        shared_by = AtSign(self.atsign2)
        atclient = AtClient(shared_by, verbose=self.verbose)
        sk = SharedKey("test_shared_key2", shared_by, shared_with)
        response = atclient.put(sk, "test2")
        self.assertIsNotNone(response)
        

    def test_get_self_key(self):
        """Test Get Function with Self Key"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        sk = SelfKey("test_self_key", atsign)
        response = atclient.get(sk)
        self.assertEqual("test1", response)

    def test_get_public_key(self):
        """Test Get Function with Public Key"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        pk = PublicKey("test_public_key", atsign)
        response = atclient.get(pk)
        self.assertEqual("test1", response)

        amateur_atsign = AtSign(self.atsign2)
        atclient = AtClient(amateur_atsign, verbose=self.verbose)
        response = atclient.get(pk)
        self.assertEqual("test1", response)

    def test_get_shared_key(self):
        """Test Get Function with Shared Key"""
        # Shared by me with other
        shared_by = AtSign(self.atsign1)
        shared_with = AtSign(self.atsign2)
        atclient = AtClient(shared_by, verbose=self.verbose)
        sk = SharedKey("test_shared_key1", shared_by, shared_with)
        response = atclient.get(sk)
        self.assertEqual("test1", response)

        # Shared by other with me
        sk = SharedKey("test_shared_key2", shared_with, shared_by)
        response = atclient.get(sk)
        self.assertEqual("test2", response)

    def test_delete_public_key(self):
        """Test Delete Function with Public Key"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        pk = PublicKey("delete_test", atsign)
        response = atclient.put(pk, "test1")

        response = atclient.delete(pk)
        self.assertIsNotNone(response)

    def test_delete_self_key(self):
        """Test Delete Function with Self Key"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        sk = SelfKey("delete_self_key_test", atsign)
        response = atclient.put(sk, "test1")

        response = atclient.delete(sk)
        self.assertIsNotNone(response)

    def test_delete_shared_key(self):
        """Test Delete Function with Shared Key"""
        shared_by = AtSign(self.atsign1)
        shared_with = AtSign(self.atsign2)
        atclient = AtClient(shared_by, verbose=self.verbose)
        sk = SharedKey("delete_shared_key_test", shared_by, shared_with)
        response = atclient.put(sk, "test1")

        response = atclient.delete(sk)
        self.assertIsNotNone(response)

    
    
if __name__ == '__main__':
    unittest.main()
    