import unittest
from src.common import AtSign
from src.common.exception import AtException
from src.connections import AtRootConnection

class AtRootConnectionTest(unittest.TestCase):
    verbose = False

    def test_root_connection(self):
        """
        Test root connection establishment.
        """
        root_connection = AtRootConnection.get_instance(verbose=AtRootConnectionTest.verbose)
        root_connection.connect()
        self.assertTrue(root_connection.is_connected())

    def test_find_secondary(self):
        """
        Test finding a secondary server address.
        """
        root_connection = AtRootConnection.get_instance(verbose=AtRootConnectionTest.verbose)
        secondary_address = root_connection.find_secondary(AtSign("@27barracuda"))
        self.assertIsNotNone(secondary_address)

    def test_find_secondary_failure(self):
        """
        Test finding a secondary server address for a non-existent AtSign.
        """
        try:
            root_connection = AtRootConnection.get_instance(verbose=AtRootConnectionTest.verbose)
            secondary_address = root_connection.find_secondary(AtSign("@wrongAtSign"))
        except AtException as e:
            self.assertEqual("Root lookup returned null for @wrongAtSign", str(e))

    def test_find_multiple_secondary_addresses(self):
        """
        Test finding multiple secondary server addresses.
        """
        root_connection = AtRootConnection.get_instance(verbose=AtRootConnectionTest.verbose)
        secondary_address1 = root_connection.find_secondary(AtSign("@27barracuda"))
        secondary_address2 = root_connection.find_secondary(AtSign("@19total67"))
        secondary_address3 = root_connection.find_secondary(AtSign("@wildgreen"))
        secondary_address4 = root_connection.find_secondary(AtSign("@colin"))
        
        self.assertIsNotNone(secondary_address1)
        self.assertIsNotNone(secondary_address2)
        self.assertIsNotNone(secondary_address3)
        self.assertIsNotNone(secondary_address4)


if __name__ == '__main__':
    unittest.main()