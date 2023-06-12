import unittest
import socket
from src.common import AtSign
from src.connections import AtRootConnection, AtSecondaryConnection, Address


class AtSecondaryConnectionTest(unittest.TestCase):
    verbose = False

    def test_secondary_connection(self):
        """
        Test secondary connection establishment.
        """
        root_connection = AtRootConnection.get_instance(verbose=AtSecondaryConnectionTest.verbose)
        secondary_address = root_connection.find_secondary(AtSign("@27barracuda"))
        secondary_connection = AtSecondaryConnection(secondary_address, verbose=AtSecondaryConnectionTest.verbose)
        secondary_connection.connect()
        self.assertTrue(secondary_connection.is_connected())
        secondary_connection.disconnect()

    def test_secondary_connection_failure(self):
        """
        Test secondary connection failure.
        """
        try:
            root_connection = AtRootConnection.get_instance(verbose=AtSecondaryConnectionTest.verbose)
            secondary_address = root_connection.find_secondary(AtSign("@27barracuda"))
            wrong_address = Address(secondary_address.host+"0", secondary_address.port)
            secondary_connection = AtSecondaryConnection(wrong_address, verbose=AtSecondaryConnectionTest.verbose)
            secondary_connection.connect()
            secondary_connection.disconnect()
        except Exception as e:
            self.assertTrue(isinstance(e, socket.gaierror))

    def test_multiple_secondary_connections(self):
        """
        Test multiple secondary connections.
        """
        root_connection = AtRootConnection.get_instance(verbose=AtSecondaryConnectionTest.verbose)
        secondary_address1 = root_connection.find_secondary(AtSign("@27barracuda"))
        secondary_connection1 = AtSecondaryConnection(secondary_address1, verbose=AtSecondaryConnectionTest.verbose)
        secondary_connection1.connect()
        secondary_address2 = root_connection.find_secondary(AtSign("@19total67"))
        secondary_connection2 = AtSecondaryConnection(secondary_address2, verbose=AtSecondaryConnectionTest.verbose)
        secondary_connection2.connect()
        secondary_address3 = root_connection.find_secondary(AtSign("@wildgreen"))
        secondary_connection3 = AtSecondaryConnection(secondary_address3, verbose=AtSecondaryConnectionTest.verbose)
        secondary_connection3.connect()
        secondary_address4 = root_connection.find_secondary(AtSign("@colin"))
        secondary_connection4 = AtSecondaryConnection(secondary_address4, verbose=AtSecondaryConnectionTest.verbose)
        secondary_connection4.connect()

        self.assertIsNotNone(secondary_connection1)
        self.assertIsNotNone(secondary_connection2)
        self.assertIsNotNone(secondary_connection3)
        self.assertIsNotNone(secondary_connection4)
        secondary_connection1.disconnect()
        secondary_connection2.disconnect()
        secondary_connection3.disconnect()
        secondary_connection4.disconnect()


if __name__ == '__main__':
    unittest.main()
