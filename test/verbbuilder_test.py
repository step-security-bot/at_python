import unittest
from src.util import FromVerbBuilder, PKAMVerbBuilder, ScanVerbBuilder

class AtVerbBuilderTest(unittest.TestCase):
    verbose = False

    def test_from_verb_builder(self):
        """
        Test From Verb Builder.
        """
        command = FromVerbBuilder().set_shared_by("@bob").build()
        self.assertEqual(command, "from:@bob")

    def test_pkam_verb_builder(self):
        """
        Test PKAM Verb Builder.
        """
        command = PKAMVerbBuilder().set_digest("digest").build()
        self.assertEqual(command, "pkam:digest")
    
    def test_scan_verb_builder(self):
        """
        Test Scan Verb Builder.
        """
        # Test not setting any parameters
        command = ScanVerbBuilder().build()
        self.assertEqual(command, "scan")

        # Test setting just regex
        command = ScanVerbBuilder().set_regex("*.public").build()
        self.assertEqual(command, "scan *.public")

        # Test setting just fromAtSign
        command = ScanVerbBuilder().set_from_at_sign("@other").build()
        self.assertEqual(command, "scan:@other")

        # Test setting just showHidden
        command = ScanVerbBuilder().set_show_hidden(True).build()
        self.assertEqual(command, "scan:showHidden:true")

        # Test setting regex & fromAtSign
        command = ScanVerbBuilder().set_regex("*.public").set_from_at_sign("@other").build()
        self.assertEqual(command, "scan:@other *.public")

        # Test setting regex & showHidden
        command = ScanVerbBuilder().set_regex("*.public").set_show_hidden(True).build()
        self.assertEqual(command, "scan:showHidden:true *.public")

        # Test setting fromAtSign & showHidden
        command = ScanVerbBuilder().set_from_at_sign("@other").set_show_hidden(True).build()
        self.assertEqual(command, "scan:showHidden:true:@other")

        # Test setting regex & fromAtSign & showHidden
        command = ScanVerbBuilder().set_regex("*.public").set_from_at_sign("@other").set_show_hidden(True).build()
        self.assertEqual(command, "scan:showHidden:true:@other *.public")
    
if __name__ == '__main__':
    unittest.main()
