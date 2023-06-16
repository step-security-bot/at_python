import unittest
from src.util import FromVerbBuilder, PKAMVerbBuilder, ScanVerbBuilder, UpdateVerbBuilder
from src.common import AtSign
from src.common.keys import SharedKey, PublicKey, PrivateHiddenKey, SelfKey

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

    def test_update_verb_builder(self):
        """
        Test Update Verb Builder.
        """
         
        builder = UpdateVerbBuilder()
        command = builder.set_key_name("test").set_shared_by("@bob").set_value("my Value 123").build()
        self.assertEqual("update:test@bob my Value 123", command)

        builder = UpdateVerbBuilder()
        command = builder.set_key_name("test").set_shared_by("@bob").set_shared_with("@bob").set_value("My value 123").build()
        self.assertEqual("update:@bob:test@bob My value 123", command)

        builder = UpdateVerbBuilder()
        command = builder.set_key_name("publickey").set_shared_by("@bob").set_is_public(True).set_value("my Value 123").build()
        self.assertEqual("update:public:publickey@bob my Value 123", command)

        builder = UpdateVerbBuilder()
        command = builder.set_key_name("publickey").set_shared_by("@alice").set_is_public(True).set_is_cached(True).set_value("my Value 123").build()
        self.assertEqual("update:cached:public:publickey@alice my Value 123", command)

        builder = UpdateVerbBuilder()
        command = builder.set_key_name("sharedkey").set_shared_by("@bob").set_shared_with("@alice").set_value("my Value 123").build()
        self.assertEqual("update:@alice:sharedkey@bob my Value 123", command)

        builder = UpdateVerbBuilder()
        sk1 = SharedKey("test", AtSign("@bob"), AtSign("@alice"))
        sk1.metadata.is_binary = True
        sk1.metadata.ttl = 1000 * 60 * 10  # 10 minutes
        command = builder.with_at_key(sk1, "myBinaryValue123456").build()
        self.assertEqual(
            "update:ttl:600000:isBinary:true:isEncrypted:true:@alice:test@bob myBinaryValue123456", command
        )

        builder = UpdateVerbBuilder()
        pk1 = PublicKey("test", AtSign("@bob"))
        pk1.metadata.is_cached = True
        command = builder.with_at_key(pk1, "myValue123").build()
        self.assertEqual("update:cached:public:test@bob myValue123", command)

        builder = UpdateVerbBuilder()
        sk2 = SelfKey("test", AtSign("@bob"))
        sk2.metadata.ttl = 1000 * 60 * 10  # 10 minutes
        command = builder.with_at_key(sk2, "myValue123").build()
        self.assertEqual("update:ttl:600000:isEncrypted:true:test@bob myValue123", command)

        builder = UpdateVerbBuilder()
        bob = AtSign("@bob")
        sk3 = SelfKey("test", bob, bob)
        sk3.metadata.ttl = 1000 * 60 * 10  # 10 minutes
        command = builder.with_at_key(sk3, "myValue123").build()
        self.assertEqual("update:ttl:600000:isEncrypted:true:@bob:test@bob myValue123", command)

if __name__ == '__main__':
    unittest.main()
