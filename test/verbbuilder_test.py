import unittest
from src.util import FromVerbBuilder, PKAMVerbBuilder

class AtSecondaryConnectionTest(unittest.TestCase):
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
        

    
if __name__ == '__main__':
    unittest.main()
