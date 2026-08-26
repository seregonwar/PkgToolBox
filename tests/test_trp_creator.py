"""Pure validation tests for the guided TRP creator."""
import unittest

from GUI.widgets.trp_creator_tab import trp_asset_role, validate_trp_assets


class TrpCreatorValidationTests(unittest.TestCase):
    def test_recognizes_configuration_and_artwork_roles(self):
        self.assertEqual(trp_asset_role("TROPCONF.SFM"), "Configuration")
        self.assertEqual(trp_asset_role("TROPCONF.ESFM"), "Configuration")
        self.assertEqual(trp_asset_role("ICON0.PNG"), "Set icon")
        self.assertEqual(trp_asset_role("GR01.PNG"), "Grade artwork")
        self.assertEqual(trp_asset_role("TROP00.PNG"), "Trophy artwork")
        self.assertIsNone(trp_asset_role("photo.jpg"))

    def test_requires_configuration_and_png(self):
        self.assertEqual(validate_trp_assets(["TROPCONF.SFM", "TROP00.PNG"]), [])
        self.assertTrue(any("configuration" in error for error in validate_trp_assets(["TROP00.PNG"])))
        self.assertTrue(any("PNG" in error for error in validate_trp_assets(["TROPCONF.SFM"])))

    def test_duplicate_archive_names_are_rejected_case_insensitively(self):
        errors = validate_trp_assets([
            "/first/TROPCONF.SFM",
            "/second/tropconf.sfm",
            "/first/TROP00.PNG",
        ])
        self.assertTrue(any("Duplicate" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
