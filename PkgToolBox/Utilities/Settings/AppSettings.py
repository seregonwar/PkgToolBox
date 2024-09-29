from PyQt5.QtGui import QColor

class AppSettings:
    def __init__(self):
        self.pkg_directories = []
        self.scan_recursive = False
        self.play_bgm = False
        self.show_directory_settings_at_startup = True
        self.auto_sort_row = False
        self.local_server_ip = ""
        self.ps4_ip = ""
        self.nodejs_installed = False
        self.http_server_installed = False
        self.official_update_download_directory = ""
        self.pkg_color_label = False
        self.game_pkg_forecolor = QColor(0xDDDDDD)
        self.patch_pkg_forecolor = QColor(0xDDDDDD)
        self.addon_pkg_forecolor = QColor(0xDDDDDD)
        self.app_pkg_forecolor = QColor(0xDDDDDD)
        self.game_pkg_backcolor = QColor(0x333333)
        self.patch_pkg_backcolor = QColor(0x333333)
        self.addon_pkg_backcolor = QColor(0x333333)
        self.app_pkg_backcolor = QColor(0x333333)
        self.rename_custom_format = ""
        self.ps5bc_json_download_date = ""
        self.psvr_neo_ps5bc_check = False
        self.pkg_titleId_column = True
        self.pkg_contentId_column = True
        self.pkg_region_column = True
        self.pkg_minimum_firmware_column = True
        self.pkg_version_column = True
        self.pkg_type_column = True
        self.pkg_category_column = True
        self.pkg_size_column = True
        self.pkg_location_column = True
        self.pkg_backport_column = True