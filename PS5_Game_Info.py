#Module created by sinajet, implemented by SeregonWar in PkgToolBox.
import json
import os
from pathlib import Path
import io

class PS5GameInfo:
    def __init__(self):
        self.gPath = ''
        self.gVer = ''
        self.region = ''
        self.gname = ''
        self.sVer = ''
        self.Fcheck = ''
        self.Fsize = ''
        self.main_dict = {}

    def convert_bytes(self, size):
        for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return '%3.1f%s' % (size, x)
            size /= 1024.0
        return size

    def folder_size(self, path='.'):
        total_size = 0
        path = Path(path)
        for item in path.glob('**/*'):
            if item.is_file():
                total_size += item.stat().st_size
        return self.convert_bytes(total_size)

    def region_convertor(self, R):
        if R == "UP":
            return "US"
        elif R == "EP":
            return "EU"
        else:
            return R

    def version_corrector(self, v):
        return v[:2] + "." + v[2:4] + "." + v[4:6] + "." + v[6:8]

    def param_table_inputer(self):
        with open(os.path.join(self.gPath, "sce_sys/param.json"), "r") as f:
            dict_param = json.load(f)

        if "localizedParameters" in dict_param:
            self.gname = dict_param["localizedParameters"]["en-US"]["titleName"].replace("â€", "-")
        else:
            self.gname = ""

        if "contentVersion" in dict_param:
            self.gVer = dict_param["contentVersion"]
            dict_param.pop("contentVersion")
        else:
            self.gVer = ""

        if "titleId" in dict_param:
            title_id = dict_param["titleId"]
            dict_param.pop("titleId")
        else:
            title_id = ""

        if "contentId" in dict_param:
            content_id = dict_param["contentId"]
            self.region = self.region_convertor(content_id[:2])
            dict_param.pop("contentId")
        else:
            content_id = ""
            self.region = ""

        if "requiredSystemSoftwareVersion" in dict_param:
            sys_ver = self.version_corrector(dict_param["requiredSystemSoftwareVersion"][2:])
            self.sVer = sys_ver[:5]
            dict_param.pop("requiredSystemSoftwareVersion")
        else:
            sys_ver = ""
            self.sVer = ""

        if "sdkVersion" in dict_param:
            sdk_ver = self.version_corrector(dict_param["sdkVersion"][2:])
            dict_param.pop("sdkVersion")
        else:
            sdk_ver = ""

        self.main_dict = {
            "Title Name": self.gname,
            "Content Version": self.gVer,
            "Title ID": title_id,
            "Content ID": content_id,
            "Required System Software Version": sys_ver,
            "SDK Version": sdk_ver,
            "Fake Self": "True" if self.Fcheck == '(<span style=" color:#55aa00;">Fake</span>)' else "False"
        }

        # Aggiungi altri parametri al main_dict
        for key, value in dict_param.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    self.main_dict[f"{key}_{sub_key}"] = str(sub_value)
            else:
                self.main_dict[key] = str(value)

    def eboot_fake_checker(self):
        with open(os.path.join(self.gPath, "eboot.bin"), "r", errors="ignore") as f:
            eboot_txt = f.read()
        if "ELF" in eboot_txt[:len("ELF")]:
            return '(<span style=" color:#036494;">official</span>)'
        else:
            return '(<span style=" color:#55aa00;">Fake</span>)'

    def eboot_fake_checker_from_data(self, eboot_data):
        eboot_txt = eboot_data[:100].decode('utf-8', errors='ignore')
        if "ELF" in eboot_txt[:len("ELF")]:
            return '(<span style=" color:#036494;">official</span>)'
        else:
            return '(<span style=" color:#55aa00;">Fake</span>)'

    def param_table_inputer_from_data(self, param_data):
        dict_param = json.loads(param_data.decode('utf-8'))

        if "localizedParameters" in dict_param:
            self.gname = dict_param["localizedParameters"]["en-US"]["titleName"].replace("â€", "-")
        else:
            self.gname = ""

        if "contentVersion" in dict_param:
            self.gVer = dict_param["contentVersion"]
            dict_param.pop("contentVersion")
        else:
            self.gVer = ""

        if "titleId" in dict_param:
            title_id = dict_param["titleId"]
            dict_param.pop("titleId")
        else:
            title_id = ""

        if "contentId" in dict_param:
            content_id = dict_param["contentId"]
            self.region = self.region_convertor(content_id[:2])
            dict_param.pop("contentId")
        else:
            content_id = ""
            self.region = ""

        if "requiredSystemSoftwareVersion" in dict_param:
            sys_ver = self.version_corrector(dict_param["requiredSystemSoftwareVersion"][2:])
            self.sVer = sys_ver[:5]
            dict_param.pop("requiredSystemSoftwareVersion")
        else:
            sys_ver = ""
            self.sVer = ""

        if "sdkVersion" in dict_param:
            sdk_ver = self.version_corrector(dict_param["sdkVersion"][2:])
            dict_param.pop("sdkVersion")
        else:
            sdk_ver = ""

        self.main_dict = {
            "Title Name": self.gname,
            "Content Version": self.gVer,
            "Title ID": title_id,
            "Content ID": content_id,
            "Required System Software Version": sys_ver,
            "SDK Version": sdk_ver,
            "Fake Self": "True" if self.Fcheck == '(<span style=" color:#55aa00;">Fake</span>)' else "False"
        }

        
        for key, value in dict_param.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    self.main_dict[f"{key}_{sub_key}"] = str(sub_value)
            else:
                self.main_dict[key] = str(value)

    def process(self, path):
        self.gPath = path
        if os.path.exists(os.path.join(self.gPath, "eboot.bin")):
            self.Fcheck = self.eboot_fake_checker()
            if os.path.exists(os.path.join(self.gPath, "sce_sys/param.json")):
                self.param_table_inputer()
            self.Fsize = self.folder_size(Path(self.gPath))
            return self.main_dict
        else:
            return {"error": "Can't find eboot file. Please select correct path."}

def get_ps5_game_info(path):
    ps5_info = PS5GameInfo()
    return ps5_info.process(path)