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

        # Aggiungi altri parametri al main_dict
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

    def load_eboot(self, file_path):
        """Load info from eboot.bin file"""
        try:
            # Leggi il file eboot.bin
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Estrai le informazioni dal file eboot.bin
            # Questo è un esempio, dovrai adattarlo in base alla struttura reale del file
            info = {
                'Title': self.extract_string(data, 0x100, 64),
                'Version': self.extract_string(data, 0x140, 8),
                'Category': self.extract_string(data, 0x148, 16),
                'Content ID': self.extract_string(data, 0x158, 36),
                'System Version': f"{data[0x160]:d}.{data[0x161]:02d}"
            }
            
            self.main_dict = info
            return info
            
        except Exception as e:
            raise Exception(f"Error loading eboot.bin: {str(e)}")

    def load_param_json(self, file_path):
        """Load info from param.json file"""
        try:
            import json
            with open(file_path, 'r', encoding='utf-8') as f:
                self.main_dict = json.load(f)
            return self.main_dict
            
        except Exception as e:
            raise Exception(f"Error loading param.json: {str(e)}")

    def extract_string(self, data, offset, length):
        """Extract null-terminated string from binary data"""
        try:
            string_bytes = data[offset:offset+length]
            null_pos = string_bytes.find(b'\x00')
            if null_pos != -1:
                string_bytes = string_bytes[:null_pos]
            return string_bytes.decode('utf-8', errors='ignore').strip()
        except Exception:
            return ""

    def save_eboot(self, file_path, changes):
        """Save changes to eboot.bin file"""
        try:
            # Leggi il file esistente
            with open(file_path, 'rb') as f:
                data = bytearray(f.read())
            
            # Applica le modifiche
            for key, value in changes.items():
                if key == "Title":
                    self.write_string(data, 0x100, value, 64)
                elif key == "Version":
                    self.write_string(data, 0x140, value, 8)
                elif key == "Category":
                    self.write_string(data, 0x148, value, 16)
                elif key == "Content ID":
                    self.write_string(data, 0x158, value, 36)
                elif key == "System Version":
                    try:
                        major, minor = map(int, value.split('.'))
                        data[0x160] = major
                        data[0x161] = minor
                    except:
                        pass
            
            # Salva il file modificato
            with open(file_path, 'wb') as f:
                f.write(data)
                
        except Exception as e:
            raise Exception(f"Error saving eboot.bin: {str(e)}")

    def save_param_json(self, file_path, changes):
        """Save changes to param.json file"""
        try:
            # Leggi il file esistente
            with open(file_path, 'r', encoding='utf-8') as f:
                param_data = json.load(f)
            
            # Applica le modifiche
            for key, value in changes.items():
                if key == "Title Name" and "localizedParameters" in param_data:
                    param_data["localizedParameters"]["en-US"]["titleName"] = value
                elif key == "Content Version":
                    param_data["contentVersion"] = value
                elif key == "Title ID":
                    param_data["titleId"] = value
                elif key == "Content ID":
                    param_data["contentId"] = value
                elif key == "Required System Software Version":
                    param_data["requiredSystemSoftwareVersion"] = f"0{value.replace('.', '')}"
                elif key == "SDK Version":
                    param_data["sdkVersion"] = f"0{value.replace('.', '')}"
                else:
                    # Gestisci altri parametri
                    if "_" in key:
                        # Gestisci parametri nidificati
                        main_key, sub_key = key.split("_", 1)
                        if main_key in param_data:
                            if isinstance(param_data[main_key], dict):
                                param_data[main_key][sub_key] = value
                    else:
                        # Parametri diretti
                        param_data[key] = value
            
            # Salva il file modificato
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(param_data, f, indent=4, ensure_ascii=False)
                
        except Exception as e:
            raise Exception(f"Error saving param.json: {str(e)}")

    def write_string(self, data, offset, string, max_length):
        """Write string to binary data with null termination"""
        try:
            # Converti la stringa in bytes
            string_bytes = string.encode('utf-8')
            # Tronca se necessario
            if len(string_bytes) > max_length - 1:
                string_bytes = string_bytes[:max_length-1]
            # Aggiungi terminatore null
            string_bytes += b'\x00' * (max_length - len(string_bytes))
            # Scrivi nel buffer
            data[offset:offset+max_length] = string_bytes
        except Exception as e:
            raise Exception(f"Error writing string: {str(e)}")

def get_ps5_game_info(path):
    ps5_info = PS5GameInfo()
    return ps5_info.process(path)