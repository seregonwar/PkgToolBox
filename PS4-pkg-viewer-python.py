from tkinter import Tk, Label, Button, Frame, filedialog
from PIL import ImageTk, Image, ImageDraw, ImageOps
import os
from package import Package
import shutil
import re


OUTPUT_FOLDER = "._temp_output"
pattern = re.compile(r'[^\x20-\x7E]')

class Application(Tk):
    def __init__(self):
        super().__init__()
        self.file_path = None
        self.package = None
        self.resizable(1,1)
        self.title("PS4-pkg-viewer-python")

        self.image_label = Label(self)
        self.image_label.pack(pady=10)

        label_frame = Frame(self)
        label_frame.pack(pady=5)
        
        self.APP_TYPE = Label(label_frame, text="")
        self.CONTENT_ID = Label(label_frame, text="")
        self.TITLE_ID = Label(label_frame, text="")
        self.TITLE = Label(label_frame, text="")
        self.APP_VER = Label(label_frame, text="")
        self.SDK_version = Label(label_frame, text="")
        self.PUBTOOLINFO = Label(label_frame, text="", wraplength=500, justify="center")
        self.file_size_label = Label(label_frame, text="")

        self.select_file_button = Button(self, text="Sélectionner un fichier PKG", command=self.select_file)
        self.select_file_button.pack(pady=5)


    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("PKG Files", "*.pkg")])
        if self.file_path:
            self.package = Package(self.file_path)
            

        if self.package is not None:
            files_to_extract = [
                {"file_id": 0x1000, "filename": "param.sfo"},
                {"file_id": 0x1200, "filename": "icon0.png"}
            ]
            
            script_directory = os.path.dirname(os.path.abspath(__file__))
            output_folder_path = os.path.join(script_directory, OUTPUT_FOLDER)
            os.makedirs(output_folder_path, exist_ok=True)

            for file_info in files_to_extract:
                file_id = file_info["file_id"]
                filename = file_info["filename"]
            
                output_file_path = os.path.join(output_folder_path, filename)
                self.package.extract(file_id, output_file_path)

            icon0_path = os.path.join(output_folder_path, "icon0.png")
            param_sfo_path = os.path.join(output_folder_path, "param.sfo")

            if os.path.exists(icon0_path):
                self.display_image(icon0_path)

            if os.path.exists(param_sfo_path):
                sfo_info = self.extract_sfo(param_sfo_path)
                self.update_idletasks()
                self.geometry(self.geometry())

            file_size = os.path.getsize(self.file_path)
            file_size_formatted = self.format_file_size(file_size)      # Convert the file size to MB, KB, or GB

            self.file_size_label.config(text=f"Content size: {file_size_formatted}")

        else:
            print("Aucun fichier PKG sélectionné.")

    def format_file_size(self, size_in_bytes):
        # Define the size units and their respective thresholds
        size_units = ["bytes", "KB", "MB", "GB"]
        threshold = 1024

        # Iterate through the units and divide the size until it's below the threshold
        for unit in size_units:
            if size_in_bytes < threshold:
                return f"{size_in_bytes:.2f} {unit}"
            size_in_bytes /= threshold
        return f"{size_in_bytes:.2f} {size_units[-1]}"  # If the size exceeds the largest unit (GB), return it in GB

    def display_image(self, image_path):
        image = Image.open(image_path)
        image = image.resize((300, 300))
        rounded_image = self.round_corners(image, 20)  # Adjust the corner radius as needed
        photo = ImageTk.PhotoImage(rounded_image)
        self.image_label.configure(image=photo)
        self.image_label.image = photo

    def round_corners(self, image, radius):
        width, height = image.size
        mask = Image.new("L", (width, height), 0)
        draw = ImageDraw.Draw(mask)
        draw.rounded_rectangle((0,0, width, height), radius, fill=255)
        result = ImageOps.fit(image, mask.size, centering=(0.5, 0.5))
        result.putalpha(mask)
        return result

    def extract_sfo(self, file_path):
        with open(file_path, 'rb') as file:
            content = file.read()

        offset1 = content.find(b"\x00VERSION") + 8
        data1 = content[offset1:offset1+14].decode("ascii", errors='ignore')

        offset2 = content.find(b"\x5F00-") - 20
        data2 = content[offset2:offset2+4].decode("ascii", errors='ignore')

        offset3 = content.find(b"\x5F00-") - 16
        data3 = content[offset3:offset3+37].decode("ascii", errors='ignore')

        offset5 = content.find(b"\x2Csdk_ver=") +9 
        data5 = content[offset5:offset5+8].decode("ascii", errors='ignore')
        data5 = data5[:2] + "." + data5[2:4]

        offset7 = content.find(b"\x00\x00\x00\x00CUSA") -128
        data7 = content[offset7:offset7+64].decode("ascii", errors='ignore')

        offset8 = content.find(b"\x5F00-") - 9
        data8 = content[offset8:offset8+9].decode("ascii", errors='ignore')

        offset9 = content.find(b"\x00c_date") + 1
        data9 = content[offset9:offset9+264].decode("ascii", errors='ignore')

        data_dict = {
            "APP_VER": data1,
            "APP_TYPE": data2,
            "CONTENT_ID": data3,
            "SDK_version": data5,
            "TITLE": data7,
            "TITLE_ID": data8,
            "PUBTOOLINFO": data9
        }

        print(data2)

        for key, value in data_dict.items():
            out_data = re.sub(pattern, '', value)
            if key == "APP_TYPE":
                if out_data == "gd":
                    out_data = "Game(gd)"
                    self.APP_TYPE.pack(pady=2)
                    self.CONTENT_ID.pack(pady=2)
                    self.APP_VER.pack(pady=2)
                    self.TITLE_ID.pack(pady=2)
                    self.TITLE.pack(pady=2)
                    self.SDK_version.pack(pady=2)
                    self.PUBTOOLINFO.pack(pady=2, fill="both", expand=True)
                    self.file_size_label.pack(pady=2, fill="both", expand=True)

                elif out_data == "gp":
                    out_data = "Patch(gp)"

                    self.APP_TYPE.pack(pady=2)
                    self.CONTENT_ID.pack(pady=2)
                    self.APP_VER.pack(pady=2)
                    self.TITLE_ID.pack(pady=2)
                    self.TITLE.pack(pady=2)
                    self.SDK_version.pack(pady=2)
                    self.PUBTOOLINFO.pack(pady=2, fill="both", expand=True)
                    self.file_size_label.pack(pady=2, fill="both", expand=True)

                elif out_data == "ac":
                    out_data = "Addon(ac)"
                    self.APP_TYPE.pack(pady=2)
                    self.CONTENT_ID.pack(pady=2)
                    self.TITLE_ID.pack(pady=2)
                    self.TITLE.pack(pady=2)
                    self.PUBTOOLINFO.pack(pady=2, fill="both", expand=True)
                    self.SDK_version.pack_forget()
                    self.APP_VER.pack_forget()
                    self.file_size_label.pack(pady=2, fill="both", expand=True)
                    
            label = getattr(self, key)
            label.config(text=f"{key}: {out_data}")

    def on_closing(self):
        # Supprimer le répertoire "_temp_output"
        output_folder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT_FOLDER)
        shutil.rmtree(output_folder_path, ignore_errors=True)
        self.destroy()

if __name__ == "__main__":
    app = Application()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
