from tkinter import ttk, Tk, Label,filedialog
from PIL import ImageTk, Image, ImageDraw, ImageOps
import tkinter as tk
import os
from package import Package
import shutil
import re

OUTPUT_FOLDER = "._temp_output"
pattern = re.compile(r'[^\x20-\x7E]')

class Application(Tk):

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("PKG Files", "*.pkg")])
        if self.file_path:
            self.package = Package(self.file_path)

        if self.package is not None:
            files_to_extract = [
                {"file_id": 0x1000, "filename": "param.sfo"},{"file_id": 0x1200, "filename": "icon0.png"}
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
            sfo_path = os.path.join(output_folder_path, "param.sfo")
            print(sfo_path)

            if os.path.exists(icon0_path):
                self.display_image(icon0_path)

            if os.path.exists(sfo_path):
                sfo_info = self.extract_sfo(sfo_path)
                self.update_idletasks()
                self.geometry(self.geometry())
        else:
            print("Aucun fichier PKG sélectionné.")

    def format_pkg_size(self, size_in_bytes):
        # Define the size units and their respective thresholds
        size_units = ["bytes", "KB", "MB", "GB"]
        threshold = 1024

        # Iterate through the units and divide the size until it's below the threshold
        for unit in size_units:
            if size_in_bytes < threshold:
                return f"{size_in_bytes:.2f} {unit}"
            size_in_bytes /= threshold
        return f"{size_in_bytes:.2f} {size_units[-1]}"

        # Adjust the corner radius as needed
    def display_image(self, image_path):
        image = Image.open(image_path)
        image = image.resize((210, 205))
        photo = ImageTk.PhotoImage(image)
        self.pkg_image.configure(image=photo)
        self.pkg_image.image = photo

    def extract_sfo(self, file_path):
        with open(file_path, 'rb') as file:
            sfo = file.read()

        offset1 = sfo.find(b"\x00VERSION") + 8
        data1 = sfo[offset1:offset1 + 14].decode("ascii", errors='ignore')

        offset2 = sfo.find(b"\x5F00-") - 20
        data2 = sfo[offset2:offset2 + 4].decode("ascii", errors='ignore')

        offset3 = sfo.find(b"\x5F00-") - 16
        data3 = sfo[offset3:offset3 + 36].decode("ascii", errors='ignore')

        offset5 = sfo.find(b"\x2Csdk_ver=") + 9
        data5 = sfo[offset5:offset5 + 8].decode("ascii", errors='ignore')
        data5 = data5[:2] + "." + data5[2:4]

        offset7 = sfo.find(b"\x00\x00\x00\x00CUSA") - 128
        data7 = sfo[offset7:offset7 + 64].decode("ascii", errors='ignore')

        offset8 = sfo.find(b"\x5F00-") - 9
        data8 = sfo[offset8:offset8 + 9].decode("ascii", errors='ignore')

        offset9 = sfo.find(b"\x00c_date") + 1
        data9 = sfo[offset9:offset9 + 264].decode("ascii", errors='ignore')
        
        pkg_size = os.path.getsize(self.file_path)
        pkg_size_formatted = self.format_pkg_size(pkg_size)

        sfo_dict = {
            "APP_TYPE": data2,
            "CONTENT_ID": data3,
            "SDK_version": data5,
            "TITLE_ID": data8,
            "APP_VER": data1,
            "TITLE": data7,
            "PUBTOOLINFO": data9,
            "Size": pkg_size_formatted,
        }

        #print(sfo_dict)

        self.treeview.delete(*self.treeview.get_children())  # Clear the Treeview first
        for key, value in sfo_dict.items():
            out_data = re.sub(pattern, '', value)
            if key == "APP_TYPE":
                if out_data == "gd":
                    out_data = "Game(gd)"
                elif out_data == "gp":
                    out_data = "Patch(gp)"
                elif out_data == "ac":
                    out_data = "Addon(ac)"
            self.treeview.insert("", "end", text=key, values=(out_data,))
    
    def __init__(self):
        super().__init__()
        self.file_path = None
        self.package = None
        self.resizable(0,0)
        self.title("PS4-pkg-viewer-python")
        
        for index in [0, 1, 2]:
            self.columnconfigure(index=index, weight=1)
            self.rowconfigure(index=index, weight=1)

        # Create pkg_imageFrame
        self.pkg_imageFrame = ttk.LabelFrame(self,text='icon0',padding=(2),labelanchor='n')
        self.pkg_imageFrame.grid(row=0, column=0)
        
        self.pkg_image = Label(self.pkg_imageFrame,text='Load file...',padx=80,pady=90)
        self.pkg_image.grid(row=0, column=0)

        # Create a Treeview for package information
        self.treeview = ttk.Treeview(self, columns=("Value"),selectmode='extended')
        self.treeview.heading("#0", text="Key")
        self.treeview.heading("Value", text="Informations")
        self.treeview.grid(row=0, column=1, pady=1,sticky="nsew")
        self.treeview.column("#0", anchor="w", width=110)
        self.treeview.column("Value", anchor="w", width=400)

        # Button 
        self.select_file_button = ttk.Button(self, text="Select pkg file", command=self.select_file)
        self.select_file_button.grid(row=1, column=1, pady=8)
        
        app_version= ttk.Label(self, text="Ver : 23.8.4")
        app_version.grid(row=1, column=0,sticky='w',padx=3)

        Traduction = ["","English", "Francais"]
        e = tk.StringVar(value=Traduction[1])

        optionmenu = ttk.OptionMenu(self, e, *Traduction)
        optionmenu.grid(row=1, column=1,padx=3,sticky='e',)

    def on_closing(self):
        # Remove the "_temp_output" directory
        output_folder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT_FOLDER)
        shutil.rmtree(output_folder_path, ignore_errors=True)
        self.destroy()

if __name__ == "__main__":
    app = Application()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
