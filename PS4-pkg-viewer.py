import tkinter as tk
from tkinterdnd2 import DND_FILES, TkinterDnD
import re, os, shutil, logging
from package import Package
from tkinter import ttk, Label, filedialog
from PIL import ImageTk, Image

OUTPUT_FOLDER = "._temp_output"
Hexpattern = re.compile(r'[^\x20-\x7E]')

class Mainapp(TkinterDnD.Tk):
    
    def DragNDrop(self, event):
        self.file_path = event.data.strip('{}')
        if self.file_path:
            self.package = Package(self.file_path)
            self.process_pkg()

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("PKG Files", "*.pkg")])
        if self.file_path:
            self.package = Package(self.file_path)
            self.process_pkg()
        else:
            print("Aucun fichier PKG sélectionné.")
    
    def process_pkg(self):
        icon0 = False
        if self.package is not None:
            files_to_extract = [
                {"file_id": 0x1000, "filename": "param.sfo"},
                {"file_id": 0x1200, "filename": "icon0.png"}
            ]
            
            self.pkg_icon0.configure(image="")
            script_dir = os.path.dirname(os.path.abspath(__file__))
            output_folder_path = os.path.join(script_dir, OUTPUT_FOLDER)
            os.makedirs(output_folder_path, exist_ok=True)

            for file_info in files_to_extract:
                file_id = file_info["file_id"]
                filename = file_info["filename"]

                output_file_path = os.path.join(output_folder_path, filename)

                try:
                    self.package.extract(file_id, output_file_path)
                    if filename == "icon0.png":
                        icon0 = True
                        #logging.info("File Name:  icon0.png")
                except ValueError as e:
                    #logging.info("icon0.png : Extraction impossible")
                    pass
                
            if icon0:
                icon0_path = os.path.join(output_folder_path, "icon0.png")
                self.display_img(icon0_path)
            sfo_path = os.path.join(output_folder_path, "param.sfo")

            if os.path.exists(sfo_path):
                sfo_info = self.sfo_offset_map(sfo_path)
                self.update_idletasks()
                self.geometry(self.geometry())
        else:
            pass

    def display_img(self, image_path):
        image = Image.open(image_path)
        image = image.resize((199, 198))
        icon0 = ImageTk.PhotoImage(image)
        self.pkg_icon0.configure(image=icon0)
        self.pkg_icon0.image = icon0

    def side_menu(self, clk_action):
        item_selection = self.treeview.selection()
        if item_selection:
            selected_item = self.treeview.item(item_selection, "values")
            if selected_item:
                self.context_menu.post(clk_action.x_root, clk_action.y_root)

    def Side_action(self):
        item_selection = self.treeview.selection()
        if item_selection:
            selected_item = self.treeview.item(item_selection, "values")
            if selected_item:
                self.clipboard_clear()
                self.clipboard_append(selected_item[0])
                self.update()

    def sfo_offset_map(self, file_path):
        with open(file_path, 'rb') as file:
            sfo = file.read()

        offset1 = sfo.find(b"\x00VERSION") + 8
        data1 = sfo[offset1:offset1 + 14].decode("ascii", errors='ignore')

        offset2 = sfo.find(b"\x5F00-") - 20
        data2 = sfo[offset2:offset2 + 2].decode("ascii", errors='ignore')

        offset3 = sfo.find(b"\x5F00-") - 16
        data3 = sfo[offset3:offset3 + 36].decode("ascii", errors='ignore')

        offset4 = sfo.find(b"\x2Csdk_ver=") + 9
        data4 = sfo[offset4:offset4 + 8].decode("ascii", errors='ignore')
        data4 = data4[:2] + "." + data4[2:4]

        offset5 = sfo.find(b"\x00\x00\x00\x00CUSA") - 128
        data5 = sfo[offset5:offset5 + 64].decode("ascii", errors='ignore')
        data5 = re.sub(Hexpattern, '', data5)

        offset6 = sfo.find(b"\x5F00-") - 9
        data6 = sfo[offset6:offset6 + 9].decode("ascii", errors='ignore')

        offset7 = sfo.find(b"\x00c_date") + 1
        data7 = sfo[offset7:offset7 + 264].decode("ascii", errors='ignore')
        
        pkg_size_fmt = os.path.getsize(self.file_path)
        pkg_size_formatted = self.pkg_size_fmt(pkg_size_fmt)

        sfo_dict = {
            "APP_TYPE": data2,
            "CONTENT_ID": data3,
            "SDK_version": data4,
            "TITLE_ID": data6,
            "APP_VER": data1,
            "TITLE": data5,
            "PUBTOOLINFO": data7,
            "Size": pkg_size_formatted,
        }

        if data2 == "gp":
            [sfo_dict.pop(key, None) for key in ["SDK_version"]]
        elif data2 == "ac":
            [sfo_dict.pop(key, None) for key in ["SDK_version", "APP_VER"]]
        
        if len(data5) <= 3:
            [sfo_dict.pop(key, None) for key in ["TITLE", "SDK_version"]]

        self.treeview.delete(*self.treeview.get_children())

        for key, value in sfo_dict.items():
            out_data = re.sub(Hexpattern, '', value)
            if out_data == "gd":
                out_data = "Game(gd)"
            elif out_data == "gp":
                out_data = "Patch(gp)"
            elif out_data == "ac":
                out_data = "Addon(ac)"
        
            self.treeview.insert("", "end", text=key, values=(out_data,))

    def pkg_size_fmt(self, sbytes):
        size_fmt = ["bytes", "KB", "MB", "GB"]
        size_max = 1024

        for unit in size_fmt:
            if sbytes < size_max:
                return f"{sbytes:.2f} {unit}"
            sbytes /= size_max
        return f"{sbytes:.2f} {size_fmt[-1]}"
    
    def close(self):
        # delete "_temp_output"
        output_folder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT_FOLDER)
        shutil.rmtree(output_folder_path, ignore_errors=True)
        self.destroy()

    def __init__(self):
        super().__init__()
        self.file_path = None
        self.package = None
        self.resizable(0,0)
        self.title("PS4-pkg-viewer")
        
        for index in [0, 1, 2]:
            self.columnconfigure(index=index, weight=1)
            self.rowconfigure(index=index, weight=1)

        # icon0 & Frame
        self.pkg_icon0Frame = ttk.LabelFrame(self, text='icon0', labelanchor='n')
        self.pkg_icon0Frame.grid(row=0, column=0, padx=3, pady=4)
        self.pkg_icon0Frame.drop_target_register(DND_FILES)
        self.pkg_icon0Frame.dnd_bind('<<Drop>>', self.DragNDrop)

        self.pkg_icon0 = Label(self.pkg_icon0Frame, text='Load file...', padx=68, pady=90)
        self.pkg_icon0.grid(row=0, column=0)

        # Treeview
        self.treeview = ttk.Treeview(self, columns=("Value"), selectmode='browse')
        self.treeview.heading("#0", text="Key")
        self.treeview.heading("Value", text="Informations")
        self.treeview.grid(row=0, column=1, pady=3, sticky="s")
        self.treeview.column("#0", anchor="w", width=110)
        self.treeview.column("Value", anchor="w", width=400)
        
        # DragNDrop action 
        self.treeview.drop_target_register(DND_FILES)
        self.treeview.dnd_bind('<<Drop>>', self.DragNDrop)
       
        # Treeview context menu and action 
        self.treeview.bind("<Button-2>", self.side_menu)
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self.Side_action)

        # Button 
        self.select_file_button = ttk.Button(self, text="Select pkg file", command=self.select_file)
        self.select_file_button.grid(row=1, column=1, pady=3)
        
        # Version 
        self.mainapp_version = ttk.Label(self, text="Ver : 23.10.2")
        self.mainapp_version.grid(row=1, column=0, sticky='w', padx=3)

if __name__ == "__main__":
    mainapp = Mainapp()
    mainapp.protocol("WM_DELETE_WINDOW", mainapp.close)
    mainapp.mainloop()
