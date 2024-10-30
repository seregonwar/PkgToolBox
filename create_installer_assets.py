from PIL import Image
import requests
import io
import os

def create_installer_assets():
    # Crea la directory se non esiste
    assets_dir = "installer_assets"
    if not os.path.exists(assets_dir):
        os.makedirs(assets_dir)
    
    # Scarica il logo da GitHub e convertilo in BMP
    response = requests.get('https://avatars.githubusercontent.com/u/109359355?v=4')
    logo = Image.open(io.BytesIO(response.content))
    logo.save(os.path.join(assets_dir, "logo.bmp"), "BMP")
    
    # Crea welcome.bmp (164x314 px)
    welcome = Image.new('RGB', (164, 314), 'white')
    welcome.paste(logo.resize((164, 164)), (0, 75))  # Centro il logo
    welcome.save(os.path.join(assets_dir, "welcome.bmp"), "BMP")
    
    # Crea header.bmp (150x57 px)
    header = Image.new('RGB', (150, 57), 'white')
    header.paste(logo.resize((57, 57)), (46, 0))  # Centro il logo
    header.save(os.path.join(assets_dir, "header.bmp"), "BMP")
    
    # Search for icon.ico in common locations
    icon_locations = [
        os.path.join("icons", "icon.ico"),
        os.path.join("assets", "icon.ico"),
        os.path.join("resources", "icon.ico"),
        "icon.ico"
    ]
    
    icon_found = False
    for icon_path in icon_locations:
        if os.path.exists(icon_path):
            import shutil
            shutil.copy2(icon_path, os.path.join(assets_dir, "icon.ico"))
            icon_found = True
            break
            
    if not icon_found:
        print("Error: icon.ico not found in any of the common locations")

if __name__ == "__main__":
    create_installer_assets()