from PIL import Image
import requests
import io
# Scarica l'immagine
response = requests.get('https://avatars.githubusercontent.com/u/109359355?v=4')
img = Image.open(io.BytesIO(response.content))

# Converti e salva come BMP
img.save('installer_assets/logo.bmp')