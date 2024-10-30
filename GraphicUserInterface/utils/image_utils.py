from PIL import Image
from PyQt5.QtGui import QImage, QPixmap
import io

class ImageUtils:
    @staticmethod
    def load_and_scale_image(image_data, max_size):
        """Load and scale an image from bytes data"""
        try:
            image = Image.open(io.BytesIO(image_data))
            
            # Convert to RGB if needed
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            # Scale image
            image.thumbnail((max_size, max_size), Image.Resampling.LANCZOS)
            
            return image
        except Exception as e:
            raise Exception(f"Error loading/scaling image: {str(e)}")
    
    @staticmethod
    def convert_to_qpixmap(pil_image):
        """Convert PIL Image to QPixmap"""
        try:
            qimage = QImage(pil_image.tobytes(), 
                          pil_image.width, 
                          pil_image.height, 
                          3 * pil_image.width,
                          QImage.Format_RGB888)
            return QPixmap.fromImage(qimage)
        except Exception as e:
            raise Exception(f"Error converting to QPixmap: {str(e)}")

    @staticmethod
    def create_thumbnail(image_data, size=(300, 300)):
        """Create a thumbnail from image data"""
        try:
            image = ImageUtils.load_and_scale_image(image_data, max(size))
            return ImageUtils.convert_to_qpixmap(image)
        except Exception as e:
            raise Exception(f"Error creating thumbnail: {str(e)}")