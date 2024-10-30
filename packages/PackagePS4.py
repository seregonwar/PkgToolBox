import os
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long
from Crypto.Random import get_random_bytes

# Constants
AES_KEY_LEN_128 = 16

# AES context
class AES_ctx:
    def __init__(self):
        self.key = None
        self.iv = None

    def set_key(self, key):
        self.key = key

    def set_iv(self, iv):
        self.iv = iv

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(pad(data, AES.block_size))

    def decrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(data), AES.block_size)

# AES functions
def AES_set_key(ctx, key, key_len):
    ctx.key = key[:key_len]
    ctx.iv = get_random_bytes(AES.block_size)

def AES_cbc_encrypt(ctx, data, out):
    out[:] = ctx.encrypt(data)

def AES_cbc_decrypt(ctx, data, out):
    out[:] = ctx.decrypt(data)

class PackagePS4:
    def __init__(self, original_file):
        self.original_file = original_file

    def is_encrypted(self):
        """Check if package is encrypted"""
        try:
            # Controlla se il PKG è cifrato verificando il flag di crittografia
            with open(self.original_file, 'rb') as f:
                # Vai all'offset del flag di crittografia (0x1A nel header PS4)
                f.seek(0x1A)
                # Leggi il flag (2 byte)
                encryption_flag = int.from_bytes(f.read(2), byteorder='little')
                # Se il flag è diverso da 0, il PKG è cifrato
                return encryption_flag != 0
        except Exception as e:
            logging.error(f"Error checking encryption: {str(e)}")
            return False

    def extract_with_passcode(self, passcode, output_dir):
        """Extract encrypted PKG with passcode"""
        if not self.is_encrypted():
            raise ValueError("Package is not encrypted")
            
        try:
            # Verifica il formato del passcode
            if len(passcode) != 32:
                raise ValueError("Invalid passcode length")
                
            # Converti il passcode in chiave AES
            key = bytes.fromhex(passcode)
            
            # Decripta il PKG usando la chiave
            self.decrypt_pkg(key, output_dir)
            
            return True
        except ValueError as e:
            raise e
        except Exception as e:
            raise ValueError(f"Failed to decrypt with passcode: {str(e)}")

    def decrypt_pkg(self, key, output_dir):
        # Implementa la decriptazione del PKG usando la chiave AES
        pass

 