from .package_base import PackageBase
from .utils import Logger
from .enums import DRMType, ContentType, PackageType, PackageFlag, Type, IROTag

# Importazioni condizionali per AesLibraryPs3
AES_LIBRARY_AVAILABLE = False
try:
    from .AesLibraryPs3.aes import AES_ctx, AES_set_key, AES_encrypt, AES_KEY_LEN_128, AES_cbc_decrypt
    from .AesLibraryPs3.amctrl import PGD_HEADER, MAC_KEY, sceDrmBBMacInit, sceDrmBBMacUpdate, bbmac_getkey
    from .AesLibraryPs3.kirk_engine import kirk_init
    # Prova a importare decrypt_pgd da amctrl se non è in kirk_engine
    try:
        from .AesLibraryPs3.kirk_engine import decrypt_pgd
    except ImportError:
        from .AesLibraryPs3.amctrl import decrypt_pgd
    AES_LIBRARY_AVAILABLE = True
except ImportError as e:
    print(f"Warning: AesLibraryPs3 modules could not be imported. Error: {e}")
    print("Some functionality may be limited.")
    AES_ctx = AES_set_key = AES_encrypt = AES_KEY_LEN_128 = AES_cbc_decrypt = None
    PGD_HEADER = MAC_KEY = sceDrmBBMacInit = sceDrmBBMacUpdate = bbmac_getkey = None
    kirk_init = decrypt_pgd = None

# Importa le classi dei pacchetti dopo aver definito AES_LIBRARY_AVAILABLE
from .package_ps3 import PackagePS3
from .package_ps4 import PackagePS4
from .package_ps5 import PackagePS5

__all__ = [
    'PackagePS3',
    'PackagePS4',
    'PackagePS5',
    'PackageBase',
    'Logger',
    'DRMType',
    'ContentType',
    'PackageType',
    'PackageFlag',
    'Type',
    'IROTag',
    'AES_LIBRARY_AVAILABLE'
]

if AES_LIBRARY_AVAILABLE:
    __all__ += [
        'AES_ctx',
        'AES_set_key',
        'AES_encrypt',
        'AES_KEY_LEN_128',
        'AES_cbc_decrypt',
        'PGD_HEADER',
        'MAC_KEY',
        'sceDrmBBMacInit',
        'sceDrmBBMacUpdate',
        'bbmac_getkey',
        'kirk_init',
        'decrypt_pgd'
    ]
