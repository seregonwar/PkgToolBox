import struct
import binascii
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

# Chiavi edat/npdrm
EDAT_HASH_KEY = bytes([0xEF, 0xFE, 0x5B, 0xD1, 0x65, 0x2E, 0xEB, 0xC1, 0x19, 0x18, 0xCF, 0x7C, 0x04, 0xD4, 0xF0, 0x11])
EDAT_IV = bytes(16)
EDAT_KEY = bytes([0xBE, 0x95, 0x9C, 0xA8, 0x30, 0x8D, 0xEF, 0xA2, 0xE5, 0xE1, 0x80, 0xC6, 0x37, 0x12, 0xA9, 0xAE])
NPDRM_OMAC_KEY2 = bytes([0x6B, 0xA5, 0x29, 0x76, 0xEF, 0xDA, 0x16, 0xEF, 0x3C, 0x33, 0x9F, 0xB2, 0x97, 0x1E, 0x25, 0x6B])
NPDRM_OMAC_KEY3 = bytes([0x9B, 0x51, 0x5F, 0xEA, 0xCF, 0x75, 0x06, 0x49, 0x81, 0xAA, 0x60, 0x4D, 0x91, 0xA5, 0x4E, 0x97])
SDAT_KEY = bytes([0x0D, 0x65, 0x5E, 0xF8, 0xE6, 0x74, 0xA9, 0x8A, 0xB8, 0x50, 0x5C, 0xFA, 0x7D, 0x01, 0x29, 0x33])

FLAG_COMPRESSED = 1
FLAG_0x02 = 0x2
FLAG_0x10 = 0x10
FLAG_0x20 = 0x20
FLAG_KEYENCRYPTED = 0x8
FLAG_DEBUG = 0x80000000
FLAG_SDAT = 0x1000000

STATUS_OK = 0
STATUS_ERROR_HEADERCHECK = -4
STATUS_ERROR_DECRYPTING = -5
STATUS_ERROR_MISSINGKEY = -3
STATUS_ERROR_INCORRECT_FLAGS = -6
STATUS_ERROR_INCORRECT_VERSION = -7
STATUS_ERROR_HASHDEVKLIC = -2
STATUS_ERROR_HASHTITLEIDNAME = -1

HEADER_MAX_BLOCKSIZE = 0x3C00


def be32(b, off=0):
    return struct.unpack_from(">I", b, off)[0]


def be64(b, off=0):
    return struct.unpack_from(">Q", b, off)[0]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def arraycopy(src, src_off, dst, dst_off, length):
    dst[dst_off:dst_off+length] = src[src_off:src_off+length]


def cmac_aes(key: bytes, data: bytes) -> bytes:
    c = CMAC.new(key, ciphermod=AES)
    c.update(data)
    return c.digest()


class NPD:
    def __init__(self, raw: bytes):
        self.magic = raw[:4]
        self.version = be32(raw, 4)
        self.license = be32(raw, 8)
        self.type = be32(raw, 12)
        self.content_id = raw[0x10:0x40]
        self.digest = raw[0x40:0x50]
        self.title_hash = raw[0x50:0x60]
        self.dev_hash = raw[0x60:0x70]
        self.unknown3 = be64(raw, 0x70)
        self.unknown4 = be64(raw, 0x78)
        if not self.validate():
            raise ValueError("Invalid NPD header")

    def validate(self):
        return self.magic == b"NPD\x00" and self.unknown3 == 0 and self.unknown4 == 0

    @classmethod
    def parse(cls, buf: bytes):
        if len(buf) < 0x80:
            raise ValueError("NPD header too short")
        return cls(buf[:0x80])


class EDATData:
    def __init__(self, flags: int, block_size: int, file_len: int):
        self.flags = flags
        self.block_size = block_size
        self.file_len = file_len

    @classmethod
    def parse(cls, meta: bytes):
        if len(meta) < 0x10:
            raise ValueError("Metadata too short")
        return cls(be32(meta, 0), be32(meta, 4), be64(meta, 8))


def decrypt_metadata_section(meta: bytes) -> bytes:
    m = meta + b"\x00" * max(0, 0x20 - len(meta))
    return bytes([
        (m[12] ^ m[8] ^ m[16]),
        (m[13] ^ m[9] ^ m[17]),
        (m[14] ^ m[10] ^ m[18]),
        (m[15] ^ m[11] ^ m[19]),
        (m[4] ^ m[8] ^ m[20]),
        (m[5] ^ m[9] ^ m[21]),
        (m[6] ^ m[10] ^ m[22]),
        (m[7] ^ m[11] ^ m[23]),
        (m[12] ^ m[0] ^ m[24]),
        (m[13] ^ m[1] ^ m[25]),
        (m[14] ^ m[2] ^ m[26]),
        (m[15] ^ m[3] ^ m[27]),
        (m[4] ^ m[0] ^ m[28]),
        (m[5] ^ m[1] ^ m[29]),
        (m[6] ^ m[2] ^ m[30]),
        (m[7] ^ m[3] ^ m[31])
    ])


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def check_npd_hash1(filename: str, npd_raw: bytes) -> bool:
    src = filename.encode("ascii", errors="ignore")
    dest = npd_raw[0x10:0x40] + src
    cm = cmac_aes(NPDRM_OMAC_KEY3, dest)
    return cm == npd_raw[0x50:0x60]


def check_npd_hash2(devklic: bytes, npd_raw: bytes) -> bool:
    output = xor_bytes(devklic, NPDRM_OMAC_KEY2)
    cm = cmac_aes(output, npd_raw[:0x60])
    return cm == npd_raw[0x60:0x70]


def create_npd_hash1(filename: str, npd_raw: bytearray):
    src = filename.encode("ascii", errors="ignore")
    dest = npd_raw[0x10:0x40] + src
    cm = cmac_aes(NPDRM_OMAC_KEY3, dest)
    arraycopy(cm, 0, npd_raw, 0x50, 0x10)
    return cm


def create_npd_hash2(devklic: bytes, npd_raw: bytearray):
    output = xor_bytes(devklic, NPDRM_OMAC_KEY2)
    cm = cmac_aes(output, npd_raw[:0x60])
    arraycopy(cm, 0, npd_raw, 0x60, 0x10)
    return cm


def calculate_block_key(blk: int, npd: NPD) -> bytes:
    src = npd.dev_hash if npd.version > 1 else bytes(0x10)
    dest = bytearray(0x10)
    arraycopy(src, 0, dest, 0, 12)
    dest[12] = (blk >> 24) & 0xFF
    dest[13] = (blk >> 16) & 0xFF
    dest[14] = (blk >> 8) & 0xFF
    dest[15] = blk & 0xFF
    return bytes(dest)


def decrypt_file(in_path: str, out_path: str, dev_klic: bytes = None, key_from_rif: bytes = None):
    with open(in_path, "rb") as f:
        npd_raw = f.read(0x80)
        meta_hdr = f.read(0x10)
        f.seek(0x80)
        npd = NPD.parse(npd_raw)
        flags = be32(meta_hdr, 0)
        data = EDATData.parse(meta_hdr)
        # validate hashes
        filename = in_path.split("\\")[-1]
        if not check_npd_hash1(filename, npd_raw):
            return STATUS_ERROR_HASHTITLEIDNAME
        if dev_klic and not check_npd_hash2(dev_klic, npd_raw):
            return STATUS_ERROR_HASHDEVKLIC
        # get key
        if flags & FLAG_SDAT:
            rif_key = xor_bytes(npd.dev_hash, SDAT_KEY)
        elif npd.license == 3:
            rif_key = dev_klic
        else:
            rif_key = key_from_rif
        if not rif_key:
            return STATUS_ERROR_MISSINGKEY

        out = open(out_path, "wb")
        # blocchi
        num_blocks = (data.file_len + data.block_size - 1) // data.block_size
        meta_stride = 0x20 if (flags & FLAG_COMPRESSED or flags & FLAG_0x20) else 0x10
        header_size = 0x100
        for i in range(num_blocks):
            f.seek(0x100 + i * meta_stride)
            dest = bytearray(0x10)
            extra = 0
            if flags & FLAG_COMPRESSED:
                meta = f.read(0x20)
                decm = decrypt_metadata_section(meta)
                data_off = be64(decm, 0)
                data_len = be32(decm, 8)
                extra = be32(decm, 12)
                arraycopy(meta, 0, dest, 0, 0x10)
            elif flags & FLAG_0x20:
                meta = f.read(0x20)
                for j in range(0x10):
                    dest[j] = meta[j] ^ meta[j+0x10]
                data_off = header_size + i * data.block_size + num_blocks * meta_stride
                data_len = data.block_size if i != num_blocks -1 else data.file_len % data.block_size or data.block_size
            else:
                meta = f.read(0x10)
                dest = meta
                data_off = header_size + i * data.block_size + num_blocks * meta_stride
                data_len = data.block_size if i != num_blocks -1 else data.file_len % data.block_size or data.block_size

            f.seek(data_off)
            padded_len = (data_len + 15) & ~15
            enc_block = f.read(padded_len)
            block_key = calculate_block_key(i, npd)
            ek = aes_ecb_encrypt(rif_key, block_key)
            if flags & FLAG_0x10:
                iv = aes_ecb_encrypt(rif_key, ek)
            else:
                iv = ek
            cipher = AES.new(ek, AES.MODE_CBC, iv)
            dec = cipher.decrypt(enc_block)
            out.write(dec[:data_len])
        out.close()
    return STATUS_OK


def encrypt_file(in_path: str, out_path: str, dev_klic: bytes, key_from_rif: bytes, content_id: bytes, flags: bytes, version: bytes, type_byte: bytes):
    # Minimal port: builds NPD header and encrypts like EDAT.cs encryptFile
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        data_len = fin.seek(0, 2) or fin.tell()
        fin.seek(0)
        # Build NPD header
        npd = bytearray(0x80)
        npd[0:4] = b"NPD\x00"
        npd[4:8] = version.rjust(4, b"\x00")
        npd[8:12] = b"\x00\x00\x00\x03"  # license devklic by default
        npd[12:16] = type_byte.rjust(4, b"\x00")
        arraycopy(content_id, 0, npd, 0x10, 0x30)
        arraycopy(dev_klic, 0, npd, 0x60, 0x10)
        create_npd_hash1(out_path.split("\\")[-1], npd)
        create_npd_hash2(dev_klic, npd)
        fout.write(npd)
        # meta block
        meta = bytearray(0x10)
        arraycopy(flags, 0, meta, 0, 4)
        meta[4:8] = struct.pack(">I", 0x4000)
        meta[8:16] = struct.pack(">Q", data_len)
        fout.write(meta)
        fout.write(b"\x00\x00\x00\x00")
        pad = bytearray(4); pad[2]=0x40
        fout.write(pad)
        fout.write(b"\x00"*8)
        while fout.tell() < 0x100:
            fout.write(b"\x00")
        block_size = 0x4000
        num = (data_len + block_size -1)//block_size
        # encrypt blocks
        hashes = bytearray(num*0x10)
        payload = bytearray()
        for i in range(num):
            blk_offset = i*block_size
            fin.seek(blk_offset)
            chunk = fin.read(block_size)
            if i == num-1 and len(chunk)<block_size:
                chunk += b"\x00"*((block_size-len(chunk)+15)&~15)
            elif len(chunk)%16:
                chunk += b"\x00"*(16-(len(chunk)%16))
            block_key = calculate_block_key(i, NPD.parse(bytes(npd)))
            ek = aes_ecb_encrypt(dev_klic, block_key)
            iv = ek
            cipher = AES.new(ek, AES.MODE_CBC, iv)
            enc = cipher.encrypt(chunk)
            payload += enc
            # hash for metadata
            cm = CMAC.new(dev_klic, ciphermod=AES)
            cm.update(chunk)
            arraycopy(cm.digest(),0,hashes, i*0x10, 0x10)
        fout.write(hashes)
        fout.write(payload)
        footer = bytes.fromhex("4D6164652062792052325220546F6F6C")
        fout.write(footer)
    return STATUS_OK
