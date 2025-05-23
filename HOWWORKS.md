# Technical Analysis of the Decryption Process for PlayStation 4 PKG and PFS File Formats

**Date:** May 23, 2025

**Analysis Author:** SeregonWar

**Primary Source:** C++ source code fragments (from the shadPS4 Emulator project) [shadPS4](https://github.com/shadps4-emu/shadPS4) and associated header files (`pkg.h`, `pfs.h`, `crypto.h`, `keys.h`, etc.).

## Abstract

This document outlines an in-depth technical analysis of the parsing and decryption mechanisms employed for the PKG (Package) and PFS (PlayStation File System) file formats specific to the PlayStation 4 console. Based on an examination of the provided source code, this paper details the fundamental data structures, the sequence of cryptographic operations, and the logical workflow required for the extraction and access of protected content. It highlights a multi-layered security system leveraging standard algorithms such as RSA-2048, AES-128-CBC, and AES-128-XTS, along with platform-specific key derivation processes. Python code examples, derived from the translation of the C++ logic, will be used to illustrate crucial steps.

## 1. Introduction

PKG files serve as the primary distribution container for software on the PlayStation 4 platform, encapsulating games, applications, patches, and downloadable content. Within these containers, application data is frequently organized into a PFS filesystem image, which is itself subject to encryption. Accessing this content necessitates a detailed understanding of the PKG file format, the identification and decryption of a hierarchy of cryptographic keys, and the subsequent interpretation and decryption of the PFS image. This paper aims to dissect this process as it emerges from the analysis of the shadPS4 Emulator project's source code.

## 2. PKG File Format Analysis

The PKG file is a structured container format, its layout primarily defined by its header and a table of entries describing internal metadata.

### 2.1. PKG File Header (`PKGHeader`)

The PKG file header, conforming to the definition in `pkg.h`, typically occupies the first 4096 bytes (0x1000) of the file. It contains metadata crucial for interpreting the rest of the package. Among the most significant fields, expressed in Big Endian format, are:

*   **`magic` (u32_be):** A fixed identifier, `0x7F434E54` (corresponding to the ASCII string ".CNT"), which validates the file format.
*   **`pkg_table_entry_offset` (u32_be) and `pkg_table_entry_count` (u32_be):** Indicate the offset and number of entries in the PKG's file table, respectively. This table primarily lists metadata files (e.g., `param.sfo`, license files).
*   **`pkg_content_id` (u8[0x24]):** A 36-byte unique content identifier. From this string, typically at file offset `0x47` (skipping the first 7 characters of the `content_id` read from the header, which itself starts at file offset `0x30`), the `pkgTitleID` (9 characters, e.g., "CUSAXXXXX") is extracted.
*   **`pfs_image_offset` (u64_be) and `pfs_image_size` (u64_be):** Locate the encrypted PFS filesystem image within the PKG file.
*   **`pfs_cache_size` (u32_be):** A parameter used to size intermediate buffers during PFS processing, particularly for its initial decryption and the localization of the PFSC substructure.
*   **Various SHA256 Digests:** The header contains SHA256 hashes of different PKG sections (e.g., `digest_table_digest`, `digest_body_digest`, `pfs_image_digest`), used for integrity verification.
*   **`pkg_content_flags` (u32_be):** Flags providing contextual information about the content type (e.g., `PKGContentFlag.FIRST_PATCH`, `PKGContentFlag.REMASTER`).

```python
# Example of PKGHeader class definition in Python (simplified)
@dataclass
class PKGHeader:
    # ... (full field definition as per previous Python code) ...
    _FORMAT_FULL = ">IIIIHHI..." # Big Endian notation for struct.unpack

    magic: int
    pkg_table_entry_offset: int
    pkg_table_entry_count: int
    pkg_content_id: bytes # 36 bytes
    pfs_image_offset: int
    pfs_image_size: int
    pfs_cache_size: int
    # ... other fields ...

    @classmethod
    def from_bytes(cls, data: bytes):
        # ... (unpacking logic) ...
        return cls(*values)
```

### 2.2. PKG Entry Table (`PKGEntry`)

Located at the offset specified by `pkg_header.pkg_table_entry_offset`, this table is an array of `PKGEntry` structures. Each `PKGEntry` (32 bytes, Big Endian, defined in `pkg.h`) describes a metadata file, generally destined for the virtual `sce_sys/` directory upon extraction.

*   **`id` (u32_be):** A numerical identifier for the file type. A mapping, such as the one provided in `pkg_type.cpp`, translates these IDs into standard filenames (e.g., `0x1000` -> "param.sfo").
*   **`filename_offset` (u32_be):** If applicable, an offset into a filename table (often an entry with `id = 0x0200`, "entry_names").
*   **`offset` (u32_be):** The absolute offset, from the beginning of the PKG file, where the data for this entry is located.
*   **`size` (u32_be):** The size in bytes of the entry's data.
*   **`flags1` (u32_be), `flags2` (u32_be):** Contain flags that, among other things, can indicate if the entry is encrypted and which key index to use for decryption.

```python
# Example of PKGEntry class definition in Python
@dataclass
class PKGEntry:
    _FORMAT = ">IIIIIIQ" # id, filename_offset, flags1, flags2, offset, size, padding
    _SIZE = struct.calcsize(_FORMAT)
    
    id: int
    filename_offset: int
    flags1: int
    flags2: int
    offset: int
    size: int
    padding: int # u64_be
    name: str = "" # Added for convenience

    # ... (from_bytes method) ...
```

## 3. PKG Entry Decryption Flow (`sce_sys` Content)

Several entries within the PKG, particularly those related to NPDRM (e.g., `nptitle.dat`, `npbind.dat`, with IDs like `0x0400`, `0x0401`, `0x0402`, `0x0403`), are encrypted. Their decryption follows these key steps, as implemented in `PKG::Extract` and `Crypto` (from `crypto.cpp` and `keys.h`):

### 3.1. Derivation of `dk3_` (Derived Key 3)

1.  **Accessing "entry_keys":** The PKG entry with `id = 0x0010` (identified as "entry_keys") is read.
2.  **Reading Encrypted Keys:** From this entry's offset, various digests and an array of seven keys (`key1` in `pkg.cpp`), each 256 bytes, are read.
3.  **RSA Decryption of `key1[3]`:** The fourth key in this array (`key1[3]`) is decrypted using the RSA-2048 algorithm with the PKCS#1 v1.5 padding scheme. The RSA private key employed for this operation is specified as `PkgDerivedKey3Keyset` in the `keys.h` file.
    ```python
    # Conceptual example of RSA decryption in Python
    # self.dk3_ is a bytearray(32)
    # key1_list[3] are the 256 encrypted bytes
    # self.crypto._key_pkg_derived_key3 is the PyCryptodome RSA key object
    
    # In RealCrypto.RSA2048Decrypt:
    # key_to_use = self._key_pkg_derived_key3 if is_dk3 else self._key_fake
    # cipher_rsa = Cipher_PKCS1_v1_5.new(key_to_use)
    # decrypted_data = cipher_rsa.decrypt(ciphertext, None)
    # output_key_buffer[:bytes_to_copy] = decrypted_data[:bytes_to_copy]
    ```
4.  **Resulting `dk3_`:** The output of this RSA decryption is a 32-byte key, denoted `dk3_`.

### 3.2. Derivation of Image Key (`imgKey`) and EKPFS Key (`ekpfsKey`)

1.  **Accessing "image_key":** The PKG entry with `id = 0x0020` ("image_key") is read.
2.  **Reading Encrypted Data:** From this entry's offset, 256 bytes of encrypted data, termed `imgkeydata`, are read.
3.  **Generating `ivKey`:**
    *   A 64-byte buffer is prepared. The first 32 bytes are a copy of the raw bytes of the `PKGEntry` (ID `0x0020`) read from the table. The subsequent 32 bytes consist of the `dk3_` key (obtained in the previous step).
    *   A SHA256 hash is computed over this 64-byte buffer. The resulting 32-byte digest is the `ivKey`.
    ```python
    # In RealCrypto.ivKeyHASH256:
    # h = SHA256.new()
    # h.update(cipher_input_64_bytes)
    # digest = h.digest() # 32 bytes
    # ivkey_result_buffer[:] = digest
    ```
4.  **AES Decryption of `imgkeydata`:**
    *   The `ivKey` (32 bytes) is split: the first 16 bytes serve as the AES Initialization Vector (IV), while the next 16 bytes constitute the AES-128 key.
    *   The 256 bytes of `imgkeydata` are decrypted using AES-128 in CBC (Cipher Block Chaining) mode with the newly derived key and IV. The result of this operation is the `imgKey` (256 bytes).
    ```python
    # In RealCrypto.aesCbcCfb128Decrypt:
    # key_aes = ivkey[16:32]
    # iv_aes = ivkey[0:16]
    # cipher_aes = AES.new(key_aes, AES.MODE_CBC, iv_aes)
    # decrypted_data = cipher_aes.decrypt(ciphertext_256_bytes)
    # decrypted_buffer[:] = decrypted_data # self.imgKey
    ```
5.  **RSA Decryption of `imgKey`:**
    *   The `imgKey` (256 bytes) is further processed. It is decrypted using RSA-2048 (PKCS#1 v1.5), but this time with a different RSA private key, named `FakeKeyset` in `keys.h`.
    *   The output of this second RSA decryption is the `ekpfsKey` (Entitlement Key for PFS), a 32-byte key crucial for the subsequent PFS filesystem decryption.

### 3.3. Specific Decryption of NPDRM Entries

For NPDRM type entries (e.g., `nptitle.dat`, `npbind.dat`):
1.  **Specific `ivKey` Generation:** Similar to step 3.2.3, a 64-byte buffer is constructed by concatenating the bytes of the current NPDRM `PKGEntry` with `dk3_`. A SHA256 hash of this buffer produces an `ivKey` specific to this entry.
2.  **AES Decryption:** The encrypted data of the NPDRM entry is decrypted using AES-128-CBC, with the key and IV derived from this specific `ivKey`. The decrypted result overwrites the original entry's data in the extraction path.

## 4. PFS Image Decryption and Parsing

The PFS image, located via `pkg_header.pfs_image_offset` and `pkg_header.pfs_image_size`, contains the actual filesystem of the game/application.

### 4.1. Derivation of PFS Data and Tweak Keys (`dataKey`, `tweakKey`)

1.  **Reading the PFS Seed:** A 16-byte cryptographic `seed` is read from a fixed offset (`0x370`) relative to the start of the PFS image (i.e., `pkg_header.pfs_image_offset + 0x370`).
2.  **Key Generation via HMAC-SHA256:** The `PfsGenCryptoKey` function (in `Crypto`) uses the `ekpfsKey` (32 bytes, obtained in step 3.2.5) and the PFS `seed` (16 bytes) to generate two 16-byte keys: `dataKey` and `tweakKey`.
    *   A 20-byte payload is constructed by concatenating a fixed index (`1`, as a `u32`) with the `seed`.
    *   An HMAC-SHA256 of this payload is computed, using `ekpfsKey` as the HMAC key.
    *   The resulting HMAC digest (32 bytes) is split: the first 16 bytes become the `tweakKey`, and the subsequent 16 bytes become the `dataKey`.
    ```python
    # In RealCrypto.PfsGenCryptoKey:
    # hmac_sha256 = HMAC.new(ekpfs_32_bytes, digestmod=SHA256)
    # index_bytes = struct.pack("<I", 1) # Little Endian u32 for index = 1
    # d_payload = index_bytes + seed_16_bytes # Total 20 bytes
    # hmac_sha256.update(d_payload)
    # data_tweak_key_digest = hmac_sha256.digest() # 32 bytes
    # tweakKey_buffer[:] = data_tweak_key_digest[0:16]
    # dataKey_buffer[:] = data_tweak_key_digest[16:32]
    ```

### 4.2. Initial PFS Image Decryption and PFSC Localization

1.  **Partial Read and Decryption:** A portion of the encrypted PFS image is read from the PKG file. The size of this portion, according to the analyzed C++ code, is `pkg_header.pfs_cache_size * 2`. If `pfs_cache_size` is zero, this phase and subsequent PFS parsing are typically skipped.
2.  **AES-XTS Decryption:** This portion is decrypted using the AES-128-XTS algorithm with the `dataKey` and `tweakKey`. XTS decryption operates on 0x1000-byte (4 KiB) blocks, and the sector number (starting from 0 for this initial decryption) is used to calculate the initial tweak for each XTS block.
3.  **`PFSC_MAGIC` Search:** Within the (partially) decrypted PFS image buffer, the magic number `PFSC_MAGIC` (0x43534650, ASCII "PFSC", Little Endian) is searched to determine the `pfsc_offset_in_pfs_image`. This offset is relative to the start of the decrypted PFS image buffer and indicates the beginning of the PFSC data structure. The search typically occurs at 0x10000-byte intervals, starting from offset 0x20000.

### 4.3. Parsing the PFSC Header (`PFSCHdrPFS`) and Sector Map (`sectorMap`)

Starting from `pfsc_offset_in_pfs_image` (within the decrypted PFS buffer), the `PFSCHdrPFS` structure (defined as `PFSCHdr` in `pfs.h` and used in `pkg.cpp`) is read and interpreted:

*   **`magic` (s32):** Should match `PFSC_MAGIC`.
*   **`data_length` (s64):** Total length of the data managed by this PFSC structure.
*   **`block_sz2` (s64):** Size of the logical, decompressed data blocks (typically 0x10000 bytes or 64 KiB).
*   **`block_offsets` (s64):** Offset (relative to the start of the PFSC structure) of the table (`sectorMap`) that maps logical blocks to their (compressed or uncompressed) data within the PFSC data area.

The number of logical data blocks is calculated: `num_data_blocks_in_pfsc = pfs_chdr_obj.data_length // pfs_chdr_obj.block_sz2`.
The `sectorMap` is then read: it is an array of `num_data_blocks_in_pfsc + 1` offsets (`u64`). Each `sectorMap[i]` indicates the start offset of logical block `i` within the PFSC data area, and `sectorMap[i+1] - sectorMap[i]` gives its (potentially compressed) size.

### 4.4. Extraction and Decompression of PFSC Logical Data Blocks

An iteration is performed from `0` to `num_data_blocks_in_pfsc - 1`. For each logical block:
1.  The offset (`sector_offset_in_pfsc_data`) and size (`sector_data_size`) of the data block are retrieved from the `sectorMap`. This data is relative to the start of the PFSC data area (i.e., after `pfsc_offset_in_pfs_image` in the decrypted PFS buffer, and after the `PFSCHdrPFS` header if `block_offsets` points after it, within the `pfsc_content_actual_bytes` buffer).
2.  The data block is extracted.
3.  If its size (`sector_data_size`) is less than `pfs_chdr_obj.block_sz2` (e.g., < 0x10000), the data block is considered compressed and is decompressed using zlib (function `DecompressPFSC`) into a temporary buffer of size `block_sz2`. Otherwise, it is copied directly.

### 4.5. Parsing Inodes (`Inode`)

The first decompressed logical PFSC block (`i_block_pfsc = 0`) acts as the PFS "superblock" and contains, among other information, the total number of inodes (`ndinode_total_count`) at offset `0x30`. Subsequent logical blocks (from 1 up to a calculated `occupied_inode_blocks` based on `ndinode_total_count` and `sizeof(Inode)`) contain the inode table.

Each `Inode` structure (defined in `pfs.h`, 0xA8 bytes in size) provides metadata for a file or directory:
*   **`Mode` (u16):** File type (directory, regular file, etc., as specified by bits in `InodeModePfs`) and permissions.
*   **`Size` (s64):** Actual size of the file in bytes.
*   **`Blocks` (u32):** Number of logical data blocks (of size `block_sz2`) occupied by the file.
*   **`loc` (u32):** Index of the file's first data block in the `sectorMap`. This `loc` is an index relative to the start of the data area managed by PFSC, not an absolute index into `sectorMap`.

### 4.6. Parsing Directory Entries (`Dirent`)

Logical PFSC blocks following the inode blocks contain directory entries (`Dirent`, from `pfs.h`). The presence of "." and ".." entries is a common indicator of a dirent block.

Each `Dirent` provides:
*   **`ino` (s32):** The inode number to which this entry refers.
*   **`type` (s32):** Entry type, with values mapping to `PFSFileType` (e.g., `PFSFileType.PFS_FILE = 2`, `PFSFileType.PFS_DIR = 3`).
*   **`namelen` (s32):** Length of the file/directory name.
*   **`entsize` (s32):** Total size of this `Dirent` structure, used to advance to the next entry.
*   **`name` (char[512]):** The null-terminated file/directory name (actual length given by `namelen`).

During this parsing stage, an `fs_table` (list of `FSTableEntry`) and an `extract_paths` map (from inode number to `pathlib.Path`) are constructed to rebuild the filesystem hierarchy. The management of `current_dir_pfs` (the current PFS directory during parsing) and the correct determination of the PFS root path (influenced by the `uroot_reached` logic or the first "." entry) are crucial. Directories are created on disk as they are identified.

## 5. Actual File Extraction from PFS

Once the PFS structure has been parsed (inodes and dirents are available), individual files are extracted:

1.  For each `FSTableEntry` representing a file:
    *   The corresponding `Inode` object is retrieved (the indexing of `iNodeBuf` using `fs_entry.inode` is a critical point requiring correct mapping or assumptions about inode compactness).
    *   From the inode, `loc` (index of the file's first block in `sectorMap`) and `Blocks` (number of blocks composing the file) are obtained.
2.  An iteration is performed for `Blocks` times, processing one logical block of the file at a time:
    *   **Locating Encrypted Data:** The current block's index in `sectorMap` is `loc + j_block_in_file`. From this, `sector_offset_in_pfsc_img` (offset of the data block within the PFSC data area) and `sector_data_actual_size` (size of this block, compressed or not) are obtained.
    *   **Calculating PKG Offset:** The absolute offset (`absolute_sector_data_offset_in_pkg`) of this data block within the original PKG file is determined.
    *   **Identifying XTS Block:** The XTS block number (0x1000 bytes, `xts_block_num_in_pfs_image`) containing the start of this sector's data, and the offset (`offset_of_sector_in_its_xts_block`) of the sector's data within that XTS block, are calculated.
    *   **Reading and XTS Decryption:** A chunk of data (0x11000 bytes in the C++ code, `read_chunk_from_pkg`) is read from the PKG file starting at the identified XTS block's beginning. This read chunk is decrypted using `decryptPFS` (AES-128-XTS) with `dataKey`, `tweakKey`, and `xts_block_num_in_pfs_image` as the initial XTS sector number. The result is stored in `decrypted_chunk_from_pkg`.
    *   **Extracting and Decompressing Sector Data:** The actual sector data (of size `sector_data_actual_size`) is extracted from `decrypted_chunk_from_pkg` using `offset_of_sector_in_its_xts_block`. If compressed, it is decompressed using zlib.
    *   **Writing File:** The decompressed block (0x10000 bytes or `block_sz2`) is written to the output file. For the final block of the file, only the amount of data needed to reach the total file size specified in the inode is written.

```python
# Concept of PFS file extraction (simplified)
# In PKG.extract_pfs_files:
# for fs_entry in self.fs_table:
#     if fs_entry.type == PFSFileType.PFS_FILE:
#         inode_obj = self.iNodeBuf[fs_entry.inode - 1] # Assuming 1-based compact
#         output_path = self.extract_paths[fs_entry.inode]
#         
#         with open(output_path, "wb") as out_f:
#             for j_block in range(inode_obj.Blocks):
#                 # ... locate sector_offset_in_pfsc_img, sector_data_actual_size from sectorMap ...
#                 # ... calculate read_start_pos_in_pkg, xts_block_num_in_pfs_image, offset_of_sector_in_its_xts_block ...
#                 
#                 pkg_file.seek(read_start_pos_in_pkg)
#                 read_chunk = pkg_file.read(0x11000) 
#                 decrypted_chunk = bytearray(len(read_chunk)) # Ensure multiple of 0x1000 or handle in decryptPFS
                                                              # C++ uses fixed 0x11000 buffers for decryptPFS.
                                                              # Make read_chunk & decrypted_chunk sizes
                                                              # a multiple of 0x1000, padding if necessary.
                # Pad read_chunk if it's not a multiple of 0x1000 for decryptPFS
                # effective_read_chunk_len = (len(read_chunk) + 0xFFF) & ~0xFFF if len(read_chunk) % 0x1000 != 0 else len(read_chunk)
                # padded_read_chunk = bytearray(effective_read_chunk_len)
                # padded_read_chunk[:len(read_chunk)] = read_chunk
                # decrypted_chunk = bytearray(effective_read_chunk_len)

#                 self.crypto.decryptPFS(self.dataKey, self.tweakKey, 
#                                        padded_read_chunk, # Or unpadded chunk if decryptPFS handles it
#                                        decrypted_chunk, 
#                                        xts_block_num_in_pfs_image)
#                 
#                 sector_data = decrypted_chunk[offset_of_sector_in_its_xts_block : 
#                                               offset_of_sector_in_its_xts_block + sector_data_actual_size]
#                 
#                 if sector_data_actual_size == 0x10000: # block_sz2
#                     decompressed_data = sector_data
#                 else:
#                     decompressed_data = decompress_pfsc(sector_data, 0x10000) # block_sz2
#                 
#                 # ... write decompressed_data to out_f, handling the last block ...
```

## 6. Cryptographic Algorithm Summary

The security system employs a combination of standard algorithms:

*   **RSA-2048 (PKCS#1 v1.5 Padding):** Used for the asymmetric decryption of critical intermediate keys. The private keys (`PkgDerivedKey3Keyset` for `dk3_`, `FakeKeyset` for `ekpfsKey`) are defined via their components (n, e, d, p, q, coefficient).
*   **SHA256:** Employed as a hash function for deriving `ivKey` and for integrity digests in the PKG header.
*   **AES-128-CBC:** Used for symmetric decryption of `imgKey` (using `ivKey`) and NPDRM entries (using an entry-specific `ivKey`). The key and IV (both 16 bytes) are typically derived from a 32-byte SHA256 hash.
*   **HMAC-SHA256:** Utilized in the `PfsGenCryptoKey` function to derive PFS `dataKey` and `tweakKey` from `ekpfsKey` and a `seed`.
*   **AES-128-XTS (Advanced Encryption Standard with Xor-Encrypt-Xor based Tweaked CodeBook Mode):** The primary algorithm for sector-level decryption of the PFS image and files within it. It requires a `dataKey` and a `tweakKey`. The "tweak" (a value that modifies the cipher for each block, based on the sector number) is encrypted with `tweakKey` (AES-ECB). This encrypted tweak is then iteratively updated for each 16-byte AES block within the XTS sector via a polynomial multiplication in the Galois Field GF(2^128) (polynomial `x^128 + x^7 + x^2 + x + 1`, or `0x87` if the highest bit is carried).

## 7. Conclusions and Considerations
The implementation of what is described can be found in [Ps4Package2.0](https://github.com/seregonwar/PkgToolBox/blob/main/packages/Ps4Package2.0-WorkInProgress.py), This technical paper was written to explain the technical vulnerabilities of pkg files and to give more technical information to those who have asked me in the last year if the files can be decrypted and modified, I am still implementing this system in PkgToolBox, once implemented anyone will be able to decrypt most of the applications and games currently available in the ps4 landscape, (a ps5 version may sooner or later come out as well).
