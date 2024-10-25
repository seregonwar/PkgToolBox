PT_LOAD = 1

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4
PF_RW = PF_R | PF_W

class Elf32_Ehdr:
    def __init__(self):
        self.e_magic = 0
        self.e_class = 0
        self.e_data = 0
        self.e_idver = 0
        self.e_pad = [0] * 9
        self.e_type = 0
        self.e_machine = 0
        self.e_version = 0
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_flags = 0
        self.e_ehsize = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrndx = 0

class Elf32_Phdr:
    def __init__(self):
        self.p_type = 0
        self.p_offset = 0
        self.p_vaddr = 0
        self.p_paddr = 0
        self.p_filesz = 0
        self.p_memsz = 0
        self.p_flags = 0
        self.p_align = 0

class Elf32_Shdr:
    def __init__(self):
        self.sh_name = 0
        self.sh_type = 0
        self.sh_flags = 0
        self.sh_addr = 0
        self.sh_offset = 0
        self.sh_size = 0
        self.sh_link = 0
        self.sh_info = 0
        self.sh_addralign = 0
        self.sh_entsize = 0

class Elf32_Rel:
    def __init__(self):
        self.r_offset = 0
        self.r_info = 0

class SceModuleInfo:
    def __init__(self):
        self.modattribute = 0
        self.modversion = [0] * 2
        self.modname = ""
        self.gp_value = None
        self.ent_top = None
        self.ent_end = None
        self.stub_top = None
        self.stub_end = None

class PSP_Header2:
    def __init__(self):
        self.signature = 0
        self.mod_attribute = 0
        self.comp_attribute = 0
        self.module_ver_lo = 0
        self.module_ver_hi = 0
        self.modname = ""
        self.mod_version = 0
        self.nsegments = 0
        self.elf_size = 0
        self.psp_size = 0
        self.boot_entry = 0
        self.modinfo_offset = 0
        self.bss_size = 0
        self.seg_align = [0] * 4
        self.seg_address = [0] * 4
        self.seg_size = [0] * 4
        self.reserved = [0] * 5
        self.devkit_version = 0
        self.decrypt_mode = 0
        self.padding = 0
        self.overlap_size = 0
        self.key_data = [0] * 0x30
        self.comp_size = 0
        self._80 = 0
        self.unk_B8 = 0
        self.unk_BC = 0
        self.key_data2 = [0] * 0x10
        self.tag = 0
        self.scheck = [0] * 0x58
        self.sha1_hash = [0] * 0x14
        self.key_data4 = [0] * 0x10

class PSP_Header:
    def __init__(self):
        self.signature = 0
        self.attribute = 0
        self.module_ver_lo = 0
        self.module_ver_hi = 0
        self.modname = ""
        self.version = 0
        self.nsegments = 0
        self.elf_size = 0
        self.psp_size = 0
        self.entry = 0
        self.modinfo_offset = 0
        self.bss_size = 0
        self.seg_align = [0] * 4
        self.seg_address = [0] * 4
        self.seg_size = [0] * 4
        self.reserved = [0] * 5
        self.devkitversion = 0
        self.decrypt_mode = 0
        self.key_data0 = [0] * 0x30
        self.comp_size = 0
        self._80 = 0
        self.reserved2 = [0] * 2
        self.key_data1 = [0] * 0x10
        self.tag = 0
        self.scheck = [0] * 0x58
        self.key_data2 = 0
        self.oe_tag = 0
        self.key_data3 = [0] * 0x1C