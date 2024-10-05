class Archiver:
    def __init__(self, index, name, offset, size, bytes_data=None):
        self.index = index
        self.name = name
        self.offset = offset
        self.size = size
        self.bytes_data = bytes_data
