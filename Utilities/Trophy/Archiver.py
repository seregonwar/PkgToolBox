class Archiver:
    def __init__(self, m_Index, m_Name, m_Offset, m_Size, m_Bytes):
        self.Index = m_Index
        self.Name = m_Name
        self.Offset = int(m_Offset)
        self.Size = int(m_Size)
        self.Bytes = m_Bytes
