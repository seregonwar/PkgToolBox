import os


def inject_file(pkg_file, file_info, input_file):
    with open(input_file, 'rb') as f:
        data = f.read()
    
    with open(pkg_file, 'r+b') as f:
        f.seek(file_info['offset'])
        f.write(data)
    
    
    return len(data)