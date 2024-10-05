import os


def inject_file(pkg_file, file_info, input_file):
    with open(input_file, 'rb') as f:
        data = f.read()
    
    with open(pkg_file, 'r+b') as f:
        # Check if the file already exists and if it needs to be overwritten
        if file_info['size'] != len(data):
            raise ValueError("The injected file size does not match the original size.")
        
        f.seek(file_info['offset'])
        f.write(data)
    
    return len(data)