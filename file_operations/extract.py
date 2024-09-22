import os

def extract_file(pkg_file, file_info, output_path):
    with open(pkg_file, 'rb') as f:
        f.seek(file_info['offset'])
        data = f.read(file_info['size'])
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(data)
    
    return output_path