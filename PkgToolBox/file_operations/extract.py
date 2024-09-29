import os

def extract_file(pkg_file, file_info, output_path, log_callback=None):
    try:
        with open(pkg_file, 'rb') as f:
            f.seek(file_info['offset'])
            data = f.read(file_info['size'])
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(data)
        
        if log_callback:
            log_callback(f"File extracted: {output_path}")
        
        return output_path
    except PermissionError as e:
        if log_callback:
            log_callback(f"Permission denied: {e}")
        raise
    except Exception as e:
        if log_callback:
            log_callback(f"An error occurred: {e}")
        raise