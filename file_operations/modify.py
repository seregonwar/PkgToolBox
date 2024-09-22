def modify_file_header(pkg_file, offset, new_data):
    with open(pkg_file, 'r+b') as f:
        f.seek(offset)
        f.write(new_data)
    return len(new_data)