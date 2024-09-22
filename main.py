import logging
import sys
from package import Package
import argparse
from gui import start_gui
import io
from contextlib import redirect_stdout
from file_operations import extract_file, inject_file, modify_file_header

# Configura il logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def run_command(cmd, pkg, file, out, update_info_callback):
    logging.debug(f"run_command called with cmd={cmd}, pkg={pkg}, file={file}, out={out}")
    if not cmd or not pkg:
        raise ValueError("The 'Command' and 'PKG' fields are mandatory.")

    args = argparse.Namespace(cmd=cmd, pkg=pkg, file=file, out=out)

    if args.cmd == "extract" and not args.file:
        raise ValueError("--file is mandatory for the extract command")
    if (args.cmd == "extract" or args.cmd == "dump") and not args.out:
        raise ValueError("--out is mandatory for extract and dump commands")

    target = Package(args.pkg)

    try:
        if args.cmd == "info":
            # Capture the output of the info() function
            f = io.StringIO()
            with redirect_stdout(f):
                target.info()
            info_output = f.getvalue()
            
            if not info_output:
                raise ValueError("No information found in the PKG file.")
            
            # Convert the output to a dictionary
            info_dict = {}
            for line in info_output.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    info_dict[key.strip()] = value.strip()
            
            # Search for the image
            image_data = None
            image_files = ['icon0.png', 'pic0.png', 'pic1.png']
            for img_file in image_files:
                try:
                    with io.BytesIO() as temp_buffer:
                        target.extract(img_file, temp_buffer)
                        image_data = temp_buffer.getvalue()
                    break
                except ValueError:
                    continue
            
            if image_data:
                info_dict['icon0'] = image_data
            
            update_info_callback(info_dict)
            return info_output  # Return the output
        elif args.cmd == "extract":
            file_info = target.get_file_info(args.file)
            extract_file(args.pkg, file_info, args.out)
            return f"File extracted: {args.file}"
        elif args.cmd == "inject":
            file_info = target.get_file_info(args.file)
            injected_size = inject_file(args.pkg, file_info, args.out)
            return f"Injected {injected_size} bytes"
        elif args.cmd == "modify":
            modified_size = modify_file_header(args.pkg, int(args.file, 16), args.out.encode())
            return f"Modified {modified_size} bytes"
        elif args.cmd == "dump":
            target.dump(args.out)
            return "Dump completed successfully"
    except FileExistsError:
        # Let the GUI handle this exception
        raise
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        raise

    return None  # Add this to handle unforeseen cases

if __name__ == "__main__":
    start_gui(run_command)
