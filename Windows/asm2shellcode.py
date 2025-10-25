# use this in terminal of visual studio tool
import subprocess
import re
import sys

def extract_text_section_windows(obj_file):
    try:
        # Use dumpbin to get section hex dump
        result = subprocess.run(
            ['dumpbin', '/rawdata:1', '/section:.text', obj_file],
            capture_output=True, text=True, check=True
        )
        
        hex_bytes = []
        for line in result.stdout.split('\n'):
            # Match lines with hex bytes in dumpbin output
            # Example: " 0040: 48 89 E5 48 83 EC 10"
            match = re.search(r'^\s+[0-9A-F]+:\s+(([0-9A-F]{2}\s?)+)', line, re.IGNORECASE)
            if match:
                hex_part = match.group(1)
                bytes_list = re.findall(r'[0-9A-F]{2}', hex_part, re.IGNORECASE)
                hex_bytes.extend(bytes_list)
        
        # Convert to \x format
        hex_string = ''.join([f'\\x{byte.lower()}' for byte in hex_bytes])
        return hex_string
        
    except subprocess.CalledProcessError as e:
        print(f"Error running dumpbin: {e}")
        return None
    except FileNotFoundError:
        print("Error: dumpbin not found. Make sure Visual Studio is installed or add to PATH")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python extract_text_win.py task.jobj")
        sys.exit(1)
    
    hex_code = extract_text_section_windows(sys.argv[1])
    if hex_code:
        with open('text_section_hex.txt', 'w') as f:
            f.write(hex_code)
        print(f"Extracted {len(hex_code)//4} bytes to text_section_hex.txt")
        print(f"First 100 chars: {hex_code[:100]}...")