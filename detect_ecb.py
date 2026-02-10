from collections import Counter

def countRepetitions(ciphertext):
    """
    Count total number of repetitions between all 16-byte blocks

    Input:
        ciphertext (bytes): The ciphertext in binary format
        
    Returns:
        int: Total number of repetitions 
    """
    BLOCK_SIZE = 16
    
    # Split ciphertext into 16-byte blocks
    blocks = []
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        if len(block) == BLOCK_SIZE:
            blocks.append(block)
    
    block_counts = Counter(blocks)
    
    # Calculate total repetitions
    # For each unique block, if it appears n times, there are (n-1) repetitions
    total_repetitions = 0
    for block, count in block_counts.items():
        if count > 1:
            total_repetitions += (count - 1)
    
    return total_repetitions

def detectECBMode(ciphertext):
    """
    Detect if ciphertext was encrypted using ECB mode.
    ECB mode will have repeated blocks for repeated plaintext blocks.
    
    Input:
        ciphertext (bytes): The ciphertext in binary format
        
    Returns:
        bool: True if ECB mode detected (repetitions found), False otherwise
    """
    repetitions = countRepetitions(ciphertext)
    return repetitions > 0

def is_valid_hex(hex_string):
    """Check if string is valid hexadecimal."""
    try:
        bytes.fromhex(hex_string)
        return True
    except ValueError:
        return False

def analyze_ciphertexts(filename):
    """
    Analyze all ciphertexts and identify the one encrypted with ECB mode.
    
    Input:
        filename (str): Path to the file containing ciphertexts
    """
    import os
    
    # Check if file exists
    if not os.path.isfile(filename):
        print(f"Error: File '{filename}' not found.")
        print("Please ensure the ciphertexts.txt file is in the same directory.")
        return
    
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    ecb_found = False
    
    for line_num, line in enumerate(lines, 1):
        hex_ciphertext = line.strip()
        
        if not hex_ciphertext:
            continue
        
        # Only process valid hex strings
        if not is_valid_hex(hex_ciphertext):
            print(f"Error decoding line {line_num}: Invalid hexadecimal format")
            continue
        
        ciphertext = bytes.fromhex(hex_ciphertext)
        
        # Check if this ciphertext was encrypted with ECB mode
        if detectECBMode(ciphertext):
            repetitions = countRepetitions(ciphertext)
            print(f"\nECB Mode Detected (Line {line_num}) \n")
            print("Ciphertext:")
            print(hex_ciphertext)
            print(f"\nNumber of repetitions: {repetitions}")
            ecb_found = True
    
    if not ecb_found:
        print("\nNo ECB mode encryption detected.")

def main():
    filename = "ciphertexts.txt"
    analyze_ciphertexts(filename)

if __name__ == "__main__":
    main()