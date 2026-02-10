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
    total_repetitions = 0
    for block, count in block_counts.items():
        if count > 1:
            total_repetitions += (count - 1)
    
    return total_repetitions

def is_valid_hex(hex_string):
    try:
        bytes.fromhex(hex_string)
        return True
    except ValueError:
        return False

def detectECBMode(filename):
    """
    Analyze all ciphertexts and identify the one encrypted with ECB mode.
    
    Input:
        filename (str): Path to the file containing ciphertexts
        
    Returns:
        bool: True if ECB mode detected in any ciphertext, False otherwise
    """
    import os
    
    if not os.path.isfile(filename):
        print(f"Error: File '{filename}' not found.")
        return False
    
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
        
        # Check if ECB mode detected (has repeated 16-byte blocks)
        repetitions = countRepetitions(ciphertext)
        if repetitions > 0:
            print(f"\nECB Mode Detected (Line {line_num}) \n")
            print("Ciphertext:")
            print(hex_ciphertext)
            print(f"\nNumber of repetitions: {repetitions}")
            ecb_found = True
    
    if not ecb_found:
        print("\nNo ECB mode encryption detected.")
    
    return ecb_found

def main():
    filename = "ciphertexts.txt"
    detectECBMode(filename)

if __name__ == "__main__":
    main()