# Block cipher setup

BLOCK_SIZE = 8  # Block size is 8 bits
KEY_SIZE = 8    # Key size is also 8 bits

# Substitution Box (S-box) to substitute 4-bit values for confusion
S_BOX = {
    0b0000: 0b1110, 0b0001: 0b0100, 0b0010: 0b1101, 0b0011: 0b0001,
    0b0100: 0b0010, 0b0101: 0b1111, 0b0110: 0b1011, 0b0111: 0b1000,
    0b1000: 0b0011, 0b1001: 0b1010, 0b1010: 0b0110, 0b1011: 0b1100,
    0b1100: 0b0101, 0b1101: 0b1001, 0b1110: 0b0000, 0b1111: 0b0111
}

# Substitution function: takes a 4-bit nibble and substitutes it using the S-box
def substitute(nibble):
    return S_BOX[nibble]

# Permutation table to shuffle bits within an 8-bit block for diffusion
PERMUTATION = [1, 5, 2, 0, 3, 7, 4, 6]

# Permutation function: rearranges bits based on the permutation table
def permute(block):
    permuted_block = 0
    for i, bit in enumerate(PERMUTATION):
        # Extract the bit from the original block and place it in the new position
        permuted_block |= ((block >> bit) & 1) << i
    return permuted_block

# Feistel function: takes the right half of the block and XORs it with the key, keeping it 4 bits
def feistel(right_half, subkey):
    return (right_half ^ subkey) & 0xF  # XOR with key and mask to ensure result is 4 bits

# Encryption function for a single 8-bit block using a single round of Feistel network
def encrypt_block(block, key):
    # Split the block into left (higher 4 bits) and right (lower 4 bits) halves
    left_half = (block >> 4) & 0xF  # Extract the left 4 bits
    right_half = block & 0xF        # Extract the right 4 bits
    
    # Feistel round: process the right half with the key
    right_transformed = feistel(right_half, key)
    
    # Substitution step: apply the S-box to the transformed right half
    right_substituted = substitute(right_transformed)
    
    # Permutation step: shuffle the bits of the substituted right half
    right_permuted = permute(right_substituted)
    
    # Combine the permuted right half with the unchanged left half to form the encrypted block
    encrypted_block = (right_permuted << 4) | left_half
    return encrypted_block

# ECB (Electronic Codebook) mode encryption: encrypts each block independently
def ecb_encrypt(plaintext, key):
    ciphertext = []
    for block in plaintext:
        # Encrypt each 8-bit block with the key
        encrypted_block = encrypt_block(block, key)
        ciphertext.append(encrypted_block)
    return ciphertext

# ECB mode decryption: in this simple case, encryption and decryption are symmetric
def ecb_decrypt(ciphertext, key):
    return ecb_encrypt(ciphertext, key)  # ECB decryption uses the same process as encryption here

# CBC (Cipher Block Chaining) mode encryption: each block depends on the previous ciphertext block
def cbc_encrypt(plaintext, key, iv):
    ciphertext = []
    previous_block = iv  # Start with the initialization vector (IV)
    for block in plaintext:
        # XOR plaintext block with the previous ciphertext block (or IV for the first block)
        xor_block = block ^ previous_block
        # Encrypt the XORed block
        encrypted_block = encrypt_block(xor_block, key)
        # Append encrypted block to ciphertext and update previous block
        ciphertext.append(encrypted_block)
        previous_block = encrypted_block
    return ciphertext

# CBC mode decryption: decrypts each block, then XORs with the previous ciphertext block or IV
def cbc_decrypt(ciphertext, key, iv):
    plaintext = []
    previous_block = iv  # Start with the initialization vector (IV)
    for block in ciphertext:
        # Decrypt the current block
        decrypted_block = encrypt_block(block, key)  # In this simple cipher, decryption uses the same function
        # XOR the decrypted block with the previous ciphertext block (or IV for the first block)
        xor_block = decrypted_block ^ previous_block
        # Append the result to the plaintext
        plaintext.append(xor_block)
        # Update the previous block for the next iteration
        previous_block = block
    return plaintext

# Example input
plaintext = [0b11001010, 0b10101100]  # Two 8-bit blocks as input plaintext
key = 0b10101010  # Example 8-bit encryption key
iv = 0b00001111  # Initialization vector (IV) for CBC mode

# ECB Mode Encryption and Decryption
ecb_encrypted = ecb_encrypt(plaintext, key)  # Encrypt plaintext using ECB mode
ecb_decrypted = ecb_decrypt(ecb_encrypted, key)  # Decrypt the ciphertext using ECB mode

# CBC Mode Encryption and Decryption
cbc_encrypted = cbc_encrypt(plaintext, key, iv)  # Encrypt plaintext using CBC mode
cbc_decrypted = cbc_decrypt(cbc_encrypted, key, iv)  # Decrypt the ciphertext using CBC mode

# Output the results
print(f"ECB Encrypted: {ecb_encrypted}")
print(f"ECB Decrypted: {ecb_decrypted}")
print(f"CBC Encrypted: {cbc_encrypted}")
print(f"CBC Decrypted: {cbc_decrypted}")
