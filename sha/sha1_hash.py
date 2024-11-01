"""
* SHA-1 Algo
* Prepared by: Omar El-Azab
* Date: 1/11/2024
"""

def left_rotate(n, b):
    """Left rotate n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

def sha1(message):
    # Initialize variables
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Pre-processing
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    message += b'\x80'
    
    while (len(message) * 8 + 64) % 512 != 0:
        message += b'\x00'
        
    message += original_bit_len.to_bytes(8, byteorder='big')

    # Process the message in 512-bit chunks
    for i in range(0, len(message), 64):
        w = [0] * 80
        chunk = message[i:i+64]
        
        # Break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = int.from_bytes(chunk[j*4:j*4+4], byteorder='big')
        
        # Extend the sixteen 32-bit words into eighty 32-bit words
        for j in range(16, 80):
            w[j] = left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
        
        # Initialize hash value for this chunk
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop
        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= j <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            
            temp = (left_rotate(a, 5) + f + e + k + w[j]) & 0xFFFFFFFF
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to the result
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Produce the final hash value (big-endian) as a 160-bit number
    return f'{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}'
