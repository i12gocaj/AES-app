# Define S-box tables and constants (these are standard values for AES)
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

inv_sbox = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Round constants for the key schedule. Need up to rcon[10] for AES-128.
rcon = [ # Added a 0x00 at the start so rcon[1] is 0x01, easier index.
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 # Enough for AES-256
]

# Helper function for multiplication in GF(2^8), used in MixColumns.
# Found this implementation online, uses shifts and XORs.
def _gf_mult(a, b):
    p = 0
    for _ in range(8):
        if b & 1: # If the last bit of b is 1
            p ^= a
        # Check if the high bit of a is set (before shifting)
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            # If the high bit was set, XOR with the AES polynomial 0x1B (x^8 + x^4 + x^3 + x + 1)
            a ^= 0x1B
        a &= 0xFF # Make sure 'a' stays within 8 bits after the shift and potential XOR
        b >>= 1 # Move to the next bit of b
    return p

class AES:
    def __init__(self, key):
        # Check if the key size is valid (16, 24, or 32 bytes)
        if len(key) not in [16, 24, 32]:
            raise ValueError("Invalid key size. Must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes.")
        self.key = key
        self.key_len_bytes = len(key)
        self.nk = self.key_len_bytes // 4  # Number of 32-bit words in the key
        self.nb = 4  # Block size in 32-bit words (always 4 for AES)
        # Determine the number of rounds based on key size
        # 10 rounds for 128-bit keys, 12 for 192, 14 for 256
        self.rounds = {16: 10, 24: 12, 32: 14}[self.key_len_bytes]
        # Generate all round keys needed for encryption/decryption right away
        self.round_keys = self._key_expansion(self.key)
        # print(f"AES initialized with {self.key_len_bytes*8}-bit key, {self.rounds} rounds.") # Debug print

    # --- Helper functions to convert between bytes and the 4x4 state matrix ---
    def _bytes_to_state(self, data):
        """Turns 16 bytes into a 4x4 matrix (columns first)."""
        if len(data) != 16:
            raise ValueError("Data length must be 16 bytes for state matrix.")
        state = [[0] * 4 for _ in range(4)]
        for r in range(4):
            for c in range(4):
                # Fill column by column
                state[r][c] = data[r + 4 * c]
        return state

    def _state_to_bytes(self, state):
        """Turns a 4x4 state matrix back into 16 bytes (columns first)."""
        # Read column by column
        return bytes(state[r][c] for c in range(4) for r in range(4))

    # --- The main AES steps ---
    def _sub_bytes(self, state):
        """Applies the S-box substitution to each byte of the state."""
        return [[sbox[byte] for byte in row] for row in state]

    def _inv_sub_bytes(self, state):
        """Applies the inverse S-box for decryption."""
        return [[inv_sbox[byte] for byte in row] for row in state]

    def _shift_rows(self, state):
        """Cyclically shifts the rows of the state (row 0 no shift, row 1 shifts 1, etc.)."""
        # I'll transpose the state first to make row operations easier in Python lists.
        s_T = [list(row) for row in zip(*state)] # Transpose
        s_T[1] = s_T[1][1:] + s_T[1][:1] # Shift row 1 left by 1
        s_T[2] = s_T[2][2:] + s_T[2][:2] # Shift row 2 left by 2
        s_T[3] = s_T[3][3:] + s_T[3][:3] # Shift row 3 left by 3
        # Transpose back to the original format
        return [list(row) for row in zip(*s_T)]

    def _inv_shift_rows(self, state):
        """Inverse of ShiftRows (shifts rows right)."""
        s_T = [list(row) for row in zip(*state)] # Transpose
        s_T[1] = s_T[1][-1:] + s_T[1][:-1] # Shift row 1 right by 1
        s_T[2] = s_T[2][-2:] + s_T[2][:-2] # Shift row 2 right by 2
        s_T[3] = s_T[3][-3:] + s_T[3][:-3] # Shift row 3 right by 3
        # Transpose back
        return [list(row) for row in zip(*s_T)]

    def _mix_columns(self, state):
        """Mixes the data within each column using GF(2^8) math."""
        new_state = [[0] * 4 for _ in range(4)]
        for c in range(4): # For each column
            col = [state[r][c] for r in range(4)] # Get the current column
            # Apply the MixColumns transformation matrix multiplication in GF(2^8)
            new_state[0][c] = _gf_mult(0x02, col[0]) ^ _gf_mult(0x03, col[1]) ^ col[2] ^ col[3]
            new_state[1][c] = col[0] ^ _gf_mult(0x02, col[1]) ^ _gf_mult(0x03, col[2]) ^ col[3]
            new_state[2][c] = col[0] ^ col[1] ^ _gf_mult(0x02, col[2]) ^ _gf_mult(0x03, col[3])
            new_state[3][c] = _gf_mult(0x03, col[0]) ^ col[1] ^ col[2] ^ _gf_mult(0x02, col[3])
            # Debugging column mixing:
            # if c == 0: print(f"MixCol input col 0: {[hex(x) for x in col]}, output: {[hex(new_state[r][0]) for r in range(4)]}")
        return new_state

    def _inv_mix_columns(self, state):
        """Inverse of MixColumns for decryption."""
        new_state = [[0] * 4 for _ in range(4)]
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            # Apply the inverse MixColumns transformation matrix multiplication
            new_state[0][c] = _gf_mult(0x0E, col[0]) ^ _gf_mult(0x0B, col[1]) ^ _gf_mult(0x0D, col[2]) ^ _gf_mult(0x09, col[3])
            new_state[1][c] = _gf_mult(0x09, col[0]) ^ _gf_mult(0x0E, col[1]) ^ _gf_mult(0x0B, col[2]) ^ _gf_mult(0x0D, col[3])
            new_state[2][c] = _gf_mult(0x0D, col[0]) ^ _gf_mult(0x09, col[1]) ^ _gf_mult(0x0E, col[2]) ^ _gf_mult(0x0B, col[3])
            new_state[3][c] = _gf_mult(0x0B, col[0]) ^ _gf_mult(0x0D, col[1]) ^ _gf_mult(0x09, col[2]) ^ _gf_mult(0x0E, col[3])
        return new_state

    def _add_round_key(self, state, round_key_matrix):
        """XORs the state with the current round key."""
        new_state = [[0] * 4 for _ in range(4)]
        for r in range(4):
            for c in range(4):
                new_state[r][c] = state[r][c] ^ round_key_matrix[r][c]
        return new_state

    # --- Key Expansion (Generating Round Keys) ---
    def _rot_word(self, word):
        """Rotates a 4-byte word (list) to the left by one byte."""
        return word[1:] + word[:1]

    def _sub_word(self, word):
        """Applies the S-box to each byte of a 4-byte word."""
        return [sbox[byte] for byte in word]

    def _key_expansion(self, key):
        """Expands the original key into a list of round keys (4x4 matrices)."""
        # Start with the key split into 4-byte words
        key_words = [list(key[i:i+4]) for i in range(0, self.key_len_bytes, 4)]

        # Total number of words needed = Nb * (Nr + 1)
        total_words_needed = self.nb * (self.rounds + 1)

        # This will hold all the expanded key words
        w = key_words[:] # Copy initial key words

        # Generate the rest of the words
        for i in range(self.nk, total_words_needed):
            temp = w[i-1][:] # Get the previous word

            if i % self.nk == 0: # If it's the first word of a new key block
                temp = self._rot_word(temp)
                temp = self._sub_word(temp)
                temp[0] ^= rcon[i // self.nk] # XOR with round constant
                # print(f"Key expansion i={i}, temp after RCON: {[hex(x) for x in temp]}") # Debug print
            elif self.nk > 6 and i % self.nk == 4: # Special case for AES-256 (nk=8)
                # Apply SubWord to the 4th word if nk=8
                temp = self._sub_word(temp)

            # The new word is the XOR of the word nk positions back and the 'temp' word
            prev_word = w[i - self.nk]
            # new_word = [w[i - self.nk][j] ^ temp[j] for j in range(4)] # Original way
            new_word = [prev_word[j] ^ temp[j] for j in range(4)] # Slightly clearer?
            w.append(new_word)

        # Now group the generated words 'w' into 4x4 round key matrices
        round_keys_list = []
        for i in range(0, total_words_needed, self.nb): # Iterate in steps of Nb (4)
            key_chunk_words = w[i : i + self.nb] # Get 4 words for this round key
            # Need to transpose these words to form the 4x4 matrix columns
            round_key_matrix = [
                [key_chunk_words[col_idx][row_idx] for col_idx in range(self.nb)]
                for row_idx in range(4)
            ]
            round_keys_list.append(round_key_matrix)

        return round_keys_list

    # --- Main Encryption/Decryption Methods for a Single Block ---
    def encrypt_block(self, plaintext_bytes):
        """Encrypts one 16-byte block of plaintext."""
        if len(plaintext_bytes) != 16:
            raise ValueError("Plaintext block must be 16 bytes exactly.")

        # Convert bytes to state matrix
        state = self._bytes_to_state(plaintext_bytes)

        # Initial AddRoundKey
        state = self._add_round_key(state, self.round_keys[0])

        # Main rounds (Nr - 1 rounds)
        for i in range(1, self.rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[i])
            # print(f"Encrypt Round {i} state: {self._state_to_bytes(state).hex()}") # Debug round state

        # Final round (no MixColumns)
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[self.rounds])

        # Convert final state matrix back to bytes
        return self._state_to_bytes(state)

    def decrypt_block(self, ciphertext_bytes):
        """Decrypts one 16-byte block of ciphertext."""
        if len(ciphertext_bytes) != 16:
             raise ValueError("Ciphertext block must be 16 bytes exactly.")

        # Convert bytes to state matrix
        state = self._bytes_to_state(ciphertext_bytes)

        # Initial AddRoundKey (using the last round key)
        state = self._add_round_key(state, self.round_keys[self.rounds])

        # Main rounds in reverse (Nr - 1 rounds)
        for i in range(self.rounds - 1, 0, -1):
            # Inverse operations applied in reverse order
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, self.round_keys[i])
            state = self._inv_mix_columns(state)
            # print(f"Decrypt Round {i} state: {self._state_to_bytes(state).hex()}") # Debug round state


        # Final round adjustments (inverse of final encryption round)
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, self.round_keys[0])

        # Convert final state matrix back to bytes
        return self._state_to_bytes(state)