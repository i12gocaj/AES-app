from aes import AES
import os

# This is the GCM reduction polynomial x^128 + x^7 + x^2 + x + 1
# Needed for the Galois Field multiplication (_galois_multiply)
# The value 0xE1... is the representation used in right-shift algorithms.
GCM_POLY = 0xE1000000000000000000000000000000

class GCM:

    def _galois_multiply(self, x, y):
        """
        Performs multiplication in the GF(2^128) field defined by GCM_POLY.
        This is crucial for the GHASH function.
        Uses the right-shift method.
        """
        # print(f"Galois Multiply: x={hex(x)}, y={hex(y)}") # Debug print
        result = 0
        v = y # v will be updated in each step
        for i in range(127, -1, -1): # Iterate through bits of x from MSB to LSB
            if (x >> i) & 1:  # Check if the i-th bit of x is set
                result ^= v # If yes, XOR the current v into the result
            # Now update v for the next iteration (effectively v = v * alpha mod poly)
            if v & 1: # Check if the LSB of v is 1
                # If LSB is 1, right shift and XOR with the reduction polynomial
                v = (v >> 1) ^ GCM_POLY
            else:
                # If LSB is 0, just right shift
                v >>= 1
        # print(f"Galois Multiply result: {hex(result)}") # Debug print
        return result

    def _ghash(self, h_int, auth_data, ciphertext):
        """
        Calculates the GHASH value.
        Processes authenticated data (AAD) and ciphertext using _galois_multiply.
        Input H is the AES encryption of the zero block, as an integer.
        """

        def pad_to_16_bytes(data):
            """Helper to pad data with zeros to a multiple of 16 bytes (128 bits)."""
            # How much padding is needed? (16 - length % 16) unless length is already multiple of 16.
            padding_len = (16 - (len(data) % 16)) % 16
            return data + b'\x00' * padding_len

        y = 0 # Accumulator for GHASH, starts at zero.

        # Process Associated Data (AAD)
        padded_auth_data = pad_to_16_bytes(auth_data)
        # print(f"GHASH processing AAD blocks ({len(padded_auth_data)//16} blocks)") # Debug print
        for i in range(0, len(padded_auth_data), 16):
            block = padded_auth_data[i:i+16]
            block_int = int.from_bytes(block, 'big')
            y ^= block_int # XOR the block into the accumulator
            y = self._galois_multiply(y, h_int) # Multiply by H in the field
            # print(f"GHASH after AAD block {i//16}: {hex(y)}") # Debug print

        # Process Ciphertext
        padded_ciphertext = pad_to_16_bytes(ciphertext)
        # print(f"GHASH processing Ciphertext blocks ({len(padded_ciphertext)//16} blocks)") # Debug print
        for i in range(0, len(padded_ciphertext), 16):
            block = padded_ciphertext[i:i+16]
            block_int = int.from_bytes(block, 'big')
            y ^= block_int # XOR the block
            y = self._galois_multiply(y, h_int) # Multiply by H
            # print(f"GHASH after Ciph block {i//16}: {hex(y)}") # Debug print

        # Process the final block containing lengths of AAD and Ciphertext (in bits)
        # Lengths are 64-bit big-endian integers.
        len_a_bits = (len(auth_data) * 8).to_bytes(8, 'big')
        len_c_bits = (len(ciphertext) * 8).to_bytes(8, 'big')
        length_block_bytes = len_a_bits + len_c_bits # Concatenate lengths
        length_block_int = int.from_bytes(length_block_bytes, 'big')
        # print(f"GHASH processing Length block: {hex(length_block_int)}") # Debug print

        y ^= length_block_int # Final XOR with length block
        y = self._galois_multiply(y, h_int) # Final multiplication by H

        # print(f"GHASH final result: {hex(y)}") # Debug print
        return y.to_bytes(16, 'big') # Return result as 16 bytes


    def _gctr(self, aes_instance, initial_counter_block, data):
        """
        Implements the GCM Counter Mode (GCTR) for encryption/decryption.
        Uses AES to encrypt counter blocks and XORs with data.
        """
        if not data: # Handle empty data case
            return b''

        def increment_counter(counter_bytes):
            """
            Increments the counter block according to GCM rules.
            Only the last 32 bits (4 bytes) are incremented.
            """
            if len(counter_bytes) != 16:
                raise ValueError("Counter block must be 16 bytes for increment.")
            counter_int = int.from_bytes(counter_bytes, 'big')
            # Isolate the last 32 bits using a mask
            last_32_bits = counter_int & 0xFFFFFFFF
            # Increment the last 32 bits, handling wrap-around (modulo 2^32)
            incremented_last_32 = (last_32_bits + 1) & 0xFFFFFFFF
            # Combine the unchanged upper part with the new lower part
            new_counter_int = (counter_int & ~0xFFFFFFFF) | incremented_last_32
            return new_counter_int.to_bytes(16, 'big')

        output_data = b''
        current_counter = initial_counter_block # Start with the provided initial counter

        # Process data in 16-byte chunks
        for i in range(0, len(data), 16):
            data_block = data[i:i+16] # Get the current chunk of data
            # print(f"GCTR Counter IN: {current_counter.hex()}") # Debug print
            # Encrypt the current counter block using the AES instance
            encrypted_counter = aes_instance.encrypt_block(current_counter)
            # print(f"GCTR Encrypted Counter: {encrypted_counter.hex()}") # Debug print

            # XOR the encrypted counter with the data block
            # Need to handle the last block which might be shorter than 16 bytes
            block_len = len(data_block)
            xor_result = bytes(data_block[j] ^ encrypted_counter[j] for j in range(block_len))
            output_data += xor_result

            # Increment the counter for the next block
            current_counter = increment_counter(current_counter)

        return output_data


    def encrypt(self, key, iv, plaintext, auth_data=b''):
        """
        Encrypts plaintext and computes authentication tag using AES-GCM.
        Requires a key, a 12-byte IV (nonce), plaintext, and optional authenticated data.
        """
        # GCM standard strongly recommends 12-byte (96-bit) IVs for efficiency.
        if len(iv) != 12:
            # Could potentially implement the GHASH-based method for other IV lengths,
            # but sticking to the common case for now.
            raise ValueError("IV (nonce) must be 12 bytes for this implementation.")

        # Initialize AES cipher with the provided key
        aes = AES(key)

        # Calculate H, the GHASH key: H = AES_K(0^128)
        h_bytes = aes.encrypt_block(b'\x00' * 16)
        h_int = int.from_bytes(h_bytes, 'big')
        # print(f"Encrypt: H = {h_bytes.hex()}") # Debug print

        # Calculate J0, the pre-counter block.
        # For 12-byte IV: J0 = IV || 0x00000001 (12 bytes IV + 3 zero bytes + 1 byte 0x01)
        j0 = iv + b'\x00\x00\x00\x01'
        # print(f"Encrypt: J0 = {j0.hex()}") # Debug print

        # Calculate the Initial Counter Block (ICB) for GCTR.
        # According to NIST SP 800-38D, the first counter used is inc32(J0).
        icb_int = (int.from_bytes(j0, 'big') + 1) & ((1 << 128) - 1) # Increment J0 (mod 2^128)
        icb = icb_int.to_bytes(16, 'big')
        # print(f"Encrypt: ICB (CTR Start) = {icb.hex()}") # Debug print

        # Encrypt the plaintext using GCTR mode starting with ICB.
        ciphertext = self._gctr(aes, icb, plaintext)

        # Calculate the GHASH over AAD and ciphertext using H.
        ghash_result_bytes = self._ghash(h_int, auth_data, ciphertext)
        # print(f"Encrypt: GHASH(AAD, C) = {ghash_result_bytes.hex()}") # Debug print

        # Encrypt J0 to produce E(K, J0)
        encrypted_j0 = aes.encrypt_block(j0)
        # print(f"Encrypt: E(K, J0) = {encrypted_j0.hex()}") # Debug print

        # Compute the final authentication tag: Tag = GHASH(AAD, C) XOR E(K, J0)
        tag_int = int.from_bytes(ghash_result_bytes, 'big') ^ int.from_bytes(encrypted_j0, 'big')
        tag = tag_int.to_bytes(16, 'big')
        # print(f"Encrypt: Final Tag = {tag.hex()}") # Debug print

        # Return the ciphertext and the tag. The IV is known by the caller.
        return ciphertext, tag


    def decrypt(self, key, iv, ciphertext, tag, auth_data=b''):
        """
        Decrypts ciphertext and verifies authentication tag using AES-GCM.
        Returns plaintext if tag is valid, otherwise raises ValueError.
        """
        if len(iv) != 12:
            raise ValueError("IV (nonce) must be 12 bytes for this implementation.")
        if len(tag) != 16:
             raise ValueError("Authentication tag must be 16 bytes (128 bits).")

        # Initialize AES cipher
        aes = AES(key)

        # Calculate H = AES_K(0^128)
        h_bytes = aes.encrypt_block(b'\x00' * 16)
        h_int = int.from_bytes(h_bytes, 'big')
        # print(f"Decrypt: H = {h_bytes.hex()}") # Debug print

        # Calculate J0 from the IV
        j0 = iv + b'\x00\x00\x00\x01'
        # print(f"Decrypt: J0 = {j0.hex()}") # Debug print

        # Calculate the ICB for GCTR decryption (same as encryption: J0 + 1)
        icb_int = (int.from_bytes(j0, 'big') + 1) & ((1 << 128) - 1)
        icb = icb_int.to_bytes(16, 'big')
        # print(f"Decrypt: ICB (CTR Start) = {icb.hex()}") # Debug print

        # --- Tag Verification ---
        # Calculate the expected tag based on received AAD, ciphertext, and derived H, J0.
        ghash_calculated_bytes = self._ghash(h_int, auth_data, ciphertext)
        encrypted_j0 = aes.encrypt_block(j0)
        computed_tag_int = int.from_bytes(ghash_calculated_bytes, 'big') ^ int.from_bytes(encrypted_j0, 'big')
        computed_tag = computed_tag_int.to_bytes(16, 'big')
        # print(f"Decrypt: GHASH(AAD, C) = {ghash_calculated_bytes.hex()}") # Debug print
        # print(f"Decrypt: E(K, J0) = {encrypted_j0.hex()}") # Debug print
        # print(f"Decrypt: Computed Tag = {computed_tag.hex()}") # Debug print
        # print(f"Decrypt: Received Tag = {tag.hex()}") # Debug print

        # CRITICAL: Compare the computed tag with the received tag.
        # Use a constant-time comparison in real-world applications to prevent timing attacks.
        # For simplicity here, direct comparison is used.
        if computed_tag != tag:
            # If tags don't match, authentication fails. DO NOT return decrypted data.
            raise ValueError("Authentication failed: Tag mismatch.")
            # return None # Alternative: return None on failure instead of raising error? Let's stick with error.

        # --- Decryption ---
        # If the tag is valid, proceed to decrypt the ciphertext using GCTR.
        plaintext = self._gctr(aes, icb, ciphertext)

        # Return the decrypted plaintext.
        return plaintext