import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import base64
import os
from gcm import GCM

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("My AES-GCM Tool")
        self.root.geometry("600x550")

        # Create an instance of our GCM implementation
        self.gcm = GCM()

        # Build the user interface
        self.create_widgets()

    def create_widgets(self):
        # Use tabs for encrypt/decrypt sections
        tab_control = ttk.Notebook(self.root)
        encrypt_tab = ttk.Frame(tab_control)
        decrypt_tab = ttk.Frame(tab_control)

        tab_control.add(encrypt_tab, text='Encrypt')
        tab_control.add(decrypt_tab, text='Decrypt')
        tab_control.pack(expand=1, fill="both", padx=5, pady=5) # Added some padding

        # Set up the content for each tab
        self.setup_encrypt_tab(encrypt_tab)
        self.setup_decrypt_tab(decrypt_tab)

    def setup_encrypt_tab(self, tab):
        # Frame to hold widgets in the encrypt tab
        main_frame = ttk.Frame(tab, padding="15") # Adjusted padding
        main_frame.pack(fill="both", expand=True)

        # Input text area
        ttk.Label(main_frame, text="Text to encrypt:").grid(row=0, column=0, sticky="w", pady=(0, 5))
        self.encrypt_input = tk.Text(main_frame, wrap=tk.WORD, height=8, relief=tk.SUNKEN, borderwidth=1) # Added some style
        self.encrypt_input.grid(row=1, column=0, sticky="nsew", pady=(0, 10))

        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        # Button to load text from a file
        ttk.Button(button_frame, text="Load from file", command=lambda: self.load_file(self.encrypt_input)).pack(side="left", padx=(0, 10))
        # Button to trigger encryption
        ttk.Button(button_frame, text="Encrypt", command=self.encrypt_text).pack(side="left")

        # Output text area for results
        ttk.Label(main_frame, text="Result (Nonce | Ciphertext | Tag) Base64:").grid(row=3, column=0, sticky="w", pady=(10, 5)) # Added margin top
        self.encrypt_output = tk.Text(main_frame, wrap=tk.WORD, height=8, relief=tk.SUNKEN, borderwidth=1) # Added some style
        self.encrypt_output.grid(row=4, column=0, sticky="nsew", pady=(0, 10))

        # Button to save the encryption result
        ttk.Button(main_frame, text="Save result", command=lambda: self.save_file(self.encrypt_output.get("1.0", "end-1c"))).grid(row=5, column=0, sticky="w", pady=(0, 10))

        # Area to display the generated key
        key_frame = ttk.LabelFrame(main_frame, text="Encryption Key Base64 (Save this!)")
        key_frame.grid(row=6, column=0, sticky="ew", pady=(10, 0))
        self.key_display = tk.Text(key_frame, wrap=tk.WORD, height=2, relief=tk.SUNKEN, borderwidth=1) # Added some style
        self.key_display.pack(fill="x", expand=True, padx=5, pady=5)

        # Configure resizing behavior
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1) # Input text area grows vertically
        main_frame.rowconfigure(4, weight=1) # Output text area grows vertically

    def setup_decrypt_tab(self, tab):
        # Frame to hold widgets in the decrypt tab
        main_frame = ttk.Frame(tab, padding="15") # Adjusted padding
        main_frame.pack(fill="both", expand=True)

        # Input area for encrypted data
        ttk.Label(main_frame, text="Encrypted text (Nonce | Ciphertext | Tag) Base64:").grid(row=0, column=0, sticky="w", pady=(0, 5))
        self.decrypt_input = tk.Text(main_frame, wrap=tk.WORD, height=8, relief=tk.SUNKEN, borderwidth=1) # Added some style
        self.decrypt_input.grid(row=1, column=0, sticky="nsew", pady=(0, 10))

        # Button to load encrypted data from file
        ttk.Button(main_frame, text="Load from file", command=lambda: self.load_file(self.decrypt_input)).grid(row=2, column=0, sticky="w", pady=(0, 10))

        # Input area for the decryption key
        key_frame = ttk.LabelFrame(main_frame, text="Decryption Key Base64")
        key_frame.grid(row=3, column=0, sticky="ew", pady=(10, 10)) # Added margin top
        self.key_input = tk.Text(key_frame, wrap=tk.WORD, height=2, relief=tk.SUNKEN, borderwidth=1) # Added some style
        self.key_input.pack(fill="x", expand=True, padx=5, pady=5)

        # Button to trigger decryption
        ttk.Button(main_frame, text="Decrypt", command=self.decrypt_text).grid(row=4, column=0, sticky="w", pady=(0, 10))

        # Output area for decrypted result
        ttk.Label(main_frame, text="Decrypted result:").grid(row=5, column=0, sticky="w", pady=(10, 5)) # Added margin top
        self.decrypt_output = tk.Text(main_frame, wrap=tk.WORD, height=8, relief=tk.SUNKEN, borderwidth=1) # Added some style
        self.decrypt_output.grid(row=6, column=0, sticky="nsew", pady=(0, 10))

        # Button to save the decrypted text
        ttk.Button(main_frame, text="Save result", command=lambda: self.save_file(self.decrypt_output.get("1.0", "end-1c"))).grid(row=7, column=0, sticky="w", pady=(0, 10))

        # Configure resizing
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1) # Encrypted input grows
        main_frame.rowconfigure(6, weight=1) # Decrypted output grows

    def encrypt_text(self):
        """Handles the encryption process when the 'Encrypt' button is clicked."""
        plaintext_str = self.encrypt_input.get(1.0, "end-1c").strip() # Get text from input box
        if not plaintext_str:
            messagebox.showwarning("Input Needed", "Please enter some text to encrypt.")
            return
        try:
            # Convert text to bytes (using UTF-8)
            plaintext_bytes = plaintext_str.encode("utf-8")

            # Generate a new random key (AES-128 = 16 bytes) and nonce (IV = 12 bytes for GCM standard)
            key = os.urandom(16)
            iv = os.urandom(12)
            # print(f"Generated Key (bytes): {key.hex()}") # Debug print
            # print(f"Generated IV (bytes): {iv.hex()}") # Debug print

            # Call our GCM implementation to encrypt
            ciphertext, tag = self.gcm.encrypt(key, iv, plaintext_bytes) # Added auth_data=b'' implicitly

            # Encode key, iv, ciphertext, and tag in Base64 for easy copy-paste/storage
            key_b64 = base64.b64encode(key).decode("utf-8")
            iv_b64 = base64.b64encode(iv).decode("utf-8")
            ciphertext_b64 = base64.b64encode(ciphertext).decode("utf-8")
            tag_b64 = base64.b64encode(tag).decode("utf-8")
            # print(f"Ciphertext (b64): {ciphertext_b64}") # Debug print
            # print(f"Tag (b64): {tag_b64}") # Debug print


            # Format the output string: Nonce | Ciphertext | Tag (Base64 encoded)
            # Using '|' as a separator, seemed sensible.
            encrypted_data_output = f"{iv_b64}|{ciphertext_b64}|{tag_b64}"

            # Display the results in the GUI
            self.encrypt_output.delete(1.0, tk.END)
            self.encrypt_output.insert(tk.END, encrypted_data_output)
            self.key_display.delete(1.0, tk.END)
            self.key_display.insert(tk.END, key_b64) # Display the key

            messagebox.showinfo("Encryption Successful", "Text encrypted.\nRemember to save the key and the result!")
        except Exception as e:
            # Show error message if anything went wrong
            messagebox.showerror("Encryption Failed", f"An unexpected error occurred:\n{str(e)}")

    def decrypt_text(self):
        """Handles the decryption process when the 'Decrypt' button is clicked."""
        encrypted_data_input = self.decrypt_input.get("1.0", "end-1c").strip() # Get from input box
        key_b64_input = self.key_input.get("1.0", "end-1c").strip() # Get key from input box

        # Basic check if inputs are provided
        if not encrypted_data_input or not key_b64_input:
            messagebox.showwarning("Input Needed", "Please provide the encrypted text and the decryption key.")
            return

        try:
            # Try to split the input string by the '|' separator
            parts = encrypted_data_input.split('|')
            if len(parts) != 3:
                # If it doesn't split into 3 parts, the format is wrong
                raise ValueError("Invalid format. Expected 'Nonce|Ciphertext|Tag' in Base64.")

            iv_b64, ciphertext_b64, tag_b64 = parts
            # print(f"Decrypting with IV (b64): {iv_b64}") # Debug print
            # print(f"Decrypting with Tag (b64): {tag_b64}") # Debug print

            # Decode the Base64 parts back into bytes
            key = base64.b64decode(key_b64_input)
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            tag = base64.b64decode(tag_b64)

            # Optional: Add warnings if decoded lengths seem wrong (though GCM.decrypt might catch this too)
            if len(key) != 16: messagebox.showwarning("Key Length", "Warning: Decoded key is not 16 bytes (expected for AES-128).")
            if len(iv) != 12: messagebox.showwarning("Nonce Length", "Warning: Decoded Nonce (IV) is not 12 bytes.")
            if len(tag) != 16: messagebox.showwarning("Tag Length", "Warning: Decoded Tag is not 16 bytes.")

            # Call our GCM implementation to decrypt and verify
            plaintext_bytes = self.gcm.decrypt(key, iv, ciphertext, tag) # Added auth_data=b'' implicitly

            # If GCM.decrypt succeeded (no ValueError for tag mismatch), decode bytes to string
            plaintext_str = plaintext_bytes.decode('utf-8')

            # Display the decrypted text
            self.decrypt_output.delete("1.0", tk.END)
            self.decrypt_output.insert(tk.END, plaintext_str)

            messagebox.showinfo("Decryption Successful", "Text decrypted and verified successfully.")

        except ValueError as e:
             # Catch specific errors like tag mismatch from GCM.decrypt or format errors
             messagebox.showerror("Decryption Failed", f"{str(e)}")
        except base64.binascii.Error as e:
             # Catch Base64 decoding errors specifically
             messagebox.showerror("Decryption Failed", f"Base64 decoding error: {str(e)}\nPlease check input format and key.")
        except Exception as e:
            # Catch any other unexpected errors during decryption
            messagebox.showerror("Decryption Failed", f"An unexpected error occurred:\n{str(e)}")


    def load_file(self, text_widget):
        """Opens a file dialog to load text into a specified text widget."""
        # Ask user to select a file
        file_path = filedialog.askopenfilename(
            title="Select a file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")] # Filter for text files
        )
        # If a file was selected (path is not empty)
        if file_path:
            try:
                # Try reading as UTF-8 first, as it's common
                try:
                    with open(file_path, 'r', encoding='utf-8') as file:
                        content = file.read()
                except UnicodeDecodeError:
                     # If UTF-8 fails, try latin-1 as a fallback (might work for some files)
                     # print(f"UTF-8 failed for {file_path}, trying latin-1") # Info print
                     with open(file_path, 'r', encoding='latin-1') as file:
                        content = file.read()
                     # Could add more fallbacks or ask user? Keeping it simple for now.

                # Clear the text widget and insert the file content
                text_widget.delete("1.0", tk.END)
                text_widget.insert(tk.END, content)
            except Exception as e:
                # Show error if file reading failed
                messagebox.showerror("File Load Error", f"Failed to read file:\n{str(e)}")

    def save_file(self, content):
        """Opens a file dialog to save the content of a text widget."""
        # Check if there is actually content to save
        if not content:
            messagebox.showwarning("Nothing to Save", "There is no content to save.")
            return
        # Ask user where to save the file
        file_path = filedialog.asksaveasfilename(
            title="Save file as...",
            defaultextension=".txt", # Default to .txt extension
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        # If a file path was chosen (not cancelled)
        if file_path:
            try:
                # Write the content to the file using UTF-8 encoding
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(content)
                messagebox.showinfo("Save Successful", f"File saved successfully:\n{file_path}")
            except Exception as e:
                # Show error if saving failed
                messagebox.showerror("File Save Error", f"Failed to save file:\n{str(e)}")