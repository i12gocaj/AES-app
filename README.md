# AES-GCM Encryption Application

The application allows you to do the following:

- **Encrypt text**: You write or load a text, and the application encrypts it using **AES-128 in GCM mode**.
- **Generate Key and Nonce**: For each encryption, it automatically generates:
  - a **16-byte secret key** (AES-128)
  - a **12-byte "Nonce"** (a random number that should not be repeated with the same key).
- **Show Results**: It displays:
  - the generated **key** (**very important to save it!**)
  - the **encryption result**, which includes the Nonce, the encrypted text, and the authentication tag — all encoded in **Base64** for easy copying.
- **Decrypt text**: You paste the encryption result (`Nonce|Ciphertext|Tag`) and the key you used, and the application tries to decrypt it.
- **Verify Integrity**: The most important part of decryption:
  - It recalculates the **authentication tag** and compares it with the one that came in the encrypted data.
  - If they don't match, it means the data was altered (or the key is incorrect), and the application will throw an **error** instead of showing corrupted data.
- **Graphical Interface**: A simple window with two tabs (**Encrypt** / **Decrypt**) built with **Tkinter**.
- **Load/Save**: Allows loading text from `.txt` files and saving the results (encrypted or decrypted text) in files as well.
