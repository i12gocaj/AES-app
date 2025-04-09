import tkinter as tk
from gui import EncryptionApp

if __name__ == "__main__":
    # Create the main window
    root = tk.Tk()
    # Create an instance of our application class
    app = EncryptionApp(root)
    # Start the Tkinter event loop
    root.mainloop()