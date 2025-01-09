import tkinter as tk
from tkinter import messagebox
import string
import secrets
import random

# Password Generation Logic
class CharacterLake:
    def __init__(self):
        """Initialize CharacterLake with character sets for password generation."""
        self.letters = string.ascii_letters
        self.digits = string.digits
        self.special_chars = string.punctuation

    def get_characters(self):
        """Return a string of all characters for password generation."""
        return self.letters + self.digits + self.special_chars

class PasswordGenerator:
    def __init__(self):
        """Initialize PasswordGenerator with CharacterLake for password creation."""
        self.character_lake = CharacterLake()

    def generate_password(self, length, secure=False):
        """
        Generate a password of the given length.
        
        :param length: Length of the password to be generated.
        :param secure: If True, use secrets.choice for a more secure password.
        :return: The generated password as a string.
        """
        characters = self.character_lake.get_characters()
        if secure:
            password = ''.join(secrets.choice(characters) for _ in range(length))
        else:
            password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def generate_secure_password(self, length):
        """
        Generate a secure password of the given length.
        
        A secure password must include at least one special character and at least five digits.
        
        :param length: Length of the password to be generated.
        :return: The generated secure password as a string.
        """
        digits = self.character_lake.digits
        special_chars = self.character_lake.special_chars

        while True:
            password = self.generate_password(length, secure=True)
            if (any(char in special_chars for char in password) and sum(char in digits for char in password) >= 5):
                return password

class PasswordApp(tk.Tk):
    def __init__(self):
        super().__init__()

        # Set up window
        self.title("Password Generator")
        self.geometry("400x300")

        # Initialize password generator
        self.password_generator = PasswordGenerator()

        # Password category (normal or secure)
        self.password_category = tk.IntVar(value=1)  # Default to normal password

        # Length Entry
        self.length_label = tk.Label(self, text="Password Length:")
        self.length_label.pack(pady=5)

        self.length_entry = tk.Entry(self)
        self.length_entry.pack(pady=5)

        # Radio buttons for password category
        self.normal_radio = tk.Radiobutton(self, text="Normal", variable=self.password_category, value=1)
        self.normal_radio.pack(pady=5)

        self.secure_radio = tk.Radiobutton(self, text="Secure", variable=self.password_category, value=2)
        self.secure_radio.pack(pady=5)

        # Generate Password Button
        self.generate_button = tk.Button(self, text="Generate Password", command=self.generate_password)
        self.generate_button.pack(pady=10)

        # Password Output Display
        self.password_output = tk.Entry(self, width=40)
        self.password_output.pack(pady=5)

        # Clipboard Button (Using Tkinter's built-in clipboard functionality)
        self.copy_button = tk.Button(self, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack(pady=5)

    def generate_password(self):
        try:
            # Get password length from entry
            length = int(self.length_entry.get())
            if length <= 0:
                raise ValueError("Password length must be a positive integer.")

            # Determine the category and generate the password
            category = self.password_category.get()
            if category == 1:
                password = self.password_generator.generate_password(length)
            elif category == 2:
                password = self.password_generator.generate_secure_password(length)

            # Display the generated password
            self.password_output.delete(0, tk.END)  # Clear previous password
            self.password_output.insert(0, password)  # Insert new password

        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))

    def copy_to_clipboard(self):
        # Copy the generated password to the clipboard using Tkinter's clipboard methods
        password = self.password_output.get()
        if password:
            self.clipboard_clear()  # Clear existing clipboard content
            self.clipboard_append(password)  # Append the new password to the clipboard
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("No Password", "Please generate a password first.")

# Run the application
if __name__ == "__main__":
    app = PasswordApp()
    app.mainloop()
