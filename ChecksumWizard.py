import hashlib
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog

# Custom Exception class for handling errors specific to ChecksumWizard
class ChecksumWizardError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

# Checksum Wizard Class to compute hash values for a given file
class ChecksumWizard:
    def __init__(self, file_path, checksum=None, selected_hash=None):
        self.hash_list = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'sha3_224': hashlib.sha3_224,
            'sha3_256': hashlib.sha3_256,
            'sha3_384': hashlib.sha3_384,
            'sha3_512': hashlib.sha3_512
        }
        self.checksum_values = []  # List to store computed checksum values
        self.file_path = file_path
        self.checksum = checksum  # Checksum value for comparison (for 'validate' mode)
        self.selected_hash = selected_hash  # Selected hash method
        self.bytes_content = None  # Content of the file to be read

    def source_file_analyzer(self):
        try:
            with open(self.file_path, 'rb') as binary_form_data:
                self.bytes_content = binary_form_data.read()
                print(f"File '{self.file_path}' successfully read.")
        except FileNotFoundError:
            raise ChecksumWizardError(f"File '{self.file_path}' not found.")
        except PermissionError:
            raise ChecksumWizardError(f"Permission denied while accessing '{self.file_path}'.")
        except Exception as e:
            raise ChecksumWizardError(f"Error in source_file_analyzer: {e}")

    def compute_checksum_for_binary_form_data(self):
        if self.bytes_content is None:
            raise ChecksumWizardError("No file content available. Please run source_file_analyzer() first.")
        
        if not self.selected_hash:
            raise ChecksumWizardError("No hash method selected.")
        
        hash_function = self.hash_list.get(self.selected_hash)
        if hash_function is None:
            raise ChecksumWizardError(f"Hash method '{self.selected_hash}' is not available.")
        
        hash_obj = hash_function()
        hash_obj.update(self.bytes_content)
        checksum = hash_obj.hexdigest()
        self.checksum_values.append((self.selected_hash, checksum))

    def verify_checksum(self):
        if not self.checksum_values:
            raise ChecksumWizardError("No checksums computed. Please run compute_checksum_for_binary_form_data() first.")
        
        if not self.checksum:
            raise ChecksumWizardError("No checksum provided for validation.")
        
        matched = False
        for method, computed_checksum in self.checksum_values:
            if self.checksum == computed_checksum:
                matched = True
                break

        return matched


# Tkinter UI Class
class ChecksumUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Checksum Wizard")
        self.geometry("700x500")
        self.file_path = ""
        self.checksum = ""
        self.selected_hash = tk.StringVar(value="md5")  # Default to 'md5' hash
        self.mode = tk.StringVar(value="generate")

        self.create_widgets()

    def create_widgets(self):
        # Title Label
        title_label = tk.Label(self, text="Checksum Wizard", font=("Helvetica", 18, "bold"))
        title_label.pack(pady=15)

        # Mode Selection (Generate / Validate) - in one line
        mode_frame = tk.Frame(self)
        mode_frame.pack(pady=10)

        self.radio_generate = tk.Radiobutton(mode_frame, text="Generate", variable=self.mode, value="generate", font=("Helvetica", 12))
        self.radio_validate = tk.Radiobutton(mode_frame, text="Validate", variable=self.mode, value="validate", font=("Helvetica", 12))
        self.radio_generate.pack(side=tk.LEFT, padx=15)
        self.radio_validate.pack(side=tk.LEFT, padx=15)

        # Hash method selection (radio buttons for hash methods, arranged in 3 lines)
        self.hash_category_label = tk.Label(self, text="Select Hash Method:", font=("Helvetica", 12))
        self.hash_category_label.pack(pady=10)

        self.hash_methods_frame = tk.Frame(self)
        self.hash_methods_frame.pack(pady=5)

        # Create the hash method radio buttons arranged in 3 rows (with 3 columns per row)
        row1 = ["md5", "sha1", "sha224"]
        row2 = ["sha256", "sha384", "sha512"]
        row3 = ["sha3_224", "sha3_256", "sha3_384", "sha3_512"]

        self.create_radio_buttons(row1, 0)
        self.create_radio_buttons(row2, 1)
        self.create_radio_buttons(row3, 2)

        # File path input and checksum validation input, and Start Process button
        self.input_frame = tk.Frame(self)
        self.input_frame.pack(pady=20)

        self.file_label = tk.Label(self.input_frame, text="File Path:", font=("Helvetica", 12))
        self.file_label.grid(row=0, column=0, padx=10, pady=5)

        self.file_entry = tk.Entry(self.input_frame, width=40, font=("Helvetica", 12))
        self.file_entry.grid(row=0, column=1, padx=10, pady=5)

        self.browse_button = tk.Button(self.input_frame, text="Browse", command=self.browse_file, font=("Helvetica", 12))
        self.browse_button.grid(row=0, column=2, padx=10, pady=5)

        # Checksum field visible only for validate mode
        self.checksum_label = tk.Label(self.input_frame, text="Checksum (for Validation):", font=("Helvetica", 12))
        self.checksum_label.grid(row=1, column=0, padx=10, pady=5)

        self.checksum_entry = tk.Entry(self.input_frame, width=40, font=("Helvetica", 12))
        self.checksum_entry.grid(row=1, column=1, padx=10, pady=5)

        self.start_button = tk.Button(self.input_frame, text="Start Process", command=self.compute_or_validate, font=("Helvetica", 12, "bold"), bg="#4CAF50", fg="white")
        self.start_button.grid(row=2, column=0, columnspan=3, pady=10)

        # Result area
        self.result_label = tk.Label(self, text="", font=("Helvetica", 12, "italic"), fg="blue")
        self.result_label.pack(pady=10)

        # Add "Copy to Clipboard" button for generated checksum
        self.copy_button = tk.Button(self, text="Copy to Clipboard", command=self.copy_to_clipboard, state=tk.DISABLED, font=("Helvetica", 12))
        self.copy_button.pack(pady=5)

        # Disable checksum entry in generate mode
        self.checksum_label.grid_forget()
        self.checksum_entry.grid_forget()

        self.mode.trace("w", self.toggle_checksum_entry)

    def create_radio_buttons(self, row_items, row_index):
        """ Create radio buttons for each hash method in a given row. """
        for col_index, item in enumerate(row_items):
            radio_button = tk.Radiobutton(self.hash_methods_frame, text=item.upper(), variable=self.selected_hash, value=item, font=("Helvetica", 10))
            radio_button.grid(row=row_index, column=col_index, padx=10, pady=5, sticky="w")

    def toggle_checksum_entry(self, *args):
        """ Toggle visibility of checksum entry field based on the mode. """
        if self.mode.get() == "validate":
            self.checksum_label.grid(row=1, column=0, padx=10, pady=5)
            self.checksum_entry.grid(row=1, column=1, padx=10, pady=5)
        else:
            self.checksum_label.grid_forget()
            self.checksum_entry.grid_forget()

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(title="Select a file", filetypes=[("All Files", "*.*")])
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, self.file_path)

    def compute_or_validate(self):
        file_path = self.file_entry.get()
        checksum = self.checksum_entry.get() if self.mode.get() == "validate" else None

        if not file_path:
            messagebox.showerror("Error", "Please select a file.")
            return

        # Get selected hash method
        selected_hash = self.selected_hash.get()

        if not selected_hash:
            messagebox.showerror("Error", "Please select a hash method.")
            return

        try:
            wizard = ChecksumWizard(file_path, checksum, selected_hash)

            # Read the file content
            wizard.source_file_analyzer()

            if self.mode.get() == "generate":
                # Compute the checksum
                wizard.compute_checksum_for_binary_form_data()

                # Display results
                result_text = f"{selected_hash.upper()}: {wizard.checksum_values[0][1]}"
                self.result_label.config(text=f"Computed Checksum:\n{result_text}")

                # Enable the "Copy to Clipboard" button
                self.copy_button.config(state=tk.NORMAL)

            elif self.mode.get() == "validate":
                if not checksum:
                    messagebox.showerror("Error", "Please provide a checksum for validation.")
                    return
                
                # Verify checksum
                valid = wizard.verify_checksum()
                if valid:
                    self.result_label.config(text="Checksum matched successfully.")
                else:
                    self.result_label.config(text="Checksum did not match.")

        except ChecksumWizardError as e:
            messagebox.showerror("Error", e.message)

    def copy_to_clipboard(self):
        checksum_text = self.result_label.cget("text").split("\n")[-1]  # Extract the last line (checksum value)
        self.clipboard_clear()
        self.clipboard_append(checksum_text)
        self.update()  # Update the window to ensure clipboard content is copied
        messagebox.showinfo("Success", "Checksum copied to clipboard.")

# Run the application
if __name__ == "__main__":
    app = ChecksumUI()
    app.mainloop()
