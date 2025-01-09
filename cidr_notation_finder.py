import tkinter as tk
from tkinter import messagebox
import ipaddress

# Define custom exceptions
class SubnetMaskError(Exception):
    def __init__(self, message="Invalid subnet mask format."):
        self.message = message
        super().__init__(self.message)

class SubnetError(Exception):
    def __init__(self, message="Invalid subnet format."):
        self.message = message
        super().__init__(self.message)

class CIDRConverter:
    def __init__(self):
        pass

    def convert_subnet_mask(self, subnet_mask):
        """ Convert subnet mask to CIDR notation (prefix length). """
        try:
            # Create an IP network with the given subnet mask
            network = ipaddress.ip_network(f'0.0.0.0/{subnet_mask}', strict=False)
            return network.prefixlen
        except ValueError:
            raise SubnetMaskError()

    def convert_subnet(self, subnet):
        """ Extract CIDR notation from a given subnet. """
        try:
            # Parse the subnet to get the prefix length
            network = ipaddress.ip_network(subnet, strict=False)
            return network.prefixlen
        except ValueError:
            raise SubnetError()

class CIDRApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("CIDR Notation Finder")
        self.geometry("400x300")
        
        self.converter = CIDRConverter()

        # Label
        self.title_label = tk.Label(self, text="CIDR Notation Finder", font=("Arial", 16))
        self.title_label.pack(pady=10)

        # Radio buttons for subnet option
        self.option_var = tk.StringVar(value="1")
        self.radio1 = tk.Radiobutton(self, text="Convert Subnet Mask to CIDR Notation", variable=self.option_var, value="1")
        self.radio1.pack(anchor="w")
        
        self.radio2 = tk.Radiobutton(self, text="Convert Subnet to CIDR Notation", variable=self.option_var, value="2")
        self.radio2.pack(anchor="w")
        
        # Entry field for subnet or subnet mask
        self.input_label = tk.Label(self, text="Enter subnet mask or subnet:")
        self.input_label.pack(pady=10)
        
        self.input_entry = tk.Entry(self, width=30)
        self.input_entry.pack(pady=5)

        # Button to convert
        self.convert_button = tk.Button(self, text="Convert", command=self.convert)
        self.convert_button.pack(pady=10)
        
        # Label to show result
        self.result_label = tk.Label(self, text="CIDR Notation: ", font=("Arial", 12))
        self.result_label.pack(pady=10)

    def convert(self):
        """ Handle conversion logic from user input. """
        choice = self.option_var.get()
        user_input = self.input_entry.get().strip()

        try:
            if choice == "1":
                # Convert subnet mask
                prefix_len = self.converter.convert_subnet_mask(user_input)
                self.result_label.config(text=f"CIDR Notation: /{prefix_len}")
            
            elif choice == "2":
                # Convert subnet
                prefix_len = self.converter.convert_subnet(user_input)
                self.result_label.config(text=f"CIDR Notation: /{prefix_len}")
            
            else:
                raise ValueError("Invalid option selected.")

        except SubnetMaskError as sme:
            messagebox.showerror("Error", sme)
        except SubnetError as se:
            messagebox.showerror("Error", se)
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    app = CIDRApp()
    app.mainloop()

