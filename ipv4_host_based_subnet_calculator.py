import ipaddress
import math
import re
import tkinter as tk
from tkinter import messagebox

# Custom exceptions (as provided earlier)
class InvalidHostCountError(Exception):
    def __init__(self, message="Number of hosts must be at least 1."):
        self.message = message
        super().__init__(self.message)

class InvalidIPError(Exception):
    def __init__(self, message="Invalid IP address format."):
        self.message = message
        super().__init__(self.message)

class InvalidPrefixError(Exception):
    def __init__(self, message="Invalid subnet prefix. Prefix must be between 0 and 32."):
        self.message = message
        super().__init__(self.message)

class InvalidNetworkError(Exception):
    def __init__(self, message="The IP address and prefix do not form a valid network."):
        self.message = message
        super().__init__(self.message)

class SubnetCalculator:
    def __init__(self, network_ip, num_hosts):
        self.network_ip = network_ip
        self.num_hosts = num_hosts
        self.validate_network_ip()
        self.prefix = self.calculate_prefix_for_hosts(num_hosts)
        self.network = ipaddress.IPv4Network(network_ip, strict=False)
        self.subnets = list(self.network.subnets(new_prefix=self.prefix))

    def validate_network_ip(self):
        try:
            network = ipaddress.IPv4Network(self.network_ip, strict=False)
        except ValueError:
            raise InvalidIPError()
        
        if not (0 <= network.prefixlen <= 32):
            raise InvalidPrefixError()
        
        if not validate_ipv4(self.network_ip.split('/')[0]):
            raise InvalidIPError()

    def calculate_prefix_for_hosts(self, num_hosts):
        if num_hosts < 1:
            raise InvalidHostCountError()
        
        prefix = 32 - math.ceil(math.log2(num_hosts + 2))
        return prefix

    def format_ip_mask(self, network):
        subnet_mask = network.netmask
        host_mask = ipaddress.IPv4Address(int(~int(subnet_mask)) & (2**32 - 1))
        return subnet_mask, host_mask

    def print_subnet_details(self):
        result = ""
        subnet_mask = ipaddress.IPv4Network(f'0.0.0.0/{self.prefix}').netmask
        result += f"Number of Usable Hosts per Subnet: {2**(32-self.prefix) - 2}\n"
        result += f"Subnet Mask: {subnet_mask}\n"
        result += f"Prefix: /{self.prefix}\n"
        
        result += "\nComplete List of Subnets:\n"
        for subnet in self.subnets:
            subnet_mask, host_mask = self.format_ip_mask(subnet)
            result += f"\nSubnet: {subnet}\n"
            result += f"Network Address: {subnet.network_address}\n"
            result += f"Host Range: {subnet.network_address + 1} - {subnet.broadcast_address - 1}\n"
            result += f"Broadcast Address: {subnet.broadcast_address}\n"
            result += f"Subnet Mask: {subnet_mask}\n"
            result += f"Host Mask: {host_mask}\n"
        
        return result

    def print_network_info(self):
        result = ""
        subnet_mask, host_mask = self.format_ip_mask(self.network)
        result += "\nSummary of the Network Information:\n"
        result += f"Network IP: {self.network_ip}\n"
        result += f"Subnet Mask: {subnet_mask}\n"
        result += f"Host Mask: {host_mask}\n"
        result += f"Network Address: {self.network.network_address}\n"
        result += f"Broadcast Address: {self.network.broadcast_address}\n"
        result += f"Number of Usable Hosts: {2**(32-self.network.prefixlen) - 2}\n"
        
        return result

def validate_ipv4(ip):
    pattern = re.compile(r'^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.' +
                         r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.' +
                         r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.' +
                         r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$')
    return pattern.match(ip) is not None

class SubnetCalculatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Subnet Calculator")

        # Input fields
        self.network_ip_label = tk.Label(root, text="Enter Network IP (e.g., 192.168.1.0/24):")
        self.network_ip_label.grid(row=0, column=0, padx=10, pady=10)
        self.network_ip_entry = tk.Entry(root, width=25)
        self.network_ip_entry.grid(row=0, column=1, padx=10, pady=10)

        self.num_hosts_label = tk.Label(root, text="Enter Number of Hosts per Subnet:")
        self.num_hosts_label.grid(row=1, column=0, padx=10, pady=10)
        self.num_hosts_entry = tk.Entry(root, width=25)
        self.num_hosts_entry.grid(row=1, column=1, padx=10, pady=10)

        # Create a frame for the output area and scrollbar
        self.output_frame = tk.Frame(root)
        self.output_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        # Scrollbar for output text box
        self.scrollbar = tk.Scrollbar(self.output_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Output display area (Text widget)
        self.result_text = tk.Text(self.output_frame, height=15, width=60, wrap=tk.WORD)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Attach scrollbar to the text widget
        self.result_text.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.result_text.yview)

        # Buttons
        self.calculate_button = tk.Button(root, text="Calculate", command=self.calculate_subnets)
        self.calculate_button.grid(row=2, column=0, columnspan=2, pady=10)

    def calculate_subnets(self):
        network_ip = self.network_ip_entry.get().strip()
        try:
            num_hosts = int(self.num_hosts_entry.get().strip())
            calculator = SubnetCalculator(network_ip, num_hosts)
            subnet_details = calculator.print_subnet_details()
            network_info = calculator.print_network_info()

            # Output the result
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, subnet_details + "\n" + network_info)

        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number of hosts.")
        except InvalidHostCountError as e:
            messagebox.showerror("Invalid Host Count", str(e))
        except InvalidIPError as e:
            messagebox.showerror("Invalid IP", str(e))
        except InvalidPrefixError as e:
            messagebox.showerror("Invalid Prefix", str(e))
        except InvalidNetworkError as e:
            messagebox.showerror("Invalid Network", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SubnetCalculatorApp(root)
    root.mainloop()
