import ipaddress
import math
import re
import tkinter as tk
from tkinter import messagebox

# Custom exceptions
class InvalidHostCountError(Exception):
    def __init__(self, message="Number of hosts must be at least 1."):
        self.message = message
        super().__init__(self.message)

class InvalidIPError(Exception):
    def __init__(self, message="Invalid IP address format."):
        self.message = message
        super().__init__(self.message)

class InvalidPrefixError(Exception):
    def __init__(self, message="Invalid subnet prefix. Prefix must be between 0 and 128."):
        self.message = message
        super().__init__(self.message)

class InvalidNetworkError(Exception):
    def __init__(self, message="The IP address and prefix do not form a valid network."):
        self.message = message
        super().__init__(self.message)

# Subnet Calculator for IPv6
class SubnetCalculatorIPv6:
    def __init__(self, network_ip, num_hosts):
        self.network_ip = network_ip
        self.num_hosts = num_hosts
        self.validate_network_ip()
        self.prefix = self.calculate_prefix_for_hosts(num_hosts)
        self.network = ipaddress.IPv6Network(network_ip, strict=False)
        self.subnets = list(self.network.subnets(new_prefix=self.prefix))

    def validate_network_ip(self):
        """ Validate if the network IP and prefix form a valid network. """
        if not validate_ipv6(self.network_ip.split('/')[0]):
            raise InvalidIPError()
        
        try:
            network = ipaddress.IPv6Network(self.network_ip, strict=False)
        except ValueError:
            raise InvalidNetworkError()
        
        if not (0 <= network.prefixlen <= 128):
            raise InvalidPrefixError()

    def calculate_prefix_for_hosts(self, num_hosts):
        """ Calculate the subnet prefix length required to accommodate the given number of hosts. """
        if num_hosts < 1:
            raise InvalidHostCountError()
        
        # For IPv6, calculate prefix to accommodate the given number of hosts.
        prefix = 128 - math.ceil(math.log2(num_hosts + 2))
        return min(max(prefix, 0), 128)

    def format_ip_mask(self, network):
        """ Return the subnet mask in a human-readable format. """
        return network.network_address

    def print_subnet_details(self):
        """ Print subnet details based on network IP and number of hosts per subnet. """
        result = ""
        num_hosts_per_subnet = 2**(128 - self.prefix) - 2
        result += f"\nSummary of the Subnet Information:\n"
        result += f"Number of Usable Hosts per Subnet: {num_hosts_per_subnet}\n"
        result += f"Prefix: /{self.prefix}\n"
        
        result += "\nComplete List of Subnets:\n"
        for subnet in self.subnets:
            subnet_mask = self.format_ip_mask(subnet)
            result += f"\nSubnet: {subnet}\n"
            result += f"Network Address: {subnet.network_address}\n"
            result += f"Host Range: {subnet.network_address + 1} - {subnet.broadcast_address - 1}\n"
            result += f"Broadcast Address: {subnet.broadcast_address}\n"
            result += f"Subnet Mask: {subnet_mask}\n"
        
        return result

    def print_network_info(self):
        """ Display subnet mask and network information for the given IP address with its prefix. """
        result = ""
        subnet_mask = self.format_ip_mask(self.network)
        num_hosts = 2**(128 - self.network.prefixlen) - 2
        result += "\nSummary of the Network Information:\n"
        result += f"Network IP: {self.network_ip}\n"
        result += f"Subnet Mask: {subnet_mask}\n"
        result += f"Network Address: {self.network.network_address}\n"
        result += f"Broadcast Address: {self.network.broadcast_address}\n"
        result += f"Number of Usable Hosts: {num_hosts}\n"
        
        return result

# Validate IPv6 address
def validate_ipv6(ip):
    """ Validate if the given IP address is a valid IPv6 address. """
    pattern = re.compile(r'^(?:[0-9a-fA-F]{1,4}:){7}(?:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|::)$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|::)$|^(?:[0-9a-fA-F]{1,4}:){1,5}:(?:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|::)$|^(?:[0-9a-fA-F]{1,4}:){1,4}:(?:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|::)$|^(?:[0-9a-fA-F]{1,4}:){1,3}:(?:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|::)$|^(?:[0-9a-fA-F]{1,4}:){1,2}:(?:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|::)$|^(?:[0-9a-fA-F]{1,4}:)(?:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|::)$|^(::)(?:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4})$')
    return pattern.match(ip) is not None

# Tkinter Application for Subnet Calculator
class SubnetCalculatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IPv6 Subnet Calculator")

        # Input fields
        self.network_ip_label = tk.Label(root, text="Enter Network IP (e.g., 2001:db8::/32):")
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
            calculator = SubnetCalculatorIPv6(network_ip, num_hosts)
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
