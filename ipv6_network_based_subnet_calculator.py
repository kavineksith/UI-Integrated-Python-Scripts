import ipaddress
import math
import re
import tkinter as tk
from tkinter import messagebox, scrolledtext

# Define custom exceptions
class InvalidNetworkCountError(Exception):
    def __init__(self, message="Number of networks must be at least 1."):
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

class SubnetCalculator:
    def __init__(self, network_ip, num_networks):
        self.network_ip = network_ip
        self.num_networks = num_networks
        self.network = None  # Initialize network as None to avoid reference errors
        self.subnets = []
        
        # Step 1: Validate the network IP address and its prefix
        self.validate_network_ip()

        # Step 2: Calculate the prefix for the requested number of networks
        self.prefix = self.calculate_prefix_for_networks(num_networks)
        
        # Step 3: Initialize the network object only if validation passed
        if self.network_ip:
            # Initialize the network object after validating
            self.network = ipaddress.IPv6Network(self.network_ip, strict=False)
            self.subnets = list(self.network.subnets(new_prefix=self.prefix))
        else:
            raise InvalidNetworkError("The IP address and prefix do not form a valid network.")

    def validate_network_ip(self):
        """ Validate if the network IP and prefix form a valid network. """
        try:
            network = ipaddress.IPv6Network(self.network_ip, strict=False)
        except ValueError:
            raise InvalidIPError()

        if not (0 <= network.prefixlen <= 128):
            raise InvalidPrefixError()

        if not self.validate_ipv6(self.network_ip.split('/')[0]):
            raise InvalidIPError()

        # After successful validation, assign the correct network_ip in CIDR format
        self.network_ip = network.with_prefixlen

    def calculate_prefix_for_networks(self, num_networks):
        """ Calculate the subnet prefix length required to accommodate the given number of networks. """
        if num_networks < 1:
            raise InvalidNetworkCountError()
        
        required_bits = math.ceil(math.log2(num_networks))
        current_prefix = ipaddress.IPv6Network(self.network_ip, strict=False).prefixlen
        new_prefix = current_prefix + required_bits
        
        if new_prefix > 128:
            raise InvalidPrefixError("Not enough address space to create the requested number of networks.")
        
        return new_prefix

    def format_ip_mask(self, network):
        """ Return the subnet mask and host mask in a human-readable format. """
        subnet_mask = network.network_address
        host_mask = ipaddress.IPv6Address(int(~int(network.network_address)) & (2**128 - 1))
        return subnet_mask, host_mask

    def get_subnet_details(self):
        """ Return subnet details based on network IP and number of networks. """
        result = []
        subnet_mask = ipaddress.IPv6Network(f'::/{self.prefix}').network_address
        result.append(f"Number of Usable Networks: {len(self.subnets)}")
        result.append(f"Subnet Mask: {subnet_mask}")
        result.append(f"Prefix: /{self.prefix}")
        
        result.append("\nComplete List of Subnets:")
        for subnet in self.subnets:
            subnet_mask, host_mask = self.format_ip_mask(subnet)
            first_usable_ip = subnet.network_address + 1
            last_usable_ip = subnet.broadcast_address - 1
            result.append(f"\nSubnet: {subnet}")
            result.append(f"Network Address: {subnet.network_address}")
            result.append(f"First Usable IP: {first_usable_ip}")
            result.append(f"Last Usable IP: {last_usable_ip}")
            result.append(f"Broadcast Address: {subnet.broadcast_address}")
            result.append(f"Subnet Mask: {subnet_mask}")
            result.append(f"Host Mask: {host_mask}")
        
        return "\n".join(result)

    def get_network_info(self):
        """ Return network mask and network information for the given IP address with its prefix. """
        subnet_mask, host_mask = self.format_ip_mask(self.network)
        result = []
        result.append(f"Network IP: {self.network_ip}")
        result.append(f"Subnet Mask: {subnet_mask}")
        result.append(f"Host Mask: {host_mask}")
        result.append(f"Network Address: {self.network.network_address}")
        result.append(f"Broadcast Address: {self.network.broadcast_address}")
        result.append(f"Number of Usable Hosts: {2**(128-self.network.prefixlen) - 2}")
        
        return "\n".join(result)

    def validate_ipv6(self, ip):
        """ Validate if the given IP address is a valid IPv6 address. """
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False


class SubnetCalculatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IPv6 Subnet Calculator")

        # Set window size
        self.root.geometry("800x600")
        
        # Network IP label and entry
        self.network_ip_label = tk.Label(root, text="Network IP Address (e.g., 2001:db8::/32):")
        self.network_ip_label.pack(pady=5)
        self.network_ip_entry = tk.Entry(root, width=40)
        self.network_ip_entry.pack(pady=5)

        # Number of networks label and entry
        self.num_networks_label = tk.Label(root, text="Number of Networks:")
        self.num_networks_label.pack(pady=5)
        self.num_networks_entry = tk.Entry(root, width=40)
        self.num_networks_entry.pack(pady=5)

        # Calculate button
        self.calculate_button = tk.Button(root, text="Calculate Subnets", command=self.calculate_subnets)
        self.calculate_button.pack(pady=10)

        # Results output area
        self.result_area = scrolledtext.ScrolledText(root, width=70, height=15)
        self.result_area.pack(pady=5)

    def calculate_subnets(self):
        """ Function to handle the button click event. """
        try:
            # Retrieve inputs
            network_ip = self.network_ip_entry.get().strip()
            num_networks = int(self.num_networks_entry.get().strip())

            # Create subnet calculator instance
            calculator = SubnetCalculator(network_ip, num_networks)

            # Clear the result area and display the results
            self.result_area.delete(1.0, tk.END)
            subnet_details = calculator.get_subnet_details()
            network_info = calculator.get_network_info()
            self.result_area.insert(tk.END, subnet_details + "\n\n" + network_info)

        except InvalidNetworkCountError as e:
            messagebox.showerror("Error", str(e))
        except InvalidIPError as e:
            messagebox.showerror("Error", str(e))
        except InvalidPrefixError as e:
            messagebox.showerror("Error", str(e))
        except InvalidNetworkError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"An unexpected error occurred: {str(e)}")


if __name__ == "__main__":
    # Create Tkinter window
    root = tk.Tk()
    app = SubnetCalculatorApp(root)
    root.mainloop()
