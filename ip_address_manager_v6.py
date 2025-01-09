import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext
import ipaddress
import json
import time
import os
import sys


class IPAddressError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class IPAddressConverter:
    def __init__(self, ip):
        self.ip = ip

    def to_hex(self):
        try:
            # Convert IPv6 Address to Hexadecimal
            decimal_ip = int(ipaddress.IPv6Address(self.ip))
            # hex_ip = hex(decimal_ip)
            hex_ip = format(decimal_ip, 'x')  # Convert integer to hexadecimal string
            return hex_ip
        except Exception as e:
            raise IPAddressError(f"Error in to_hex: {e}")

    def to_binary(self):
        try:
            # Convert IPv6 address to packed bytes and then to binary string
            binary_ip = format(int(ipaddress.IPv6Address(self.ip)), '0128b')
            return binary_ip
        except Exception as e:
            raise IPAddressError(f"Error in to_binary: {e}")

    def to_decimal(self):
        try:
            decimal_ip = int(ipaddress.IPv6Address(self.ip))
            return decimal_ip
        except Exception as e:
            raise IPAddressError(f"Error in to_decimal: {e}")


class SubnetCalculator:
    def __init__(self, ip, cidr):
        self.ip = ip
        self.cidr = cidr

    def calculate_subnet(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.network_address, network.netmask
        except Exception as e:
            raise IPAddressError(f"Error in calculate_subnet: {e}")

    def subnet_mask_binary(self):
        try:
            subnet_mask = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False).netmask
            binary_subnet_mask = bin(int(subnet_mask))[2:]  # Remove '0b' prefix
            return binary_subnet_mask.zfill(128)  # Pad with zeros to ensure 128 bits
        except Exception as e:
            raise IPAddressError(f"Error in subnet_mask_binary: {e}")

    def host_mask_calculator(self):
        try:
            host_mask = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False).hostmask
            return host_mask
        except Exception as e:
            raise IPAddressError(f"Error in host_mask_calculator: {e}")

    def host_mask_binary(self):
        try:
            host_mask = self.host_mask_calculator()
            # For IPv6, use 128 bits
            return "{0:0128b}".format(int(host_mask))
        except Exception as e:
            raise IPAddressError(f"Error in host_mask_binary: {e}")

    def subnet_binary(self):
        try:
            subnet = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False).network_address
            return format(int(subnet), '0128b')
        except Exception as e:
            raise IPAddressError(f"Error in subnet_binary: {e}")

    def usable_host_ip_range(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            subnet = network.network_address
            broadcast = network.broadcast_address
            first_usable = subnet + 1
            last_usable = broadcast - 1
            return first_usable, last_usable
        except Exception as e:
            raise IPAddressError(f"Error in usable_host_ip_range: {e}")

    def broadcast_address(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.broadcast_address
        except Exception as e:
            raise IPAddressError(f"Error in broadcast_address: {e}")

    def total_number_of_hosts(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.num_addresses
        except Exception as e:
            raise IPAddressError(f"Error in total_number_of_hosts: {e}")

    def number_of_usable_hosts(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            check_host_count = network.num_addresses - 2
            if check_host_count <= 0:
                return 0
            else:
                return check_host_count
        except ValueError as e:
            raise IPAddressError(f"Error in number_of_usable_hosts: {e}")

    def network_address(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.network_address
        except ValueError as e:
            raise IPAddressError(f"Error in network_address: {e}")

    def cidr_notation(self):
        return self.cidr

    def ip_type(self):
        try:
            ip_obj = ipaddress.ip_address(self.ip)
            if isinstance(ip_obj, ipaddress.IPv6Address):
                if ip_obj.is_private:
                    return "Private IPv6"
                elif ip_obj.is_loopback:
                    return "Loopback IPv6"
                elif ip_obj.is_link_local:
                    return "Link-local IPv6"
                elif ip_obj.is_site_local:
                    return 'Site-local IPv6'
                elif ip_obj.is_reserved:
                    return "Reserved IPv6"
                elif ip_obj.is_unspecified:
                    return "APIPA (Automatic Private IP Addressing) IPv6"
                elif ip_obj.is_global:
                    return "Public IPv6"
                elif ip_obj.ipv4_mapped:
                    return 'IPv4-Mapped IPv6'
                else:
                    # For other IPv6 addresses, check if it's multicast
                    if ip_obj.is_multicast:
                        return 'Multicast IPv6'
                    else:
                        return 'Global Unicast IPv6'
            else:
                return "Other IPv6"
        except Exception as e:
            raise IPAddressError(f"Error in ip_type: {e}")


# Function to chunk a string into smaller parts of a specified length
def chunkstring(string, length, delimiter=':'):
    if len(string) % length != 0:
        raise IPAddressError("String length is not a multiple of chunk length.")
    
    if delimiter in string:
        # IPv6 binary representation with delimiters
        chunks = [string[i:i + length] for i in range(0, len(string), length)]
        return delimiter.join(chunks)
    else:
        # IPv6 binary representation without delimiters
        chunks = [string[i:i + length] for i in range(0, len(string), length)]
        return '.'.join(chunks)


def hex_ip_formatter(hex_ip_raw):
    # Format Hexadecimal String with Colons
    hex_ip_formatted = ':'.join(hex_ip_raw[i:i+4] for i in range(0, len(hex_ip_raw), 4))
    return hex_ip_formatted


def result_to_display(labels, data):
    try:
        # Ensure both labels and data have the same length
        if len(labels) != len(data):
            raise ValueError("Lengths of labels and data do not match.")

        # Loop through each label and its corresponding data value and
        # create a dictionary pairing labels with data
        json_data = {label: value for label, value in zip(labels, data)}

        # Convert the dictionary to JSON string
        json_output = json.dumps(json_data, indent=4)
        return json_output
    except Exception as e:
        raise IPAddressError(f"Error in result_to_display: {e}")


def data_process(usr_ip_address):
    try:
        given_ip_address, given_cidr = usr_ip_address.strip().split('/')
        subnet_calculator = SubnetCalculator(given_ip_address, int(given_cidr))

        ip_type = subnet_calculator.ip_type()
        network_address = subnet_calculator.network_address()
        broadcast_address = subnet_calculator.broadcast_address()
        total_hosts = subnet_calculator.total_number_of_hosts()
        usable_hosts = subnet_calculator.number_of_usable_hosts()
        cidr_notation = subnet_calculator.cidr_notation()
        usable_host_range_start, usable_host_range_end = subnet_calculator.usable_host_ip_range()
        usable_host_range_str = f"{usable_host_range_start} - {usable_host_range_end}" if usable_host_range_start and usable_host_range_end else "N/A"

        ip_converter = IPAddressConverter(given_ip_address)
        binary_ip = ip_converter.to_binary()
        decimal_ip = ip_converter.to_decimal()
        hex_ip_raw = ip_converter.to_hex()
        # hex_ip = ipaddress.IPv6Address(hex_ip_raw).exploded
        hex_ip = hex_ip_formatter(hex_ip_raw)
        simplified_hex_ip = ipaddress.IPv6Address(hex_ip)
        standard_ip_address = simplified_hex_ip.exploded

        subnet_calculator = SubnetCalculator(given_ip_address, int(given_cidr))
        subnet, subnet_mask = subnet_calculator.calculate_subnet()
        subnet_mask_bin = subnet_calculator.subnet_mask_binary()
        subnet_bin = subnet_calculator.subnet_binary()
        host_mask = subnet_calculator.host_mask_calculator()
        host_mask_bin = subnet_calculator.host_mask_binary()

        # Convert subnet, subnet mask, and host mask to hexadecimal
        subnet_hex = subnet.exploded
        subnet_mask_hex = subnet_mask.exploded
        host_mask_hex = ipaddress.IPv6Address(int(host_mask_bin, 2)).exploded

        labels = [
            "IPv6 address",
            "IPv6 Type",
            "Network Address",
            "Broadcast Address",
            "Total Number of Hosts",
            "Number of Usable Hosts",
            "CIDR Notation",
            "Usable Host IP Range",
            "Decimal representation",
            "Hexadecimal representation",
            "Binary representation",
            "Shorthand IPv6 Address",
            "Standard IPv6 Address",
            "Subnet",
            "Subnet mask",
            "Host mask",
            "Subnet binary",
            "Subnet mask binary",
            "Host mask binary",
            "Subnet hexadecimal representation",
            "Subnet mask hexadecimal representation",
            "Host mask hexadecimal representation",
            "Subnet decimal representation",
            "Subnet mask decimal representation",
            "Host mask decimal representation"
        ]

        data = [
            str(given_ip_address),
            str(ip_type),
            str(network_address),
            str(broadcast_address),
            str(total_hosts),
            str(usable_hosts),
            f'/{cidr_notation}',
            str(usable_host_range_str),
            str(decimal_ip),
            str(hex_ip),
            str(chunkstring(binary_ip, 8, '.')),
            str(simplified_hex_ip),
            str(standard_ip_address),
            f'{subnet}/{given_cidr}',
            str(subnet_mask),
            str(host_mask),
            str(chunkstring(subnet_bin, 8)),
            str(chunkstring(subnet_mask_bin, 8)),
            str(chunkstring(host_mask_bin, 8)),
            str(subnet_hex),
            str(subnet_mask_hex),
            str(host_mask_hex),
            str(int(subnet)),
            str(int(subnet_mask)),
            str(int(host_mask_bin, 2))
        ]

        result = result_to_display(labels, data)
        return result

    except Exception as e:
        raise IPAddressError(f"Error in data_process: {e}")


class IPAddressConverterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IPv6 Address Calculator")
        self.root.geometry("800x600")
        
        # Set up the UI components
        self.setup_ui()
        
    def setup_ui(self):
        # Input Section
        self.ip_label = tk.Label(self.root, text="Enter IPv6 Address and CIDR (e.g. 2001:0db8::1/64):")
        self.ip_label.pack(pady=10)
        
        self.ip_entry = tk.Entry(self.root, width=50)
        self.ip_entry.pack(pady=5)
        
        # Button to trigger calculation
        self.calc_button = tk.Button(self.root, text="Calculate", command=self.calculate_ip)
        self.calc_button.pack(pady=10)
        
        # Results Section
        self.results_label = tk.Label(self.root, text="Results:")
        self.results_label.pack(pady=10)
        
        self.result_text = scrolledtext.ScrolledText(self.root, height=15, width=80)
        self.result_text.pack(pady=10)
        
    def calculate_ip(self):
        try:
            usr_ip_address = self.ip_entry.get()
            if not usr_ip_address:
                raise ValueError("IPv6 Address is required.")
            
            # Call the processing function (replace with your own processing logic)
            result = data_process(usr_ip_address)  # Assuming this function is in your script
            
            # Display the result in the scrolled text area
            self.result_text.delete(1.0, tk.END)  # Clear previous results
            self.result_text.insert(tk.END, result)  # Insert new results
            
        except ValueError as ve:
            messagebox.showerror("Input Error", f"Invalid input: {ve}")
        except IPAddressError as ip_err:
            messagebox.showerror("IP Address Error", f"Error processing IP Address: {ip_err.message}")
        except Exception as e:
            messagebox.showerror("Unknown Error", f"An unexpected error occurred: {e}")
        
# Main Program
def main():
    root = tk.Tk()
    app = IPAddressConverterApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()