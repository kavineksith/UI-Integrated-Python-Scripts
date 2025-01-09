import tkinter as tk
from tkinter import messagebox, scrolledtext
import ipaddress
import json
import time
import os
import sys

# Custom Exception
class IPAddressError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

# Screen Manager Class
class ScreenManager:
    def __init__(self):
        self.clear_command = 'cls' if os.name == 'nt' else 'clear'

    def clear_screen(self):
        try:
            os.system(self.clear_command)
        except OSError as e:
            raise IPAddressError(f"Error clearing the screen: {e}")
        except KeyboardInterrupt:
            raise IPAddressError("Process interrupted by the user.")
        except Exception as e:
            raise IPAddressError(f"An error occurred: {e}")

# IPAddressConverter Class
class IPAddressConverter:
    def __init__(self, ip):
        self.ip = ip

    def to_decimal_and_hex(self):
        try:
            decimal_ip = int(ipaddress.ip_address(self.ip))
            hex_ip = hex(decimal_ip)
            return decimal_ip, hex_ip
        except ValueError as ve:
            raise IPAddressError(f"Error in to_decimal_and_hex: {ve}")

    def to_binary(self):
        try:
            binary_ip = format(int(ipaddress.ip_address(self.ip)), '032b')
            return binary_ip
        except ValueError as ve:
            raise IPAddressError(f"Error in to_binary: {ve}")

# SubnetCalculator Class
class SubnetCalculator:
    def __init__(self, ip, cidr):
        self.ip = ip
        self.cidr = cidr

    def calculate_subnet(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.network_address, network.netmask
        except ValueError as ve:
            raise IPAddressError(f"Error in calculate_subnet: {ve}")

    def subnet_mask_binary(self):
        try:
            subnet_mask = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False).netmask
            return bin(int(subnet_mask))
        except ValueError as ve:
            raise IPAddressError(f"Error in subnet_mask_binary: {ve}")

    def host_mask_calculator(self):
        try:
            host_mask = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False).hostmask
            return host_mask
        except ValueError as ve:
            raise IPAddressError(f"Error in host_mask_calculator: {ve}")

    def host_mask_binary(self):
        try:
            host_mask = self.host_mask_calculator()
            ip_version = ipaddress.ip_address(self.ip).version
            if ip_version == 4:
                return "{0:032b}".format(int(host_mask))
            else:
                raise ValueError("Invalid IP version")
        except ValueError as ve:
            raise IPAddressError(f"Error in host_mask_binary: {ve}")

    def subnet_binary(self):
        try:
            subnet = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False).network_address
            return format(int(subnet), '032b')
        except ValueError as ve:
            raise IPAddressError(f"Error in subnet_binary: {ve}")

    def usable_host_ip_range(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            usable_hosts = list(network.hosts())
            first_host, last_host = usable_hosts[0], usable_hosts[-1]
            ip_range_str = f"{first_host} - {last_host}"
            return ip_range_str
        except ValueError as ve:
            raise IPAddressError(f"Error in usable_host_ip_range: {ve}")

    def broadcast_address(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.broadcast_address
        except ValueError as ve:
            raise IPAddressError(f"Error in broadcast_address: {ve}")

    def total_number_of_hosts(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.num_addresses
        except ValueError as ve:
            raise IPAddressError(f"Error in total_number_of_hosts: {ve}")

    def number_of_usable_hosts(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            check_host_count = network.num_addresses - 2
            if check_host_count <= 0:
                return '0'
            else:
                return check_host_count
        except ValueError as ve:
            raise IPAddressError(f"Error in number_of_usable_hosts: {ve}")

    def network_address(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.network_address
        except ValueError as ve:
            raise IPAddressError(f"Error in network_address: {ve}")

    def cidr_notation(self):
        return self.cidr

    def ip_type(self):
        try:
            ip_obj = ipaddress.ip_address(self.ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                if ip_obj.is_private:
                    return "Private IPv4"
                elif ip_obj.is_loopback:
                    return "Loopback IPv4"
                elif ip_obj.is_link_local:
                    return "Link-local IPv4"
                elif ip_obj.is_reserved:
                    return "Reserved IPv4"
                elif ip_obj.is_unspecified:
                    return "APIPA (Automatic Private IP Addressing) IPv4"
                elif ip_obj.is_multicast:
                    return "Multicast IPv4"
                elif ip_obj.is_global:
                    return "Public IPv4"
            else:
                return "Other IPv4"
        except ValueError:
            return None
        
    def ip_addresses_range(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            usable_hosts = list(network.hosts())
            with open('./list.txt', 'a', encoding='utf-8') as ip_list:
                for host_ip in usable_hosts:
                    data = f'{str(host_ip)}\n'
                    ip_list.writelines(data)
                ip_list.close()
        except Exception as e:
            raise IPAddressError(f"Error in ip_addresses_range: {e}")

# Function to validate IP address format
def validate_ip_address(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Function to validate IPv4 class
def validate_ipv4_class(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            first_octet = int(ip.split('.')[0])
            if 1 <= first_octet <= 126:
                return 'A'
            elif 128 <= first_octet <= 191:
                return 'B'
            elif 192 <= first_octet <= 223:
                return 'C'
            elif first_octet == 127:
                return 'Loopback'
            elif first_octet == 0 or first_octet == 255:
                return 'Reserved'
            else:
                return 'Unknown'
    except ValueError:
        return None

# Function to validate user input
def validate_input(ip_version, ip_address, cidr):
    try:
        if not ip_version or ip_version.lower() not in ['ipv4']:
            raise IPAddressError(f"Invalid {ip_version} address.")

        if not ip_address:
            raise IPAddressError(f"Invalid {ip_version} address.")

        if not validate_ip_address(ip_address):
            raise IPAddressError(f"Invalid {ip_version} address.")

        cidr = int(cidr)  # convert cidr string to integer value

        if cidr < 0 or (ip_version == 'ipv4' and cidr > 32):
            raise IPAddressError("Invalid CIDR notation")

        return ip_address, cidr
    except Exception as e:
        raise IPAddressError(f"Input validation error: {e}")

# Function to chunk string into parts
def chunkstring(string, length):
    return (string[0 + i:length + i] for i in range(0, len(string), length))

# Function to format results for display as a json object
def result_to_display(labels, data):
    try:
        if len(labels) != len(data):
            raise IPAddressError("Lengths of labels and data do not match.")

        # Join labels and data into separate strings with each pair on a new line
        json_data = {label: value for label, value in zip(labels, data)}

        json_output = json.dumps(json_data, indent=4)

        return json_output  # Now returning the formatted JSON
    except Exception as e:
        raise IPAddressError(f"Error in result_to_display: {e}")


# Function to process data for an IP address
def data_process(usr_ip_address):
    try:
        given_ip_address, given_cidr = usr_ip_address.strip().split('/')
        ip_address, cidr = validate_input("ipv4", given_ip_address, given_cidr)

        ip_class = validate_ipv4_class(ip_address)

        subnet_calculator = SubnetCalculator(ip_address, int(cidr))
        ip_converter = IPAddressConverter(ip_address)

        ip_type = subnet_calculator.ip_type()
        network_address = subnet_calculator.network_address()
        broadcast_address = subnet_calculator.broadcast_address()
        total_hosts = subnet_calculator.total_number_of_hosts()
        usable_hosts = subnet_calculator.number_of_usable_hosts()
        cidr_notation = subnet_calculator.cidr_notation()
        usable_host_range = subnet_calculator.usable_host_ip_range()

        decimal_ip, hex_ip = ip_converter.to_decimal_and_hex()
        binary_ip = ip_converter.to_binary()

        subnet, subnet_mask = subnet_calculator.calculate_subnet()
        host_mask = subnet_calculator.host_mask_calculator()
        subnet_mask_bin = subnet_calculator.subnet_mask_binary()
        subnet_bin = subnet_calculator.subnet_binary()
        host_mask_bin = subnet_calculator.host_mask_binary()

        labels = [
            "IPv4 address",
            "IPv4 class",
            "IPv4 Type",
            "Network Address",
            "Broadcast Address",
            "Total Number of Hosts",
            "Number of Usable Hosts",
            "CIDR Notation",
            "Usable Host IP Range",
            "Decimal representation",
            "Hexadecimal representation",
            "Binary representation",
            "Subnet",
            "Subnet mask",
            "Host mask",
            "Subnet binary",
            "Subnet mask binary",
            "Host mask binary"
        ]

        data = [
            str(ip_address),
            str(ip_class),
            str(ip_type),
            str(network_address),
            str(broadcast_address),
            str(total_hosts),
            str(usable_hosts),
            f'/{cidr_notation}',
            str(usable_host_range),
            str(decimal_ip),
            str(hex_ip),
            '.'.join(chunkstring(binary_ip[0:], 8)),
            f'{subnet}/{cidr}',
            str(subnet_mask),
            str(host_mask),
            '.'.join(chunkstring(subnet_bin[0:], 8)),
            '.'.join(chunkstring(subnet_mask_bin[2:], 8)),
            '.'.join(chunkstring(host_mask_bin, 8))
        ]

        json_output = result_to_display(labels, data)
        return labels, data, json_output
    
    except IPAddressError as ipade:
        print(f'Error processing {usr_ip_address}: {ipade}')
        return f"Error: {ipade}", None, None
    except Exception as e:
        print(f"An error occurred processing {usr_ip_address}: {e}")
        return f"An error occurred: {e}", None, None


# Tkinter UI Class
class IPAddressApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Address Information")
        self.root.geometry("600x500")
        
        # IP Address Entry
        self.ip_label = tk.Label(root, text="Enter IP address and CIDR (e.g., 192.168.1.1/24):")
        self.ip_label.pack(pady=10)

        self.ip_entry = tk.Entry(root, width=40)
        self.ip_entry.pack(pady=10)

        # Process Button
        self.process_button = tk.Button(root, text="Process", command=self.process_ip)
        self.process_button.pack(pady=10)

        # Text Area for Results
        self.result_text = scrolledtext.ScrolledText(root, width=70, height=20, wrap=tk.WORD)
        self.result_text.pack(pady=20)

    def process_ip(self):
        ip_input = self.ip_entry.get()
        if ip_input:
            labels, data, json_output = data_process(ip_input)
            if isinstance(labels, str):  # If it's an error message
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, labels)
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, json_output)
        else:
            messagebox.showerror("Input Error", "Please enter a valid IP address and CIDR notation.")

# Run the Tkinter App
if __name__ == "__main__":
    root = tk.Tk()
    app = IPAddressApp(root)
    root.mainloop()

