import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import socket
import struct
import sys
import csv
from pathlib import Path


class PortScanner:
    def __init__(self, ip_address, start_port, end_port):
        self.ip_address = ip_address
        self.start_port = int(start_port)
        self.end_port = int(end_port)
        self.results = []

    def scan_tcp_ports(self):
        try:
            for port in range(self.start_port, self.end_port + 1):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                result = s.connect_ex((self.ip_address, port))
                if result == 0:
                    service = self.get_service_name(port, 'tcp')
                    banner = self.grab_banner_tcp(s)
                    self.results.append((port, service, "Open", self.ip_address, banner))
                else:
                    self.results.append((port, "Unknown", "Closed", self.ip_address, "Unknown"))
                s.close()
        except KeyboardInterrupt:
            print("Operation interrupted by user.")
            sys.exit(1)
        except socket.gaierror:
            print("IP address couldn't be resolved.")
            sys.exit(1)
        except socket.error:
            print("Couldn't connect to server.")
            sys.exit(1)

    def grab_banner_tcp(self, s):
        try:
            # Receive up to 1024 bytes of data from the socket
            banner = s.recv(1024)
            if banner:
                return banner.decode().strip('\n').strip('\r').splitlines()[0]  # Only return the first line
            else:
                return "Unknown"
        except ConnectionError as e:
            print(f"Connection error occurred: {e}")
            sys.exit(1)
        except TimeoutError as e:
            print(f"Timeout error occurred: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            sys.exit(1)

    def scan_udp_ports(self):
        try:
            for port in range(self.start_port, self.end_port + 1):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                s.sendto(b'', (self.ip_address, port))
                try:
                    response, _ = s.recvfrom(1024)
                    service = self.get_service_name(port, 'udp')
                    self.results.append((port, service, "Open", self.ip_address, "Unknown"))
                except socket.timeout:
                    self.results.append((port, "Unknown", "Closed", self.ip_address, "Unknown"))
                finally:
                    s.close()
        except KeyboardInterrupt:
            print("Operation interrupted by user.")
            sys.exit(1)
        except socket.gaierror:
            print("IP address couldn't be resolved.")
            sys.exit(1)
        except socket.error:
            print("Couldn't connect to server.")
            sys.exit(1)

    def scan_icmp_ports(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.settimeout(2)
            packet_id = 12345  # Random packet ID
            sequence = 1  # Sequence number
            icmp_request = self.create_icmp_request(packet_id, sequence)
            s.sendto(icmp_request, (self.ip_address, 0))  # Sending to port 0 as ICMP doesn't have ports
            try:
                response, _ = s.recvfrom(1024)
                if self.is_icmp_response_valid(response, packet_id):
                    self.results.append(("ICMP", "Echo Reply", "Open", self.ip_address, "Unknown"))
                else:
                    self.results.append(("ICMP", "No response", "Closed", self.ip_address, "Unknown"))
            except socket.timeout:
                self.results.append(("ICMP", "No response", "Closed", self.ip_address, "Unknown"))
            finally:
                s.close()
        except KeyboardInterrupt:
            print("Operation interrupted by user.")
            sys.exit(1)
        except socket.gaierror:
            print("IP address couldn't be resolved.")
            sys.exit(1)
        except socket.error:
            print("Couldn't connect to server.")
            sys.exit(1)

    def create_icmp_request(self, packet_id, sequence):
        # ICMP Echo Request packet structure: Type (8 bits), Code (8 bits), Checksum (16 bits), Identifier (16 bits),
        # Sequence Number (16 bits)
        icmp_type = 8  # ICMP Echo Request type
        icmp_code = 0  # ICMP Echo Request code
        icmp_checksum = 0  # Placeholder for checksum calculation
        icmp_identifier = packet_id
        icmp_seq_number = sequence
        # Constructing the packet
        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_seq_number)
        icmp_checksum = self.calculate_checksum(icmp_header)
        # Reconstructing the packet with correct checksum
        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_seq_number)
        return icmp_header

    def calculate_checksum(self, data):
        # ICMP uses a checksum calculated over the ICMP header and data, with the checksum field itself zeroed out
        # Checksum is calculated by summing up 16-bit words and taking the one's complement
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + (data[i + 1])
            checksum += word
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        return checksum

    def is_icmp_response_valid(self, response, packet_id):
        # Validate ICMP Echo Reply response by checking packet ID
        icmp_type = response[20]  # ICMP Type is at offset 20
        icmp_code = response[21]  # ICMP Code is at offset 21
        if icmp_type == 0 and icmp_code == 0:  # ICMP Type 0 (Echo Reply), Code 0
            received_packet_id = response[24] << 8 | response[25]  # Packet ID is at offset 24-25
            if received_packet_id == packet_id:
                return True
        return False

    def get_service_name(self, port, protocol):
        try:
            service_name = socket.getservbyport(port, protocol)
            return service_name
        except OSError:
            return "Unknown"
        except Exception as e:
            print(f"An error occurred: {e}")
            sys.exit(1)


class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")
        self.root.geometry("900x600")

        # Set up the UI components
        self.setup_ui()

    def setup_ui(self):
        # IP Address Section
        self.ip_label = tk.Label(self.root, text="Enter IP Address:")
        self.ip_label.pack(pady=10)

        self.ip_entry = tk.Entry(self.root, width=40)
        self.ip_entry.pack(pady=5)

        # Port Range Section
        self.port_label = tk.Label(self.root, text="Enter Port Range (Start-Port, End-Port):")
        self.port_label.pack(pady=10)

        self.port_range_entry = tk.Entry(self.root, width=40)
        self.port_range_entry.pack(pady=5)

        # Scan Type Section
        self.scan_type_label = tk.Label(self.root, text="Select Scan Type:")
        self.scan_type_label.pack(pady=10)

        self.scan_type = tk.StringVar()
        self.scan_type.set("tcp")  # Default selection

        # Create a frame for radio buttons to appear in the same line
        radio_frame = tk.Frame(self.root)
        radio_frame.pack(pady=5)

        # Place radio buttons in the frame
        self.scan_tcp_radio = tk.Radiobutton(radio_frame, text="TCP Scan", variable=self.scan_type, value="tcp")
        self.scan_tcp_radio.pack(side='left')

        self.scan_udp_radio = tk.Radiobutton(radio_frame, text="UDP Scan", variable=self.scan_type, value="udp")
        self.scan_udp_radio.pack(side='left')

        self.scan_icmp_radio = tk.Radiobutton(radio_frame, text="ICMP Scan", variable=self.scan_type, value="icmp")
        self.scan_icmp_radio.pack(side='left')

        # Start Scan Button
        self.scan_button = tk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=20)

        # Results Display Section
        self.results_label = tk.Label(self.root, text="Scan Results:")
        self.results_label.pack(pady=10)

        self.result_text = scrolledtext.ScrolledText(self.root, height=15, width=100)
        self.result_text.pack(pady=10)

    def start_scan(self):
        ip_address = self.ip_entry.get().strip()
        port_range = self.port_range_entry.get().strip()

        # Validate input
        if not ip_address or not port_range:
            messagebox.showerror("Input Error", "IP Address and Port Range are required.")
            return

        try:
            start_port, end_port = map(int, port_range.split(','))
        except ValueError:
            messagebox.showerror("Input Error", "Port range should be in the format 'Start-Port, End-Port'.")
            return

        # Initialize PortScanner instance
        scan_type = self.scan_type.get()
        scanner = PortScanner(ip_address, start_port, end_port)

        # Clear previous results
        self.result_text.delete(1.0, tk.END)

        # Perform the scan based on the selected type
        try:
            if scan_type == "tcp":
                scanner.scan_tcp_ports()
            elif scan_type == "udp":
                scanner.scan_udp_ports()
            elif scan_type == "icmp":
                scanner.scan_icmp_ports()

            # Display results
            self.display_results(scanner.results)
            # Ask to save results to CSV after scan is complete
            self.save_results()

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during the scan: {e}")
            return

    def display_results(self, results):
        if not results:
            self.result_text.insert(tk.END, "No results found.\n")
            return

        self.result_text.insert(tk.END, "{:<10} {:<20} {:<15} {:<15} {:<50}\n".format(
            "Port", "Service", "Port Status", "IP Address", "Banner"
        ))
        for result in results:
            self.result_text.insert(tk.END, "{:<10} {:<20} {:<15} {:<15} {:<50}\n".format(*result))

    def save_results(self):
        # Ask user to select a file path for saving CSV
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return  # User canceled the file dialog

        # If there are no results, show an error
        if not self.result_text.get(1.0, tk.END).strip():
            messagebox.showerror("No Results", "There are no results to save.")
            return

        # Write results to CSV
        try:
            with open(file_path, 'w', newline='') as csvfile:
                csv_writer = csv.writer(csvfile)
                csv_writer.writerow(["Port", "Service", "Port Status", "IP Address", "Banner"])

                # Extract results from the displayed text
                for line in self.result_text.get(1.0, tk.END).strip().split('\n')[1:]:  # Skip header
                    csv_writer.writerow(line.split())

            # Show success message with file path
            messagebox.showinfo("Success", f"Results saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"An error occurred while saving the results: {e}")

def main():
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()