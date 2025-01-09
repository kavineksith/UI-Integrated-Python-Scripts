import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import socket
import csv

class PortScanner:
    def __init__(self, ip_address, start_port, end_port):
        self.ip_address = ip_address
        self.start_port = int(start_port)
        self.end_port = int(end_port)
        self.open_ports = []
        self.closed_ports = []

    def scan_ports(self):
        for port in range(self.start_port, self.end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((self.ip_address, port))
            if result == 0:
                self.open_ports.append(port)
            else:
                self.closed_ports.append(port)
            sock.close()

    def get_results(self):
        return self.open_ports, self.closed_ports

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

        # Start Scan Button
        self.scan_button = tk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=20)

        # Results Display Section
        self.results_label = tk.Label(self.root, text="Scan Results:")
        self.results_label.pack(pady=10)

        self.result_text = scrolledtext.ScrolledText(self.root, height=15, width=100)
        self.result_text.pack(pady=10)

        # Save Results Section
        self.save_button = tk.Button(self.root, text="Save Results to CSV", command=self.save_results)
        self.save_button.pack(pady=10)

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
        scanner = PortScanner(ip_address, start_port, end_port)

        # Clear previous results
        self.result_text.delete(1.0, tk.END)

        # Perform the scan
        try:
            scanner.scan_ports()

            # Display results
            open_ports, closed_ports = scanner.get_results()
            self.display_results(open_ports, closed_ports)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during the scan: {e}")
            return

    def display_results(self, open_ports, closed_ports):
        if not open_ports and not closed_ports:
            self.result_text.insert(tk.END, "No results found.\n")
            return

        self.result_text.insert(tk.END, "Opened Ports:\n")
        for port in open_ports:
            self.result_text.insert(tk.END, f"Port {port} is OPEN\n")

        self.result_text.insert(tk.END, "\nClosed Ports:\n")
        for port in closed_ports:
            self.result_text.insert(tk.END, f"Port {port} is CLOSED\n")

    def save_results(self):
        # Ask user to select a file path for saving CSV
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return  # User canceled the file dialog

        # Extract results from the displayed text
        text_content = self.result_text.get(1.0, tk.END).strip()
        if not text_content:
            messagebox.showerror("No Results", "There are no results to save.")
            return

        try:
            # Write results to CSV
            open_ports = [line.split()[1] for line in text_content.splitlines() if "OPEN" in line]
            closed_ports = [line.split()[1] for line in text_content.splitlines() if "CLOSED" in line]

            with open(file_path, 'w', newline='') as csvfile:
                csv_writer = csv.writer(csvfile)
                csv_writer.writerow(["Port", "Status"])

                # Write open ports
                for port in open_ports:
                    csv_writer.writerow([port, "OPEN"])

                # Write closed ports
                for port in closed_ports:
                    csv_writer.writerow([port, "CLOSED"])

            messagebox.showinfo("Success", f"Results saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"An error occurred while saving the results: {e}")

def main():
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
