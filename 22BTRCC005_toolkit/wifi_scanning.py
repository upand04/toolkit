'''
WiFi Scanning Window (wifi_scanning.py):
    - The WiFi scanning window (wifi_window) is created similarly to the other windows.
    - It contains a tk.Label widget and tk.Entry widget for input of the IP address range to scan.
    - Buttons for starting and ending the scan (start_scan_button and end_scan_button) are provided.
    - A tk.Text widget (output_text) is used to display the results of the scan.
'''

import tkinter as tk
import re
import socket
import scapy.all as sc

def wifi_scanning(root):
    # WiFi scanning GUI and logic...
    def start_scan():
        ip_add_range_entered = ip_entry.get()
        ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")

        if ip_add_range_pattern.search(ip_add_range_entered):
            output_text.delete(1.0, tk.END)  # Clear previous output
            output_text.insert(tk.END, f"{ip_add_range_entered} is a valid IP address range.\n")
            output_text.see(tk.END)

            try:
                arp_result = sc.arping(ip_add_range_entered, verbose=False, timeout=1)
                
                # Check if arp_result is empty or None
                if arp_result:
                    for received in arp_result:
                        if stop_scan:
                            break
                        if received and received[0] and received[0][1]:
                            ip = received[0][1].psrc
                            mac = received[0][1].hwsrc
                            try:
                                hostname, _, _ = socket.gethostbyaddr(ip)
                            except socket.herror:
                                hostname = "Unknown"
                            output_text.insert(tk.END, f"IP: {ip} MAC: {mac} Hostname: {hostname}\n")
                            output_text.see(tk.END)
                else:
                    output_text.insert(tk.END, "No ARP responses received.\n")
                    output_text.see(tk.END)
            except Exception as e:
                output_text.insert(tk.END, f"An error occurred: {str(e)}\n")
                output_text.see(tk.END)
        else:
            output_text.insert(tk.END, f"Invalid IP address and range format: {ip_add_range_entered}\n")
            output_text.see(tk.END)

    def end_scan():
        global stop_scan
        stop_scan = True

    # Create the window for WiFi scanning
    wifi_window = tk.Toplevel(root)
    wifi_window.title("WiFi Scanning")

    # Set window dimensions
    wifi_window.geometry("560x320")

    # IP address entry
    ip_label = tk.Label(wifi_window, text="IP Address and Range (ex: 192.168.1.0/24):")
    ip_label.pack(pady=5)
    ip_entry = tk.Entry(wifi_window)
    ip_entry.pack(pady=5)

    # Output text area
    output_text = tk.Text(wifi_window, height=10, width=60)
    output_text.pack(pady=10)

    # Start scan button
    start_scan_button = tk.Button(wifi_window, text="Start Scan", command=start_scan)
    start_scan_button.pack(pady=5)

    # End scan button
    end_scan_button = tk.Button(wifi_window, text="End Scan", command=end_scan)
    end_scan_button.pack(pady=5)

    # Global variable to control scanning process
    global stop_scan
    stop_scan = False
