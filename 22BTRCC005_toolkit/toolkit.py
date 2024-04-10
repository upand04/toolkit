'''TOOLKIT OPTIONS:
1. IP Address & Domain Analysis
2. Packet Sniffing
3. Banner Grabbing
4. ARP Spoofing
5. WiFi Scanning'''

import tkinter as tk
from ip_domain_analysis import open_ip_domain_window
from packet_sniffing import packet_sniffing
from banner_grabbing import banner_grabbing_main
from arp_spoofing import arp_spoofing_main
from wifi_scanning import wifi_scanning

# Create the main window
root = tk.Tk()

# Set window dimensions
root.geometry("400x300")

# Welcome message
welcome_label = tk.Label(root, text="Welcome to TOOLKIT", font=("Helvetica", 16))
welcome_label.pack(pady=10)

# Prompt message
prompt_label = tk.Label(root, text="Please select one of the options below:")
prompt_label.pack()

# Button for IP Address & Domain Analysis
ip_domain_button = tk.Button(root, text="IP Address & Domain Analysis", command=lambda: open_ip_domain_window(root))
ip_domain_button.pack(pady=5)

# Button for Packet Sniffing
packet_sniffing_button = tk.Button(root, text="Packet Sniffing", command=lambda: packet_sniffing(root))
packet_sniffing_button.pack(pady=5)

# Button for banner Grabbing
packet_sniffing_button = tk.Button(root, text="Banner Grabbing", command=lambda: banner_grabbing_main(root))
packet_sniffing_button.pack(pady=5)

# Button for ARP Spoofing
packet_sniffing_button = tk.Button(root, text="ARP Spoofing", command=lambda: arp_spoofing_main(root))
packet_sniffing_button.pack(pady=5)

# Button for WiFi Scanning
wifi_scanning_button = tk.Button(root, text="WiFi Scanning", command=lambda: wifi_scanning(root))
wifi_scanning_button.pack(pady=5)

# Start the event loop
root.mainloop()
