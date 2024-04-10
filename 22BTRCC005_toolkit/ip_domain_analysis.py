'''ip_domain_analysis.py:
    - This module provides functionality for analyzing IP addresses and domain names.
    - It creates a window where users can enter a website name and top-level domain (TLD).
    - Upon clicking the "Save" button, it resolves the IP address of the entered domain using the socket.gethostbyname() function and displays the result.'''

import tkinter as tk
import socket

def open_ip_domain_window(root):
    ip_domain_window = tk.Toplevel(root)
    ip_domain_window.title("IP Address & Domain Analysis")

    def save_values():
        fulladdr = f"www.{website_entry.get()}.{tld_entry.get()}"
        ipaddr = socket.gethostbyname(fulladdr)
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
