'''banner_grabbing_main.py:
    - This module performs banner grabbing, which involves retrieving information about a service running on a specific port of a target IP address.
    - It creates a window where users can enter the target IP address and port number.
    - Upon clicking the "Grab Banner" button, it attempts to establish a connection to the specified target IP and port, retrieves the banner information, and displays it.'''

import tkinter as tk
import socket

def banner_grabbing_main(root):
    def open_banner_grabbing_window():
        # Banner grabbing GUI code...
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
        # Banner grabbing logic...
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