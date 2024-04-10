'''packet_sniffing.py:
    - This module enables packet sniffing functionality.
    - It creates a window where users can enter the number of packets to sniff.
    - Upon clicking the "Start Sniffing" button, it uses the scapy library to sniff the specified number of packets and displays the captured packets in a text widget.'''

import tkinter as tk
from scapy.all import sniff

def packet_sniffing(root):
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

    packet_sniffing_window = tk.Toplevel(root)
    packet_sniffing_window.title("Packet Sniffing")
    # Rest of the GUI code...

    
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