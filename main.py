from scapy.all import *
from scapy.layers.inet import TCP, IP
import tkinter as tk


def main():
    window = tk.Tk()
    window.title = "PortScanner"
    window.geometry("250x250")
    window.configure(bg="#302c34")

    label1 = tk.Label(window, text="Target IP")
    label1.grid(row=0, column=0, padx=20, pady=20)
    target_entry = tk.Entry(window)
    target_entry.grid(row=0, column=1, padx=20, pady=20)

    label2 = tk.Label(window, text="Start Port")
    label2.grid(row=1, column=0, padx=20, pady=20)
    sport_entry = tk.Entry(window)
    sport_entry.grid(row=1, column=1, padx=20, pady=20)

    label3 = tk.Label(window, text="End Port")
    label3.grid(row=2, column=0, padx=20, pady=20)
    eport_entry = tk.Entry(window)
    eport_entry.grid(row=2, column=1, padx=20, pady=20)

    generate_button = tk.Button(window, text="Find ports", command=lambda: find_ports(window, target_entry.get(), sport_entry.get(), eport_entry.get()))
    generate_button.grid(row=4, column=0, columnspan=2)
    window.mainloop()


def find_ports(window, target_ip, startingPort, lastPort):
    result_window = tk.Toplevel(window)
    result_window.title('Results')
    try:
        for x in range(startingPort, lastPort):
            packets = IP(dst=target_ip) / TCP(dport=x, flags='S')
            response = sr1(packets, timeout=0.5, verbose=0)
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                result_label = tk.Label(result_window, text="Port " + str(x) + " is open!")
                result_label.pack()
            sr(IP(dst=target_ip) / TCP(dport=response.sport, flags='R'), timeout=0.5, verbose=0)
    except AttributeError:
        result_label = tk.Label(result_window, text="No port is available!")
        result_label.pack()
    result_window.mainloop()


if __name__ == "__main__":
    main()
    
