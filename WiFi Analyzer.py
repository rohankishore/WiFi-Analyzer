import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from customtkinter import *
from scapy.all import *
from tkinter import scrolledtext

"""
THIS PROJECT REQUIRES WINPCAP OR NCAP DRIVERS INSTALLED AND RUNNING
"""

__project_submitted_by__ = "Rohan Kishore"
__project_title__ = "WiFi Analyzer"

class SnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("WiFi Analyzer")
        self.sniffer_running = False
        self.threshold = 5000

        menubar = tk.Menu(master)

        # Create "Help" menu and add to menubar
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Project Info", command=self.info)
        help_menu.add_command(label="Help", command=self.help)
        menubar.add_cascade(label="About", menu=help_menu)

        # Add menubar to master window
        master.config(menu=menubar)

        # tab view
        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        # Creating the required tabs
        sniffer = tk.Frame(notebook, background="#1d1d1d")
        devices = tk.Frame(notebook, background="#1d1d1d")
        notebook.add(sniffer, text="Network Sniffer")
        notebook.add(devices, text="Saved Passwords")

        # buttons to start, stop and write the data of the traffic analyzing proccess to a text file. Also contains the text box
        self.start_button = CTkButton(sniffer, text="Start", command=self.start_sniffer)
        self.stop_button = CTkButton(sniffer, text="Stop", command=self.stop_sniffer)
        CTkButton(sniffer, text="Save As a TXT File", command=self.save_as_txt).place(
            x=390, y=5
        )
        self.text_area = scrolledtext.ScrolledText(
            sniffer,
            wrap=tk.WORD,
            width=80,
            height=25,
            background="#1b1b1b",
            foreground="green",
        )
        self.text_area.config(state=tk.DISABLED)
        self.start_button.place(x=10, y=5)
        self.stop_button.place(x=200, y=5)
        self.text_area.pack(pady=20, side=BOTTOM)

        ############################## Saved Passwords ############################################

        # listbox to show all the passwords in a listview
        passwords_list = tk.Listbox(
            devices, background="#1b1b1b", foreground="green", borderwidth=0, border=0
        )
        passwords_list.pack(fill=X)

        # getting the list of saved passwords
        data = (
            subprocess.check_output(["netsh", "wlan", "show", "profiles"])
            .decode("utf-8")
            .split("\n")
        )
        allProfiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
        for i in allProfiles:
            results = (
                subprocess.check_output(
                    ["netsh", "wlan", "show", "profile", i, "key=clear"]
                )
                .decode("utf-8")
                .split("\n")
            )
            results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
            try:
                a = "{:<30}|  {:<}".format(i, results[0])
                passwords_list.insert(tk.END, a)
            except IndexError:
                b = "{:<30}|  {:<}".format(i, "")
                passwords_list.insert(tk.END, b)

    #################################################################################################################
    def start_sniffer(self):
        self.sniffer_running = True
        t = threading.Thread(target=self.sniff)
        t.start()

    # help menu function
    def help(self):
        messagebox.showinfo(
            "Help",
            "This app contains two sections. First section is 'Network Sniffer', which monitors all the traffic happening in the network."
            "You can spot any vulnerabilities in the network if there's any unusually heavy traffic or if you see any passwords"
            "in non-encrypted form."
            + "\n"
            + "\n"
            + "The second section is 'Saved Passwords'. It will show you the passwords of every saved network in your computer." +
            "\n" + "\n" + "THIS REQUIRES WinPcap or Ncap DRIVERS INSTALLED AND RUNNING",
        )

    def stop_sniffer(self):
        self.sniffer_running = False

    # function to show the project info
    def info(self):
        messagebox.showinfo(
            "Project Info",
            "Project Name: WiFi Analyzer"
            + "\n"
            + "Project Submitted by: Rohan Kishore"
            + "\n"
            + "Programming Language Used: Python"
            + "\n"
            + "Libraries Used: Scapy, Tkinter and Customtkinter",
        )

    # function to write the traffic info to a text file
    def save_as_txt(self):
        if self.sniffer_running is False:
            text = self.text_area.get(0.0, END)
            name = str(
                filedialog.asksaveasfilename(
                    title="Select file", defaultextension=".txt"
                )
            )
            file = open(name, "w")
            file.write(text)
            file.close()
        elif self.sniffer_running is True:
            messagebox.showerror(
                "Uh Oh!", "Stop the sniffer service to write this into a txt file"
            )

    # sniffer main function
    def sniff(self):
        while self.sniffer_running:
            sniffed_packet = sniff(count=1)
            self.text_area.config(state=tk.NORMAL)
            self.text_area.insert(tk.END, sniffed_packet[0].summary() + "\n")
            self.text_area.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = CTk()  # main window
    app = SnifferApp(root)
    root.mainloop()  # looping the window
