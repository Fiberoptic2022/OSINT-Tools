import customtkinter as ctk
from virustotal_checker import VirusTotalChecker
import logging
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd

logging.basicConfig(filename="app.log", level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class VirusTotalApp(ctk.CTk):
    def __init__(self, virustotal_checker: VirusTotalChecker):
        super().__init__()

        self.virustotal_checker = virustotal_checker
        self.title("VirusTotal Checker")
        self.geometry("800x600")

        # Notebook for tabs
        notebook = ttk.Notebook(self)
        notebook.pack(pady=10, fill="both", expand=True)

        # Tab 0 - Single Checks
        tab0 = ctk.CTkFrame(notebook)
        notebook.add(tab0, text="Single Checks")

        # Entry field
        self.label_single = ctk.CTkLabel(tab0, text="Enter IP, Domain, URL, or File Hash:")
        self.label_single.pack(pady=10)


        self.entry_single = ctk.CTkEntry(tab0, width=400)
        self.entry_single.pack(pady=10)

        # Buttons for VirusTotal checks
        self.submit_button_ip = ctk.CTkButton(tab0, text="Check IP", command=self.check_ip)
        self.submit_button_ip.pack(pady=5)

        self.submit_button_domain = ctk.CTkButton(tab0, text="Check Domain", command=self.check_domain)
        self.submit_button_domain.pack(pady=5)

        self.submit_button_url = ctk.CTkButton(tab0, text="Check URL", command=self.check_url)
        self.submit_button_url.pack(pady=5)

        self.submit_button_file = ctk.CTkButton(tab0, text="Check File", command=self.check_file)
        self.submit_button_file.pack(pady=5)

        self.submit_button_single = ctk.CTkButton(tab0, text="Close App", command=self.close_app)
        self.submit_button_single.pack(pady=5)



        # Textbox for results
        self.result_textbox_single = ctk.CTkTextbox(tab0, height=200)
        self.result_textbox_single.pack(pady=10, fill="both", expand=True)



        # Tab 1 - Multiple Checks
        tab1 = ctk.CTkFrame(notebook)
        notebook.add(tab1, text="Multiple Checks")

        self.label_multiple = ctk.CTkLabel(tab1, text="Enter IPs, Domains, URLs, or File Hashes separated by commas:")
        self.label_multiple.pack(pady=10)

        self.entry_mutiple = ctk.CTkEntry(tab1, width=400)
        self.entry_mutiple.pack(pady=10)

        self.submit_button_ips = ctk.CTkButton(tab1, text="Check IPs", command=self.check_ips)
        self.submit_button_ips.pack(pady=5)

        self.submit_button_domains = ctk.CTkButton(tab1, text="Check Domains", command=self.check_domains)
        self.submit_button_domains.pack(pady=5)

        self.submit_button_urls = ctk.CTkButton(tab1, text="Check URLs", command=self.check_urls)
        self.submit_button_urls.pack(pady=5)

        self.submit_button_files = ctk.CTkButton(tab1, text="Check Files", command=self.check_files)
        self.submit_button_files.pack(pady=5)

        self.submit_button_mutiple = ctk.CTkButton(tab1, text="Close App", command=self.close_app)
        self.submit_button_mutiple.pack(pady=5)



        # Textbox for results
        self.result_textbox_multiple = ctk.CTkTextbox(tab1, height=200)
        self.result_textbox_multiple.pack(pady=10, fill="both", expand=True)



        # Tab 2 - CSV Processing
        tab2 = ctk.CTkFrame(notebook)
        notebook.add(tab2, text="CSV Query")

        self.label_csv = ctk.CTkLabel(tab2, text="Load a CSV file for analysis:")
        self.label_csv.pack(pady=20)

        load_button = ctk.CTkButton(tab2, text="Load CSV", command=self.load_csv)
        load_button.pack(pady=20)

        self.data = None

        # Dropdown for filtering
        filter_label = ctk.CTkLabel(tab2, text="Filter by Result:")
        filter_label.pack(pady=5)

        self.filter_combobox = ctk.CTkComboBox(tab2, values=['malicious', 'clean'])
        self.filter_combobox.pack(pady=5)

        filter_button = ctk.CTkButton(tab2, text="Apply Filter", command=self.filter_data)
        filter_button.pack(pady=5)

        # Dropdown for column selection
        column_label = ctk.CTkLabel(tab2, text="Select Column:")
        column_label.pack(pady=5)

        self.column_combobox = ctk.CTkComboBox(tab2, values=[''])
        self.column_combobox.pack(pady=5)

        # Buttons for various analyses
        stats_button = ctk.CTkButton(tab2, text="Show Statistics", command=self.show_stats)
        stats_button.pack(pady=5)

        self.button_csv = ctk.CTkButton(tab2, text="Close App", command=self.close_app)
        self.button_csv.pack(pady=5)

        # Textbox for results
        self.result_textbox_csv = ctk.CTkTextbox(tab2, height=200)
        self.result_textbox_csv.pack(pady=10, fill="both", expand=True)



    def check_ip(self):
        mal_ip = self.entry_single.get()

        # Clear the textbox
        self.result_textbox_single.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_ip(mal_ip)
        actionable_data = self.virustotal_checker._extract_actionable_data(results)
        self.result_textbox_single.insert(ctk.END, actionable_data)

    def check_url(self):
        url = self.entry_single.get()

        # Clear the textbox
        self.result_textbox_single.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_url(url)
        actionable_data = self.virustotal_checker._extract_actionable_data(results)
        self.result_textbox_single.insert(ctk.END, actionable_data)

    def check_domain(self):
        domain = self.entry_single.get()

        # Clear the textbox
        self.result_textbox_single.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_domain(domain)
        actionable_data = self.virustotal_checker._extract_actionable_data(results)
        self.result_textbox_single.insert(ctk.END, actionable_data)

    def check_file(self):
        file_hash = self.entry_single.get()

        # Clear the textbox
        self.result_textbox_single.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_file(file_hash)
        actionable_data = self.virustotal_checker._extract_actionable_data(results)
        self.result_textbox_single.insert(ctk.END, actionable_data)

    def check_ips(self):
        ips = self.entry_mutiple.get().split(',')
        ip_list = [ip.strip() for ip in ips]

        # Clear the textbox
        self.result_textbox_multiple.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_ips(ip_list)
        for result in results:
            self.result_textbox_multiple.insert(ctk.END, result + "\n\n")


    def check_domains(self):
        domains = self.entry_mutiple.get().split(',')
        domain_list = [domain.strip() for domain in domains]

        # Clear the textbox
        self.result_textbox_multiple.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_domains(domain_list)
        for result in results:
            self.result_textbox_multiple.insert(ctk.END, result + "\n\n")


    def check_urls(self):
        urls = self.entry_mutiple.get().split(',')
        url_list = [url.strip() for url in urls]

        # Clear the textbox
        self.result_textbox_multiple.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_urls(url_list)
        for result in results:
            self.result_textbox_multiple.insert(ctk.END, result + "\n\n")

    def check_files(self):
        file_hashes = self.entry_mutiple.get().split(',')
        file_list = [file.strip() for file in file_hashes]

        # Clear the textbox
        self.result_textbox_multiple.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_files(file_list)
        for result in results:
            self.result_textbox_multiple.insert(ctk.END, result + "\n\n")

    def run_tests(self):
        test_type = input("Enter the type of test to run: (ip, domain, url, file, ips, domains, urls, files): ")

        if test_type == 'ip':
            mal_ip = input("Enter the IP address: ") or '1.1.1.1'
            results = self.virustotal_checker.check_ip(mal_ip)
            actionable_data = self.virustotal_checker._extract_actionable_data(results)
            print(actionable_data)

        elif test_type == 'domain':
            domain = input("Enter the domain: ") or 'google.com'
            results = self.virustotal_checker.check_domain(domain)
            actionable_data = self.virustotal_checker._extract_actionable_data(results)
            print(actionable_data)

        elif test_type == 'url':
            url = input("Enter the URL: ") or 'https://www.example.com'
            results = self.virustotal_checker.check_url(url)
            actionable_data = self.virustotal_checker._extract_actionable_data(results)
            print(actionable_data)

        elif test_type == 'file':
            file_hash = input("Enter the file hash: ") or 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            results = self.virustotal_checker.check_file(file_hash)
            actionable_data = self.virustotal_checker._extract_actionable_data(results)
            print(actionable_data)

        elif test_type == 'ips':
            ip_list = input("Enter the IP addresses separated by commas: ").split(',')
            ip_list = [ip.strip() for ip in ip_list]
            results = self.virustotal_checker.check_ips(ip_list)
            for result in results:
                print(result)

        elif test_type == "domains":
            domain_list = input("Enter the domains separated by commas: ").split(',')
            domain_list = [domain.strip() for domain in domain_list]
            results = self.virustotal_checker.check_domains(domain_list)
            for result in results:
                print(result)

        elif test_type == "urls":
            url_list = input("Enter the URLs separated by commas: ").split(',')
            url_list = [url.strip() for url in url_list]
            results = self.virustotal_checker.check_urls(url_list)
            for result in results:
                print(result)

        elif test_type == "files":
            file_list = input("Enter the file hashes separated by commas: ").split(',')
            file_list = [file.strip() for file in file_list]
            results = self.virustotal_checker.check_files(file_list)
            for result in results:
                print(result)

        else:
            print("Invalid test type. Please choose from: ip, domain, url, file, ips, domains, urls, files")

    def load_csv(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])

        if file_path:
            self.data = pd.read_csv(file_path)
            self.column_combobox['values'] = self.data.columns.tolist()
            messagebox.showinfo("CSV Loaded", "CSV file has been loaded successfully")

    def filter_data(self):
        if self.data is None:
            messagebox.showerror("Error", "No CSV file loaded")
            return

        result = self.filter_combobox.get()
        self.filtered_data = self.data[self.data['result'] == result]
        self.display_result(self.result_textbox_csv, self.filtered_data.to_string(index=False))

    def show_stats(self):
        if self.data is None:
            messagebox.showerror("Error", "No CSV file loaded")
            return

        stats = self.data.describe().to_string()
        self.display_result(self.result_textbox_csv, stats)

    def display_result(self, textbox, result):
        textbox.delete(1.0, tk.END)
        textbox.insert(tk.END, result)

    def close_app(self):
        self.destroy()




if __name__ == "__main__":
    # Initialize the VirusTotal Checker
    virustotal_checker = VirusTotalChecker()


    # Initialize the GUI
    app = VirusTotalApp(virustotal_checker)

    app.mainloop()

    # Close the VirusTotal Checker
    virustotal_checker.close()

