import customtkinter as ctk
from virustotal_checker import VirusTotalChecker
import logging
import json




class VirusTotalApp(ctk.CTk):
    def __init__(self, checker):
        super().__init__()

        self.virustotal_checker = checker
        self.title("VirusTotal Checker")
        self.geometry("600x400")

        # Label
        self.label = ctk.CTkLabel(self, text="Enter IP Addresses (comma-separated):")
        self.label.pack(pady=10)

        # Entry field
        self.entry = ctk.CTkEntry(self, width=500)
        self.entry.pack(pady=10)

        # Submit button
        self.submit_button = ctk.CTkButton(self, text="Check IPs", command=self.check_ip)
        self.submit_button.pack(pady=10)

        self.submit_button_domain = ctk.CTkButton(self, text="Check Domain", command=self.check_domain)
        self.submit_button_domain.pack(pady=10)

        self.submit_button_url = ctk.CTkButton(self, text="Check URL", command=self.check_url)
        self.submit_button_url.pack(pady=10)

        self.submit_button_file = ctk.CTkButton(self, text="Check File", command=self.checker.check_file)
        self.submit_button_file.pack(pady=10)

        self.submit_button_ips = ctk.CTkButton(self, text="Check IPs", command=self.check_ips)
        self.submit_button_ips.pack(pady=10)

        self.submit_button_domains = ctk.CTkButton(self, text="Check Domains", command=self.check_domains)
        self.submit_button_domains.pack(pady=10)

        self.submit_button_urls = ctk.CTkButton(self, text="Check URLs", command=self.check_urls)
        self.submit_button_urls.pack(pady=10)

        self.submit_button_files = ctk.CTkButton(self, text="Check Files", command=self.check_files)
        self.submit_button_files.pack(pady=10)



        self.submit_button_tests = ctk.CTkButton(self, text="Run Tests", command=self.run_tests)
        self.submit_button_tests.pack(pady=10)

        self.submit_button_close = ctk.CTkButton(self, text="Close", command=self.close_app)
        self.submit_button_close.pack(pady=10)



        # Textbox for results
        self.result_textbox = ctk.CTkTextbox(self, height=200)
        self.result_textbox.pack(pady=10)

    def check_ip(self):
        mal_ip = self.entry.get()

        # Clear the textbox
        self.result_textbox.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_ip(mal_ip)
        actionable_data = self.virustotal_checker._extract_actionable_data(results)
        self.result_textbox.insert(ctk.END, actionable_data)

    def check_url(self):
        url = self.entry.get()

        # Clear the textbox
        self.result_textbox.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_url(url)
        actionable_data = self.virustotal_checker._extract_actionable_data(results)
        self.result_textbox.insert(ctk.END, actionable_data)

    def check_domain(self):
        domain = self.entry.get()

        # Clear the textbox
        self.result_textbox.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_domain(domain)
        self.result_textbox.insert(ctk.END, results)

    def check_file(self):
        file_hash = self.entry.get()

        # Clear the textbox
        self.result_textbox.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_file(file_hash)
        actionable_data = self.virustotal_checker._extract_actionable_data(results)
        self.result_textbox.insert(ctk.END, actionable_data)


    def check_ips(self):
        ips = self.entry.get().split(',')
        ip_list = [ip.strip() for ip in ips]

        # Clear the textbox
        self.result_textbox.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_ips(ip_list)

        for result in results:
            self.result_textbox.insert(ctk.END, result + "\n\n")

    def check_domains(self):
        domains = self.entry.get().split(',')
        domain_list = [domain.strip() for domain in domains]

        # Clear the textbox
        self.result_textbox.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_domains(domain_list)
        for result in results:
            self.result_textbox.insert(ctk.END, result + "\n\n")


    def check_urls(self):
        urls = self.entry.get().split(',')
        url_list = [url.strip() for url in urls]

        # Clear the textbox
        self.result_textbox.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_urls(url_list)
        for result in results:
            self.result_textbox.insert(ctk.END, result + "\n\n")

    def check_files(self):
        file_hashes = self.entry.get().split(',')
        file_list = [file.strip() for file in file_hashes]

        # Clear the textbox
        self.result_textbox.delete("1.0", ctk.END)

        # Run the checks and display results
        results = self.virustotal_checker.check_files(file_list)
        for result in results:
            self.result_textbox.insert(ctk.END, result + "\n\n")

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

    def close_app(self):
        self.virustotal_checker.close()
        self.destroy()
