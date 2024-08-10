import requests
import logging
import configparser
from defang import defang
import base64


# Configure logging
logging.basicConfig(filename='Virus_Total_Results.txt', filemode='w', level=logging.DEBUG)

class VirusTotalChecker:
    def __init__(self, output_file="vt_results.txt"):
        self.config = configparser.ConfigParser()
        self.config.read('C:\\Users\\Analyst\\.config\\config.ini')
        self.api_key = self.config['VirusTotal_API']['virus_total_api_key']
        if not self.api_key:
            logging.error("VirusTotal API key not found in config.ini.")
            raise ValueError("VirusTotal API key not found in config.ini.")

        self.base_url = 'https://www.virustotal.com/api/v3/'
        self.output_file = output_file
        self.save_results_to_file("", "Virus Total Checker initialized.")
        print("Virus Total Checker initialized.")


    def _make_request(self, endpoint, resource):
        headers = {
            'x-apikey': self.api_key
        }
        try:
            response = requests.get(f"{self.base_url}{endpoint}/{resource}", headers=headers)
            response.raise_for_status()
            logging.debug(f"Request successful for {endpoint}/{resource}")
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for {endpoint}/{resource} with error: {e}")
            return None


# Section of the code that creates the virus total check functions.
    def check_ip(self, mal_ip):
        logging.debug(f"Checking IP: {mal_ip}")
        return self._make_request('ip_addresses', mal_ip)

    def check_domain(self, domain):
        logging.debug(f"Checking domain: {domain}")
        return self._make_request('domains', domain)

    def check_url(self, url):
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        fulll_url = f"urls/{encoded_url}"
        logging.debug(f"Checking URL: {url}")
        header = {
            'x-apikey': self.api_key
        }
        respoonse = requests.get(f"{self.base_url}{fulll_url}", headers=header)
        logging.debug(f"Request successful for {fulll_url}")
        if respoonse.status_code == 200:
            return respoonse.json()
        else:
            logging.error(f"Request failed for {fulll_url} with error: {respoonse.status_code}")
            return None

    def check_file(self, file_hash):
        logging.debug(f"Checking file hash: {file_hash}")
        return self._make_request('files', file_hash)

    def check_ips(self, ip_list):
        ip_list = [ip.strip() for ip in ip_list]
        results_list = []
        for mal_ip in ip_list:
            results = self.check_ip(mal_ip)
            if results is None:
                logging.debug(f"No data returned for IP: {mal_ip}")
                continue
            results_list.append(results)

        actionable_data_list = self._extract_actionable_data_for_list(results_list)
        for ip, data in zip(ip_list, actionable_data_list):
            if data != "No results found.":
                print(data)
                self.save_results_to_file(ip, data)
        return actionable_data_list


    def check_domains(self, domain_list):
        domain_list = [domain.strip() for domain in domain_list]
        results_list = []
        for domain in domain_list:
            results = self.check_domain(domain)
            if results is None:
                logging.debug(f"No data returned for domain: {domain}")
                continue
            results_list.append(results)

        actionable_data_list = self._extract_actionable_data_for_list(results_list)
        for domain, data in zip(domain_list, actionable_data_list):
            if data != "No results found.":
                print(data)
                self.save_results_to_file(domain, data)
        return actionable_data_list

    def check_urls(self, url_list):
        url_list = [url.strip() for url in url_list]
        results_list = []
        for url in url_list:
            results = self.check_url(url)
            if results is None:
                logging.debug(f"No data returned for URL: {url}")
                continue
            results_list.append(results)

        actionable_data_list = self._extract_actionable_data_for_list(results_list)
        for url, data in zip(url_list, actionable_data_list):
            if data != "No results found.":
                print(data)
                self.save_results_to_file(url, data)

        return actionable_data_list

    def check_files(self, file_list):
        file_list = [file.strip() for file in file_list]
        results_list = []
        for file_hash in file_list:
            results = self.check_file(file_hash)
            if results is None:
                logging.debug(f"No data returned for file hash: {file_hash}")
                continue
            results_list.append(results)

        actionable_data_list = self._extract_actionable_data_for_list(results_list)
        for file_hash, data in zip(file_list, actionable_data_list):
            if data != "No results found.":
                print(data)
                self.save_results_to_file(file_hash, data)

        return actionable_data_list




# Section of the code that extracts the actionable data from the results.
    def _extract_actionable_data(self, results):
        if not results or "data" not in results:
            logging.debug(f"No results found: {results}")
            return "No results found."

        data = results['data']
        attributes = data['attributes'] if 'attributes' in data else {}

        actionable_results = {
            "VirusTotal Link": data['links']['self'] if 'links' in data and 'self' in data['links'] else 'N/A',
            "ID": defang(data['id']) if 'id' in data else 'N/A',
            "Country": attributes['country'] if 'country' in attributes else 'N/A',
            "Owner": attributes['as_owner'] if 'as_owner' in attributes else 'N/A',
            "Reputation Score": attributes['reputation'] if 'reputation' in attributes else 'N/A',
            "Malicious Votes": attributes['total_votes']['malicious'] if 'total_votes' in attributes and 'malicious' in attributes['total_votes'] else 0,
            "Harmless Votes": attributes['total_votes']['harmless'] if 'total_votes' in attributes and 'harmless' in attributes['total_votes'] else 0,
            "Malicious Engines": []
        }

        if 'last_analysis_results' in attributes:
            for engine, details in attributes['last_analysis_results'].items():
                if 'category' in details and 'result' in details and details['category'] == 'malicious' and details['result'] == 'malicious':
                    actionable_results["Malicious Engines"].append({
                        "Engine Name": engine,
                        "Category": details['category'],
                        "Result": details['result']
                    })

        logging.debug(f"Extracted actionable data: {actionable_results}")
        return self._format_results_as_text(actionable_results)

    def _format_results_as_text(self, results):
        # Ensure keys exist before accessing them
        virus_total_link = results['VirusTotal Link'] if 'VirusTotal Link' in results else 'N/A'
        id_info = results['ID'] if 'ID' in results else 'N/A'
        country = results['Country'] if 'Country' in results else 'N/A'
        owner = results['Owner'] if 'Owner' in results else 'N/A'
        reputation_score = results['Reputation Score'] if 'Reputation Score' in results else 'N/A'
        malicious_votes = results['Malicious Votes'] if 'Malicious Votes' in results else 0
        harmless_votes = results['Harmless Votes'] if 'Harmless Votes' in results else 0

        text_result = (
            f"VirusTotal Link: {virus_total_link}\n"
            f"ID: {id_info}\n"
            f"Country: {country}\n\n"  # Add an extra newline after Country
            f"Owner: {owner}\n"
            f"Reputation Score: {reputation_score}\n"
            f"Malicious Votes: {malicious_votes}\n"
            f"Harmless Votes: {harmless_votes}\n"
        )

        if results['Malicious Engines']:
            text_result += "Malicious Engines:\n"
            for engine in results['Malicious Engines']:
                text_result += (
                    f"  Engine Name: {engine['Engine Name']}\n"
                    f"  Category: {engine['Category']}\n"
                    f"  Result: {engine['Result']}\n"
                )
        else:
            text_result += "No Malicious Engines detected.\n"

        return text_result.strip()

    def _extract_actionable_data_for_list(self, results_list):
        all_results = []
        for results in results_list:
            actionable_data = self._extract_actionable_data(results)
            all_results.append(actionable_data)
        return all_results

    def save_results_to_file(self, identifier, results):
        with open(self.output_file, 'a') as f:
            f.write(f"Results for {identifier}:\n")
            f.write(results)
    #         f.write("\n")


    # def save_results_to_file(self, query, results):
    #     with open(self.output_file, 'a') as file:
    #         file.write(f"Query: {query}\n")
    #         file.write(results)
    #         file.write("\n\n")





# Section of the code that runs the tests.
    def run_tests(self):
        test_type = input("Enter the type of test to run: (ip, domain, url, file, ips): ")

        if test_type == 'ip':
            mal_ip = input("Enter the IP address: ") or '8.8.8.8'
            results = self.check_ip(mal_ip)
            actionable_data = self._extract_actionable_data(results)
            print(actionable_data)
            self.save_results_to_file(mal_ip, actionable_data)

        elif test_type == 'domain':
            domain = input("Enter the domain: ") or 'google.com'
            results = self.check_domain(domain)
            actionable_data = self._extract_actionable_data(results)
            print(actionable_data)
            self.save_results_to_file(domain, actionable_data)

        elif test_type == 'url':
            url = input("Enter the URL: ") or 'https://www.example.com'
            results = self.check_url(url)
            actionable_data = self._extract_actionable_data(results)
            print(actionable_data)
            self.save_results_to_file(url, actionable_data)

        elif test_type == 'file':
            file_hash = input("Enter the file hash: ") or ''
            results = self.check_file(file_hash)
            actionable_data = self._extract_actionable_data(results)
            print(actionable_data)
            self.save_results_to_file(file_hash, actionable_data)

        elif test_type == 'ips':
            ip_list = input("Enter the IP addresses separated by commas: ").split(',')
            ip_list = [ip.strip() for ip in ip_list]  # Clean up any extra whitespace
            self.check_ips(ip_list)

        elif test_type == "domains":
            domain_list = input("Enter the domains separated by commas: ").split(',')
            domain_list = [domain.strip() for domain in domain_list]
            self.check_domains(domain_list)

        elif test_type == "urls":
            url_list = input("Enter the URLs separated by commas: ").split(',')
            url_list = [url.strip() for url in url_list]
            self.check_urls(url_list)

        else:
            print("Invalid test type. Please enter one of the following: ip, domain, url, file, ips")

    def close_app(self):
        print("Closing VirusTotal App...")
        exit(0)

    def close(self):
        print("Closing VirusTotal Checker...")
        exit(0)

# Section of the code that executes the test version of the code.



if __name__ == "__main__":
    vt_checker = VirusTotalChecker()
    vt_checker.run_tests()

    vt_checker.close_app()




