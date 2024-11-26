import xml.etree.ElementTree as ET
import re
from collections import Counter
import nltk
from nltk.corpus import stopwords
import re
from .env import cve_lists, exploit_lists
import GVM.GVM.gvm as gvm
from pymetasploit3.msfrpc import MsfRpcClient

def extract_keywords(text):
    words = nltk.word_tokenize(text)
    stop_words = set(stopwords.words('english'))
    keywords = [word for word in words if word.lower() not in stop_words]

    # Thêm vào đoạn mã này để bao gồm các từ như "dRuby" và "DRb"
    additional_keywords = re.findall(
        r'\b(?:[a-z]+[A-Z]|[A-Z]+[a-z])[a-zA-Z0-9]*\b', text)
    keywords += additional_keywords
    if "VNC" in keywords: keywords.append("vnc_")
    keywords = [child for child in keywords if child.lower() in exploit_lists]
    print("Core\\views\extract_keywords\key_words: ", end=" ")
    print(list(set(keywords)))
    return list(set(keywords))

class ModulesDetection:
    def __init__(self, msf_client):
        self.gvm_client = gvm
        self.msf_client = msf_client

    def get_vulnerability_details(self, vuln_id):
        """Retrieve vulnerability details from GVM."""
        vuln = self.gvm_client.get_result(id=vuln_id)
        et = ET.fromstring(vuln).find("result")
        name = et.find('name').text
        description = et.find('description').text
        port = et.find('port').text.split('/')[0]
        cve = None if et.find('nvt').find('refs') is None else et.find('nvt').find("refs").findall('ref')
        host = et.find('host').text
        return {
            "name": name,
            "description": description,
            "port": port,
            "cve": cve,
            "host": host,
            "et": et
        }

    def extract_cve_ids(self, cve_refs):
        """Extract CVE IDs from vulnerability references."""
        if cve_refs is None:
            return []
        return [ref.attrib['id'] for ref in cve_refs if ref.attrib['type'] == "cve"]

    def search_cves(self, cve_ids):
        """Search for modules in Metasploit by CVE IDs."""
        cve_results = []
        for cve_id in cve_ids:
            results = self.msf_client.call('module.search', [cve_id])
            results = [str(result) for result in results]
            cve_results.extend(results)
        counter = Counter(cve_results)
        top_cves = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        return [eval(cve[0]) for cve in top_cves if cve[1] == top_cves[0][1]]

    def base_search_exploits(self, name, description):
        """Search for exploits in Metasploit by name and description."""
        search_term = set()
        if name:
            search_term.update(extract_keywords(name))
        if description:
            search_term.update(extract_keywords(description))

        print("Search terms before: ", search_term)

        # Search for modules in Metasploit
        search_results = []
        for term in search_term:
            results = self.msf_client.call('module.search', [term])
            search_results.extend(str(result) for result in results)

        # Count and sort results
        counter = Counter(search_results)
        sorted_results = sorted(counter.items(), key=lambda x: x[1], reverse=True)

        # Get top-ranked exploits
        exploits = []
        if sorted_results:
            max_score = sorted_results[0][1]
            for result in sorted_results[:100]:
                if result[1] == max_score:
                    evaluated_result = eval(result[0])
                    exploits.append(evaluated_result)

        # Format exploits
        formatted_exploits = [
            {"name": f"{item['name']} : {item['fullname']}", "module": item["fullname"]}
            for item in exploits[:1]
        ]

        return formatted_exploits

    def extract_target_uri(self, description, host):
        """Extract the target URI from the vulnerability description."""
        try:
            target_uri = re.split(rf"{host}|port:", description)[-1].strip()
            return "" if "/" not in target_uri else target_uri
        except:
            return ""

    def format_module_data(self, modules):
        """Format Metasploit modules for rendering."""
        return [{"name": f"{module['name']} : {module['fullname']}", "module": module["fullname"]} for module in modules]

    def get(self, request, vuln_id, **kwargs):
        """Main method to process vulnerability and return response."""
        username = request.user.username
        host = request.get_host()

        # Step 1: Get vulnerability details
        vuln_details = self.get_vulnerability_details(vuln_id)
        name, description, port, cve, host, et = vuln_details.values()

        # Step 2: Search CVE-based modules
        cve_ids = self.extract_cve_ids(cve)
        top_cve_modules = self.search_cves(cve_ids)
        cve_result = self.format_module_data(top_cve_modules)[:5]

        # Step 3: Search exploit-based modules
        exploits = self.search_exploits(name, description)
        exploit_result = self.format_module_data(exploits)[:1]

        # Step 4: Extract target URI
        target_uri = self.extract_target_uri(description, host)

        # Print the results

if __name__ == "__main__":
    vuln_id = "6ab116d0-6285-4497-89b5-f531f0debad0"
    msf_client = client = MsfRpcClient('msf', port=55552, username='msf', server='127.0.0.1')
    module = ModulesDetection(msf_client)
    vuln = module.get_vulnerability_details(vuln_id)
    print(vuln)