from rank_bm25 import BM25Okapi
from pymetasploit3.msfrpc import MsfRpcClient
from nltk.tokenize import word_tokenize
from tqdm import tqdm
import json


class MetasploitBM25:
    def __init__(self, client):
        self.client = client
        self.modules_file = '/home/kali/Documents/UET/ADAT/Core/modules_detection//modules.json'
        self.modules_attrib_file = '/home/kali/Documents/UET/ADAT/Core/modules_detection/modules_attrib.json'
    @staticmethod
    def print_meta():
        print("xinchao")
    def get_all_modules(self):
        """Fetch all modules and save them with their type."""
        exploits = self.client.modules.exploits
        auxiliaries = self.client.modules.auxiliary

        all_modules = []
        for exploit in tqdm(exploits, desc="Fetching Exploit Modules"):
            all_modules.append({"name": exploit, "type": "exploit"})

        for auxiliary in tqdm(auxiliaries, desc="Fetching Auxiliary Modules"):
            all_modules.append({"name": auxiliary, "type": "auxiliary"})

        with open(self.modules_file, 'w') as file:
            json.dump(all_modules, file, indent=4)

        print(f"Total modules saved: {len(all_modules)}")

    def create_module_attrib(self):
        """Load modules from the file and enrich them with metadata."""
        with open(self.modules_file, 'r') as file:
            data = json.load(file)

        module_info = []
        for module in tqdm(data, desc="Adding Module Attributes"):
            try:
                if module['type'] == 'exploit':
                    info = self.client.modules.use('exploit', module['name'])
                else:
                    info = self.client.modules.use('auxiliary', module['name'])

                rport = str(info.options.get('RPORT', ''))
                module_info.append({
                    "fullname": info.fullname,
                    "name": info.name,
                    "description": info.description,
                    "rport": rport,
                    "references": info.references,
                })
            except Exception as e:
                print(f"Error processing module {module['name']}: {e}")
                continue

        with open(self.modules_attrib_file, 'w') as file:
            json.dump(module_info, file, indent=4)

    def get_metasploit_modules(self):
        """Load enriched modules from the file."""
        with open(self.modules_attrib_file, 'r') as file:
            return json.load(file)

    @staticmethod
    def prepare_bm25_data(modules):
        """Prepare the corpus for BM25."""
        corpus = []
        for module in tqdm(modules, desc="Preparing BM25 Corpus"):
            text = f"{module['name']} {module['description']}"
            corpus.append(word_tokenize(text.lower()))
        return corpus

    @staticmethod
    def process_gvm_vulnerabilities(vulnerabilities):
        """Tokenize vulnerabilities for BM25 processing."""
        return [word_tokenize(vuln.lower()) for vuln in vulnerabilities]

    @staticmethod
    def map_vulnerabilities_to_modules(vulnerabilities, modules, bm25_corpus):
        """Map vulnerabilities to the most relevant modules."""
        bm25 = BM25Okapi(bm25_corpus)
        results = []
        for vuln in vulnerabilities:
            scores = bm25.get_scores(word_tokenize(vuln.lower()))
            best_match_index = scores.argmax()
            best_module = modules[best_match_index]
            results.append({
                "vulnerability": vuln,
                "matched_module": best_module["fullname"],
                "rport": best_module["rport"],
                "score": scores[best_match_index],
            })
        return results


if __name__ == "__main__":
    # nltk.download('punkt')

    # Initialize the client and the class
    client = MsfRpcClient('msf', port=55552, username='msf', server='127.0.0.1')
    metasploit = MetasploitBM25(client)

    # Uncomment as needed to initialize or process data
    # metasploit.get_all_modules()
    # metasploit.create_module_attrib()

    # Example vulnerabilities
    gvm_vulnerabilities = [
        "Possible Backdoor: Ingreslock",
        "The rexec service is running",
        "rlogin Passwordless Login",
        "TWiki XSS and Command Execution Vulnerabilities",
        "Distributed Ruby (dRuby/DRb) Multiple Remote Code Execution Vulnerabilities",
        "vsftpd Compromised Source Packages Backdoor Vulnerability",
        "Operating System (OS) End of Life (EOL) Detection",
        "MySQL / MariaDB Default Credentials (MySQL Protocol)",
        "vsftpd Compromised Source Packages Backdoor Vulnerability",
        "Apache Tomcat AJP RCE Vulnerability (Ghostcat)",
        "DistCC RCE Vulnerability (CVE-2004-2687)",
        "VNC Brute Force Login",
        "PostgreSQL Default Credentials (PostgreSQL Protocol)",
        "UnrealIRCd Authentication Spoofing Vulnerability",
        "Java RMI Server Insecure Default Configuration RCE Vulnerability",
        "rsh Unencrypted Cleartext Login",
        "PHP-CGI-based setups vulnerability when parsing query string parameters from php files."
        "The rlogin service is running",
        "Test HTTP dangerous methods",
        "FTP Brute Force Logins Reporting",
        "UnrealIRCd Backdoor",
        "SSL/TLS: OpenSSL CCS Man in the Middle Security Bypass Vulnerability"
    ]

    # Load modules and prepare BM25 data
    metasploit_modules = metasploit.get_metasploit_modules()
    bm25_corpus = metasploit.prepare_bm25_data(metasploit_modules)
    processed_vulnerabilities = metasploit.process_gvm_vulnerabilities(gvm_vulnerabilities)

    # Map vulnerabilities to modules
    mapping_results = metasploit.map_vulnerabilities_to_modules(
        gvm_vulnerabilities, metasploit_modules, bm25_corpus
    )

    # Print results
    for result in mapping_results:
        print(f"Vulnerability: {result['vulnerability']}")
        print(f"Matched Module: {result['matched_module']}")
        print(f"Matched RPORT: {result['rport']}")
        print(f"Score: {result['score']:.2f}\n")
