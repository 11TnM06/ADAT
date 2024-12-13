from rank_bm25 import BM25Okapi
from pymetasploit3.msfrpc import MsfRpcClient
from nltk.tokenize import word_tokenize
from tqdm import tqdm
import json
import numpy as np
from nltk.corpus import stopwords
stop_words = set(stopwords.words('english'))

class DataHandler:
    def __init__(self, modules_file, modules_attrib_file, client):
        self.client = client
        self.modules_file = modules_file
        self.modules_attrib_file = modules_attrib_file

    def save_modules(self, modules):
        """Save modules to a JSON file."""
        with open(self.modules_file, 'w') as file:
            json.dump(modules, file, indent=4)
        print(f"Modules saved to {self.modules_file}")

    def load_modules(self):
        """Load modules from a JSON file."""
        with open(self.modules_file, 'r') as file:
            return json.load(file)

    def save_module_attrib(self, module_info):
        """Save enriched module attributes to a JSON file."""
        with open(self.modules_attrib_file, 'w') as file:
            json.dump(module_info, file, indent=4)
        print(f"Module attributes saved to {self.modules_attrib_file}")

    def load_module_attrib(self):
        """Load enriched module attributes from a JSON file."""
        with open(self.modules_attrib_file, 'r') as file:
            return json.load(file)

    @staticmethod
    def load_json_file(filename):
        with open(filename, 'r') as file:
            return json.load(file)

    @staticmethod
    def prepare_bm25_data(modules):
        """Prepare corpus for BM25."""
        corpus = []
        for module in modules:
            # add cve if exist in references
            cve = []
            if module['references']:
                for ref in module['references']:
                    if "CVE" == ref[0]:
                        cve.append(ref[0] + "-" + ref[1])
                        # print(ref[0] + "-" + ref[1])
            text = f"{module['name']} {module['description']} {' '.join(cve)}"
            tokens = word_tokenize(text.lower())
            corpus.append(tokens)
        return corpus

    @staticmethod
    def prepare_tfidf_corpus(modules):
        corpus = []
        for module in modules:
            # add cve if exist in references
            cve = []
            if module['references']:
                for ref in module['references']:
                    if "CVE" == ref[0]:
                        cve.append(ref[0] + "-" + ref[1])
                        # print(ref[0] + "-" + ref[1])
            text = f"{module['name']} {module['description']} {' '.join(cve)}"
            corpus.append(text.lower())
        return corpus

    @staticmethod
    def process_gvm_vulnerabilities(vulnerabilities):
        """Tokenize vulnerabilities for BM25 processing."""
        words = []
        for vuln in vulnerabilities:
            token = word_tokenize(vuln.lower())
            tmp = []
            for word in token:
                if word not in stop_words:
                    tmp.append(word)
            words.append(tmp)
        return words

    def get_all_modules(self):
        """Fetch all modules (exploit and auxiliary) and save them."""
        exploits = self.client.modules.exploits
        auxiliaries = self.client.modules.auxiliary

        all_modules = []
        for exploit in tqdm(exploits, desc="Fetching Exploit Modules"):
            all_modules.append({"name": exploit, "type": "exploit"})

        for auxiliary in tqdm(auxiliaries, desc="Fetching Auxiliary Modules"):
            all_modules.append({"name": auxiliary, "type": "auxiliary"})

        self.save_modules(all_modules)

    def create_module_attrib(self):
        """Load modules and enrich them with attributes."""
        modules = self.load_modules()
        module_info = []
        i = 0
        for module in tqdm(modules, desc="Adding Module Attributes"):
            if i == 10:
                break
            try:
                if module['type'] == 'exploit':
                    info = self.client.modules.use('exploit', module['name'])
                else:
                    info = self.client.modules.use('auxiliary', module['name'])
                rport = ""
                if isinstance(info.options, dict):
                    rport = str(info.options.get('RPORT', ''))
                elif isinstance(info.options, list):
                    for option in info.options:
                        if isinstance(option, dict) and 'RPORT' in option:
                            rport = str(option['RPORT'])
                            break
                module_info.append({
                    "fullname": info.fullname,
                    "name": info.name,
                    "description": info.description,
                    "rport": rport,
                    "references": info.references,
                })
            except Exception as e:
                i += 1
                print(f"Error processing module {module['name']}: {e}")
                continue
        self.save_module_attrib(module_info)

class EnhancedBM25Search:
    def __init__(self, min_score=11.0, cve_weight=5):
        self.min_score = min_score
        self.cve_weight = cve_weight

    def map_vulnerabilities_to_modules(self, queries, modules, corpus):
        """
        Perform BM25 search for each query against the corpus.
        :param corpus: Tokenized module descriptions.
        :param queries: List of queries (e.g., GVM vulnerabilities).
        :param modules: List of module metadata.
        :return: List of results with matched modules and scores.
        """
        bm25 = BM25Okapi(corpus)
        results = []

        for vuln in queries:
            scores = bm25.get_scores(vuln)

            # Check the best match or fallback to "No module found"
            max_score = np.max(scores)
            if max_score > self.min_score:
                best_match_index = np.argmax(scores)
                best_module = modules[best_match_index]
                results.append({
                    "vulnerability": vuln,
                    "matched_module": best_module.get("fullname", "Unknown"),
                    "score": max_score,
                })
            else:
                results.append({
                    "vulnerability": vuln,
                    "matched_module": "No module found",
                    "score": max_score,
                })

        return results

    def map_vulnerabilities_to_modules_1(self, queries, modules, corpus, top_k=3):
        """
        Perform BM25 search for each query against the corpus.
        :param corpus: Tokenized module descriptions.
        :param queries: List of queries (e.g., GVM vulnerabilities).
        :param modules: List of module metadata.
        :return: List of results with matched modules and scores.
        """
        bm25 = BM25Okapi(corpus)
        results = []

        for vuln in queries:
            scores = bm25.get_scores(vuln)

            # Check the best match or fallback to "No module found"
            top_indices = np.argsort(scores)[-top_k:][::-1]
            top_results = []

            for index in top_indices:
                if scores[index] > self.min_score:
                    matched_module = modules[index]
                    top_results.append({
                        "query": vuln,
                        "matched_module": matched_module.get("fullname", "Unknown"),
                        "score": scores[index],
                    })
                else:
                    top_results.append({
                        "query": vuln,
                        "matched_module": "No module found",
                        "score": scores[index],
                    })

            results.append({
                "query": vuln,
                "top_results": top_results
            })

        return results

class MetasploitBM25:
    def __init__(self, vulnerabilities, modules, bm25_corpus):
        self.vulnerabilities = vulnerabilities
        self.modules = modules
        self.bm25_corpus = bm25_corpus

    def map_vulnerabilities_to_modules(self):
        """Map vulnerabilities to Metasploit modules using BM25."""
        vulnerabilities = self.vulnerabilities
        modules = self.modules
        bm25_corpus = self.bm25_corpus
        bm25 = BM25Okapi(bm25_corpus)
        results = []

        for vuln in vulnerabilities:
            scores = bm25.get_scores(vuln)
            best_match_index = scores.argmax()
            best_module = modules[best_match_index]
            results.append({
                "vulnerability": vuln,
                "matched_module": best_module["fullname"],
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
