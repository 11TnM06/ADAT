# %%
# Imports and Setup
import json
from sys import modules

from jedi.plugins.django import mapping
from nltk import accuracy
from tqdm import tqdm
from nltk.tokenize import word_tokenize
from rank_bm25 import BM25Okapi
from pymetasploit3.msfrpc import MsfRpcClient
import xml.etree.ElementTree as ET
import re
from collections import Counter
import nltk
from nltk.corpus import stopwords
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# %%
nltk.download('punkt')
nltk.download('stopwords')
stop_words = set(stopwords.words('english'))


# %% md

# %% md
## Data Handling Class
# %% md

# %%
# Data Handling Class
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


# %% md
## BM25 Algorithm
# %% md
## Base Search Algorithm
# %%
from env import exploit_lists, cve_lists


class BaseSearch:
    """Handles keyword extraction and searching for exploits."""

    @staticmethod
    def extract_keywords(text):
        """Extract relevant keywords from text."""
        words = nltk.word_tokenize(text)
        stop_words = set(stopwords.words('english'))
        keywords = [word for word in words if word.lower() not in stop_words]

        # Include additional patterns for specific keywords
        additional_keywords = re.findall(r'\b(?:[a-z]+[A-Z]|[A-Z]+[a-z])[a-zA-Z0-9]*\b', text)
        keywords += additional_keywords

        # Include custom rules
        if "VNC" in keywords:
            keywords.append("vnc_")

        # Filter against exploit lists
        keywords = [child for child in keywords if child.lower() in exploit_lists]

        # print("Extracted Keywords: ", set(keywords))
        return list(set(keywords))

    def base_search_exploits(self, msf_client, name, description):
        """Search for Metasploit modules by name and description."""
        search_term = set()
        if name:
            search_term.update(self.extract_keywords(name))
        if description:
            search_term.update(self.extract_keywords(description))

        # print("Search terms: ", search_term)

        # Search modules in Metasploit
        search_results = []
        for term in search_term:
            results = msf_client.call('module.search', [term])
            search_results.extend(str(result) for result in results)

        # Count and rank search results
        counter = Counter(search_results)
        sorted_results = sorted(counter.items(), key=lambda x: x[1], reverse=True)

        # Extract top-ranked modules
        exploits = []
        if sorted_results:
            max_score = sorted_results[0][1]
            for result in sorted_results[:100]:
                if result[1] == max_score:
                    evaluated_result = eval(result[0])
                    exploits.append(evaluated_result)

        # Format the results
        formatted_exploits = [
            {"name": f"{item['name']}", "module": item["fullname"]}
            for item in exploits[:1]
        ]
        return formatted_exploits


# %%
class TfidfSearch:
    def __init__(self, processed_vulnerabilities, metasploit_modules, tfidf_corpus, min_score=0.25):
        self.processed_vulnerabilities = processed_vulnerabilities
        self.metasploit_modules = metasploit_modules
        self.tfidf_corpus = tfidf_corpus
        self.min_score = min_score
        self.vectorizer = TfidfVectorizer()

    def map_vulnerabilities_to_modules(self):
        """Search Metasploit modules using TF-IDF."""

        tfidf_matrix = self.vectorizer.fit_transform(self.tfidf_corpus)
        query_matrix = self.vectorizer.transform(self.processed_vulnerabilities)
        results = []
        for i, query in enumerate(self.processed_vulnerabilities):
            scores = cosine_similarity(query_matrix[i], tfidf_matrix).flatten()
            max_index = np.argmax(scores)
            max_score = scores[max_index]

            if max_score > self.min_score:
                matched_module = self.metasploit_modules[max_index]
                results.append({
                    "query": query,
                    "matched_module": matched_module["fullname"],
                    "score": max_score,
                })
            else:
                results.append({
                    "query": query,
                    "matched_module": "No module found",
                    "score": max_score,
                })
        return results


# %%
# MetasploitBM25 Class
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


# %%
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
                    "query": vuln,
                    "matched_module": best_module.get("fullname", "Unknown"),
                    "score": max_score,
                })
            else:
                results.append({
                    "query": vuln,
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


# %%
import GVM.GVM.gvm as gvm


class ModulesDetection:
    """Handles GVM vulnerabilities and Metasploit module interactions."""

    def __init__(self, msf_client):
        self.gvm_client = None  # Replace with GVM client if needed
        self.msf_client = msf_client

    def get_vulnerability_details(self, vuln_id):
        """Retrieve vulnerability details from GVM."""
        vuln = gvm.get_result(id=vuln_id)  # Mocked GVM client
        # print(vuln)
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
        """Search Metasploit modules by CVE IDs."""
        cve_results = []
        for cve_id in cve_ids:
            results = self.msf_client.call('module.search', [cve_id])
            results = [str(result) for result in results]
            cve_results.extend(results)

        # Rank and extract top CVE matches
        counter = Counter(cve_results)
        top_cves = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        return [eval(cve[0]) for cve in top_cves if cve[1] == top_cves[0][1]]

    def extract_target_uri(self, description, host):
        """Extract the target URI from the vulnerability description."""
        try:
            target_uri = re.split(rf"{host}|port:", description)[-1].strip()
            return "" if "/" not in target_uri else target_uri
        except Exception:
            return ""

    def get_vuln_ids(self, report_id="c572f205-ba3e-40aa-8136-5ed3e0ad715b"):
        response = gvm.get_report(id=report_id)
        response = ET.fromstring(response).find('report').find(
            'report').find('results').findall('result')
        list_ids = []
        for child in response:
            list_ids.append(child.attrib['id'])
        return list_ids

    def format_module_data(self, modules):
        """Format Metasploit modules for rendering."""
        return [{"name": f"{module['name']} : {module['fullname']}", "module": module["fullname"]} for module in
                modules]


# %%
# Execution Section
# Initialize the client and classes
msf_client = MsfRpcClient('msf', port=55552, username='msf', server='127.0.0.1')
modules_detection = ModulesDetection(msf_client)
base_search = BaseSearch()

# Initialize paths
modules_file = "modules.json"
modules_attrib_file = "modules_attrib.json"

# Initialize DataHandler and MetasploitBM25
data_handler = DataHandler(modules_file, modules_attrib_file, msf_client)
# Uncomment to fetch or enrich modules
# metasploit.get_all_modules()
# metasploit.create_module_attrib()

results = data_handler.load_json_file("/home/kali/Documents/UET/ADAT/Core/modules_detection/modules_result.json")
list_ids = modules_detection.get_vuln_ids()


# %%
def run_tfidf_search():
    # Load modules and prepare BM25 data
    metasploit_modules = data_handler.load_module_attrib()
    tfidf_corpus = data_handler.prepare_tfidf_corpus(metasploit_modules)
    correct_matches = 0
    total_comparisons = 0
    no_module_cnt = 0
    # for vuln_id in tqdm(list_ids, desc="Search Module by BM25 Method"):
    for vuln_id in list_ids:
        vuln_details = modules_detection.get_vulnerability_details(vuln_id)
        name, description, port, cve_refs, host = (
            vuln_details["name"],
            vuln_details["description"],
            vuln_details["port"],
            vuln_details["cve"],
            vuln_details["host"],
        )
        text = name
        if cve_refs is not None:
            for ref in cve_refs:
                if 'type' in ref.attrib and ref.attrib['type'] == 'cve':
                    text += ref.attrib['id'] + " "
        if description is not None:
            gvm_vulnerabilities = [
                f"{text}",
                description,
            ]
        else:
            gvm_vulnerabilities = [
                f"{text}"
            ]
        # processed_vulnerabilities = data_handler.process_gvm_vulnerabilities(gvm_vulnerabilities)
        # Map vulnerabilities to modules
        metasploit = TfidfSearch(gvm_vulnerabilities, metasploit_modules, tfidf_corpus, min_score=0)
        mapping_result = metasploit.map_vulnerabilities_to_modules()

        # Display results
        # for result in mapping_results:
        #     print(f"Vulnerability: {result['vulnerability']}")
        #     print(f"Matched Module: {result['matched_module']}")
        #     #print(f"Matched RPORT: {result['rport']}")
        #     #print(f"Score: {result['score']:.2f}\n")
        matching_json_entry = next(
            (item for item in results if item["Name"] == name and item["Port"] == port),
            None,
        )
        if matching_json_entry:
            # Compare the module found with the module in the JSON
            json_module = matching_json_entry["Module"]
            if json_module == "No module found":
                no_module_cnt += 1
            if mapping_result:
                if json_module == mapping_result[0]["matched_module"]:
                    correct_matches += 1
                else:
                    print(
                        f"STT: {total_comparisons + 1}, {json_module} | {mapping_result[0]['matched_module']} | {mapping_result[0]['score']:.2f}")
                    # print("")
            else:
                if json_module == "No module found":
                    correct_matches += 1
                else:
                    # print("")
                    print(
                        f"STT: {total_comparisons + 1}, {json_module} | {mapping_result[0]['matched_module']} | {mapping_result[0]['score']:.2f}")
        total_comparisons += 1
    print(f"No modules found: {no_module_cnt}")
    print(f"Accuracy: {correct_matches}/{total_comparisons}")
    # Calculate accuracy
    if total_comparisons == 0:
        print(f"Accuracy of TF/IDF Method: {total_comparisons:.2%}")  # Avoid division by zero
    else:
        accuracy = correct_matches / total_comparisons
        print(f"Accuracy of TF/IDF Method: {accuracy:.2%}")
        # Print results
        # print(f"CVE Modules: {cve_modules}")
        # print(f"Exploit Modules: {exploit_modules[0]['module']}")


# run_tfidf_search()
# %%
def run_bm25_search():
    # Load modules and prepare BM25 data
    metasploit_modules = data_handler.load_module_attrib()
    bm25_corpus = data_handler.prepare_bm25_data(metasploit_modules)
    correct_matches = 0
    total_comparisons = 0
    no_module_cnt = 0
    # for vuln_id in tqdm(list_ids, desc="Search Module by BM25 Method"):
    for vuln_id in list_ids:
        vuln_details = modules_detection.get_vulnerability_details(vuln_id)
        # break
        name, description, port, cve_refs, host = (
            vuln_details["name"],
            vuln_details["description"],
            vuln_details["port"],
            vuln_details["cve"],
            vuln_details["host"],
        )
        text = name + port
        if cve_refs is not None:
            for ref in cve_refs:
                if 'type' in ref.attrib and ref.attrib['type'] == 'cve':
                    text += ref.attrib['id'] + " "
        if description is not None:
            gvm_vulnerabilities = [
                f"{text}",
                f"{port}",
                description,
            ]
        else:
            gvm_vulnerabilities = [
                f"{text}",
                f"{port}",
            ]
        processed_vulnerabilities = data_handler.process_gvm_vulnerabilities(gvm_vulnerabilities)
        # Map vulnerabilities to modules
        metasploit = MetasploitBM25(processed_vulnerabilities, metasploit_modules, bm25_corpus)
        mapping_result = metasploit.map_vulnerabilities_to_modules()

        # Display results
        # for result in mapping_results:
        #     print(f"Vulnerability: {result['vulnerability']}")
        #     print(f"Matched Module: {result['matched_module']}")
        #     #print(f"Matched RPORT: {result['rport']}")
        #     #print(f"Score: {result['score']:.2f}\n")
        matching_json_entry = next(
            (item for item in results if item["Name"] == name and item["Port"] == port),
            None,
        )
        if matching_json_entry:
            # Compare the module found with the module in the JSON
            json_module = matching_json_entry["Module"]
            if json_module == "No module found":
                no_module_cnt += 1
            if mapping_result:
                if json_module == mapping_result[0]["matched_module"]:
                    correct_matches += 1
                else:
                    print(
                        f"STT: {total_comparisons + 1}, {json_module} | {mapping_result[0]['matched_module']} | {mapping_result[0]['score']:.2f}")
                    # print("")
            else:
                if json_module == "No module found":
                    correct_matches += 1
                else:
                    # print("")
                    print(
                        f"STT: {total_comparisons + 1}, {json_module} | {mapping_result[0]['matched_module']} | {mapping_result[0]['score']:.2f}")
        total_comparisons += 1
    print(f"No modules found: {no_module_cnt}")
    print(f"Accuracy: {correct_matches}/{total_comparisons}")
    # Calculate accuracy
    if total_comparisons == 0:
        print(f"Accuracy of BM25 Method: {total_comparisons:.2%}")  # Avoid division by zero
    else:
        accuracy = correct_matches / total_comparisons
        print(f"Accuracy of BM25 Method: {accuracy:.2%}")
        # Print results
        # print(f"CVE Modules: {cve_modules}")
        # print(f"Exploit Modules: {exploit_modules[0]['module']}")


run_bm25_search()


# %%
def run_enhanced_bm25_search():
    # Load modules and prepare BM25 data
    metasploit_modules = data_handler.load_module_attrib()
    bm25_corpus = data_handler.prepare_bm25_data(metasploit_modules)
    correct_matches = 0
    total_comparisons = 0
    no_module_cnt = 0
    # for vuln_id in tqdm(list_ids, desc="Search Module by BM25 Method"):
    for vuln_id in list_ids:
        vuln_details = modules_detection.get_vulnerability_details(vuln_id)
        name, description, port, cve_refs, host = (
            vuln_details["name"],
            vuln_details["description"],
            vuln_details["port"],
            vuln_details["cve"],
            vuln_details["host"],
        )
        text = name
        if cve_refs is not None:
            for ref in cve_refs:
                if 'type' in ref.attrib and ref.attrib['type'] == 'cve':
                    text += ref.attrib['id'] + " "
        if description is not None:
            gvm_vulnerabilities = [
                f"{text}",
                f"{port}",
                description,
            ]
        else:
            gvm_vulnerabilities = [
                f"{text}",
                f"{port}"
            ]
        processed_vulnerabilities = data_handler.process_gvm_vulnerabilities(gvm_vulnerabilities)
        # Map vulnerabilities to modules
        metasploit = EnhancedBM25Search(min_score=13.1, cve_weight=5)
        mapping_result = metasploit.map_vulnerabilities_to_modules(processed_vulnerabilities, metasploit_modules,
                                                                   bm25_corpus)

        # Display results
        # for result in mapping_results:
        #     print(f"Vulnerability: {result['vulnerability']}")
        #     print(f"Matched Module: {result['matched_module']}")
        #     #print(f"Matched RPORT: {result['rport']}")
        #     #print(f"Score: {result['score']:.2f}\n")
        matching_json_entry = next(
            (item for item in results if item["Name"] == name and item["Port"] == port),
            None,
        )
        if matching_json_entry:
            # Compare the module found with the module in the JSON
            json_module = matching_json_entry["Module"]
            if json_module == "No module found":
                no_module_cnt += 1
            if mapping_result:
                if json_module == mapping_result[0]["matched_module"]:
                    correct_matches += 1
                else:
                    print(
                        f"STT: {total_comparisons + 1}, {json_module} | {mapping_result[0]['matched_module']} | {mapping_result[0]['score']:.2f}")
                    # print("")
            else:
                if json_module == "No module found":
                    correct_matches += 1
                else:
                    # print("")
                    print(
                        f"STT: {total_comparisons + 1}, {json_module} | {mapping_result[0]['matched_module']} | {mapping_result[0]['score']:.2f}")
            total_comparisons += 1
    print(f"No modules found: {no_module_cnt}")
    print(f"Accuracy: {correct_matches}/{total_comparisons}")
    # Calculate accuracy
    if total_comparisons == 0:
        print(f"Accuracy of Enhanced BM25 Rate: {total_comparisons:.2%}")  # Avoid division by zero
    else:
        accuracy = correct_matches / total_comparisons
        print(f"Accuracy of Enhanced BM25 Rate: {accuracy:.2%}")
        # Print results
        # print(f"CVE Modules: {cve_modules}")
        # print(f"Exploit Modules: {exploit_modules[0]['module']}")


run_enhanced_bm25_search()


# %%
def run_enhanced_bm25_search_1():
    # Load modules and prepare BM25 data
    metasploit_modules = data_handler.load_module_attrib()
    bm25_corpus = data_handler.prepare_bm25_data(metasploit_modules)
    correct_matches = 0
    total_comparisons = 0
    no_module_cnt = 0
    # for vuln_id in tqdm(list_ids, desc="Search Module by BM25 Method"):
    for vuln_id in list_ids:
        vuln_details = modules_detection.get_vulnerability_details(vuln_id)
        name, description, port, cve_refs, host = (
            vuln_details["name"],
            vuln_details["description"],
            vuln_details["port"],
            vuln_details["cve"],
            vuln_details["host"],
        )
        text = name
        if cve_refs is not None:
            for ref in cve_refs:
                if 'type' in ref.attrib and ref.attrib['type'] == 'cve':
                    text += " " + ref.attrib['id'] + " "
        if description is not None:
            gvm_vulnerabilities = [
                f"{text}",
                description,
            ]
        else:
            gvm_vulnerabilities = [
                f"{text}"
            ]
        processed_vulnerabilities = data_handler.process_gvm_vulnerabilities(gvm_vulnerabilities)
        # Map vulnerabilities to modules
        metasploit = EnhancedBM25Search(min_score=13.1, cve_weight=5)
        mapping_result = metasploit.map_vulnerabilities_to_modules_1(processed_vulnerabilities, metasploit_modules,
                                                                     bm25_corpus, 3)

        # Display results
        # for result in mapping_results:
        #     print(f"Vulnerability: {result['vulnerability']}")
        #     print(f"Matched Module: {result['matched_module']}")
        #     #print(f"Matched RPORT: {result['rport']}")
        #     #print(f"Score: {result['score']:.2f}\n")
        matching_json_entry = next(
            (item for item in results if item["Name"] == name and item["Port"] == port),
            None,
        )
        if matching_json_entry:
            # Compare the module found with the module in the JSON
            json_module = matching_json_entry["Module"]
            if json_module == "No module found":
                no_module_cnt += 1
            # print(mapping_result[0])
            if mapping_result:
                if json_module == mapping_result[0]['top_results'][0]['matched_module']:
                    correct_matches += 1
                else:
                    print(
                        f"STT: {total_comparisons + 1}, {json_module} | {mapping_result[0]['top_results'][0]['matched_module']} {mapping_result[0]['top_results'][0]['score']:.2f} | {mapping_result[0]['top_results'][1]['matched_module']} {mapping_result[0]['top_results'][1]['score']:.2f} | {mapping_result[0]['top_results'][2]['matched_module']} {mapping_result[0]['top_results'][2]['score']:.2f}")
                    # print("")
            else:
                if json_module == "No module found":
                    correct_matches += 1
                else:
                    # print("")
                    print(
                        f"STT: {total_comparisons + 1}, {json_module} | {mapping_result[0]['top_results'][0]['matched_module']} {mapping_result[0]['top_results'][0]['score']:.2f} | {mapping_result[0]['top_results'][1]['matched_module']} {mapping_result[0]['top_results'][1]['score']:.2f} | {mapping_result[0]['top_results'][2]['matched_module']} {mapping_result[0]['top_results'][2]['score']:.2f}")
            total_comparisons += 1
    print(f"No modules found: {no_module_cnt}")
    print(f"Accuracy: {correct_matches}/{total_comparisons}")
    # Calculate accuracy
    if total_comparisons == 0:
        print(f"Accuracy of Enhanced BM25 Rate: {total_comparisons:.2%}")  # Avoid division by zero
    else:
        accuracy = correct_matches / total_comparisons
        print(f"Accuracy of Enhanced BM25 Rate: {accuracy:.2%}")
        # Print results
        # print(f"CVE Modules: {cve_modules}")
        # print(f"Exploit Modules: {exploit_modules[0]['module']}")


# run_enhanced_bm25_search_1()
# %%
def run_base_search():
    correct_matches = 0
    total_comparisons = 0
    for vuln_id in tqdm(list_ids, desc="Search Module by Base Method"):
        vuln_details = modules_detection.get_vulnerability_details(vuln_id)
        name, description, port, cve_refs, host = (
            vuln_details["name"],
            vuln_details["description"],
            vuln_details["port"],
            vuln_details["cve"],
            vuln_details["host"],
        )
        # Search for CVE-based modules
        cve_ids = modules_detection.extract_cve_ids(cve_refs)
        cve_modules = modules_detection.search_cves(cve_ids)

        # Search for exploits using BaseSearch
        exploit_modules = base_search.base_search_exploits(msf_client, name, description)
        matching_json_entry = next(
            (item for item in results if item["Name"] == name and item["Port"] == port),
            None,
        )
        if matching_json_entry:
            # Compare the module found with the module in the JSON
            json_module = matching_json_entry["Module"]
            if exploit_modules:
                # print(exploit_modules[0])
                if json_module == exploit_modules[0]["module"]:
                    correct_matches += 1
            else:
                if matching_json_entry["Module"] == "No module found":
                    correct_matches += 1
            total_comparisons += 1
    # Calculate accuracy
    if total_comparisons == 0:
        print(f"Accuracy: {total_comparisons:.2%}")  # Avoid division by zero
    else:
        accuracy = correct_matches / total_comparisons
        print(f"Accuracy of Base Method: {accuracy:.2%}")
        # Print results
        # print(f"CVE Modules: {cve_modules}")
        # print(f"Exploit Modules: {exploit_modules[0]['module']}")


# %%
run_base_search()
# %% md
### Calculate Accuracy
# %%
# def calculate_accuracy(results):
#     #print(results[0])
#     for
#
# results = data_handler.load_json_file("/home/kali/Documents/UET/ADAT/Core/modules_detection/modules_result.json")
# accuracy = calculate_accuracy(results, mapping_results, )