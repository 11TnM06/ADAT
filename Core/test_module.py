from rank_bm25 import BM25Okapi
from pymetasploit3.msfrpc import MsfRpcClient
import nltk
from nltk.tokenize import word_tokenize
import json
from tqdm import tqdm
# Khởi tạo Metasploit RPC client
client = MsfRpcClient('msf', port=55552, username='msf', server='127.0.0.1')


def get_all_modules():
    # Fetch exploit and auxiliary modules
    exploits = client.modules.exploits
    auxiliaries = client.modules.auxiliary

    # Create a list to store module information with tags
    all_modules = []

    # Add exploit modules with the 'type' tag
    for exploit in tqdm(exploits, desc="Find exploit modules"):
        all_modules.append({
            "name": exploit,
            "type": "exploit"
        })

    # Add auxiliary modules with the 'type' tag
    for auxiliary in tqdm(auxiliaries, desc="Find auxiliary modules"):
        all_modules.append({
            "name": auxiliary,
            "type": "auxiliary"
        })

    # Save to a JSON file
    with open('modules.json', 'w') as file:
        json.dump(all_modules, file, indent=4)  # Use indent=4 for readable JSON output

    print(f"Total modules saved: {len(all_modules)}")
    return

def create_module_attrib():
    with open('modules.json', 'r') as file:
        data = json.load(file)
    module_info = []
    for module in tqdm(data, desc="Add module attributes"):
        try:
            if module['type'] == 'exploit':
                info = client.modules.use('exploit', module['name'])
            else:
                info = client.modules.use('auxiliary', module['name'])
        except Exception as e:
            print(f"Error processing module {module}: {e}")
            continue
        if 'RPORT' in info.options:
            rport = str(info['RPORT'])
        else:
            rport = ""
        module_info.append({
            "fullname": info.fullname,
            "name": info.name,
            "description": info.description,
            "rport": rport,
            "references": info.references,
        })

    with open('modules_attrib.json', 'w') as file:
        json.dump(module_info, file)

# Lấy danh sách các module từ Metasploit
def get_metasploit_modules():
    with open('modules_attrib.json', 'r') as file:
        data = json.load(file)
    return data

# Chuẩn bị dữ liệu cho BM25
def prepare_bm25_data(modules):
    corpus = []
    for module in modules:
        # Gộp tên và mô tả để làm tài liệu cho BM25
        text = f"{module['name']} {module['description']}"
        corpus.append(word_tokenize(text.lower()))
    return corpus

# Xử lý dữ liệu GVM
def process_gvm_vulnerabilities(vulnerabilities):
    return [word_tokenize(vuln.lower()) for vuln in vulnerabilities]

# Tìm module phù hợp với lỗ hổng từ GVM
def map_vulnerabilities_to_modules(vulnerabilities, modules, bm25_corpus):
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
            "score": scores[best_match_index]
        })
    return results

# Main
if __name__ == "__main__":
    get_all_modules()
    # Danh sách lỗ hổng từ GVM
    create_module_attrib()
    gvm_vulnerabilities = [
        "The rexec service is running",
        "rlogin Passwordless Login",
        "TWiki XSS and Command Execution Vulnerabilities",
        "vsftpd Compromised Source Packages Backdoor Vulnerability",
    ]

    # Lấy module Metasploit và chuẩn bị dữ liệu
    metasploit_modules = get_metasploit_modules()
    bm25_corpus = prepare_bm25_data(metasploit_modules)
    processed_vulnerabilities = process_gvm_vulnerabilities(gvm_vulnerabilities)
    # Tìm kiếm module phù hợp
    mapping_results = map_vulnerabilities_to_modules(gvm_vulnerabilities, metasploit_modules, bm25_corpus)

    # In kết quả tìm kiếm
    for result in mapping_results:
        print(f"Vulnerability: {result['vulnerability']}")
        print(f"Matched Module: {result['matched_module']}")
        print(f"Matched RPORT: {result['rport']}")
        print(f"Score: {result['score']}\n")

