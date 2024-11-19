from rank_bm25 import BM25Okapi
from pymetasploit3.msfrpc import MsfRpcClient
import nltk
from nltk.tokenize import word_tokenize
import json
# Khởi tạo Metasploit RPC client
client = MsfRpcClient('msf', port=55552, username='msf', server='127.0.0.1')

def create_module_attrib():
    with open('modules.json', 'r') as file:
        data = json.load(file)
    module_info = []
    for module in data["modules"]:
        info = client.modules.use('exploit', module)
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
        text = f"{module['name']} {module['description']} {module['rport']}"
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
    # Danh sách lỗ hổng từ GVM
    #create_module_attrib()
    gvm_vulnerabilities = [
        "The rexec service is running on port 512",
        "rlogin Passwordless Login on port 513",
        "TWiki XSS and Command Execution Vulnerabilities on port 80",
        "vsftpd Compromised Source Packages Backdoor Vulnerability on port 21",
    ]

    # Lấy module Metasploit và chuẩn bị dữ liệu
    metasploit_modules = get_metasploit_modules()
    bm25_corpus = prepare_bm25_data(metasploit_modules)
    processed_vulnerabilities = process_gvm_vulnerabilities(gvm_vulnerabilities)
    # Tìm kiếm module phù hợp
    mapping_results = map_vulnerabilities_to_modules(gvm_vulnerabilities, metasploit_modules, bm25_corpus)

    # In kết quả
    for result in mapping_results:
        print(f"Vulnerability: {result['vulnerability']}")
        print(f"Matched Module: {result['matched_module']}")
        print(f"Matched RPORT: {result['rport']}")
        print(f"Score: {result['score']}\n")
