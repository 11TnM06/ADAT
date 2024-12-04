from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.template import loader
from django.views import View
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_protect

from pymetasploit3.msfrpc import MsfRpcClient
from .env import cve_lists, exploit_lists
import GVM.GVM.gvm as gvm
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import time
from collections import Counter

from nltk.tokenize import word_tokenize
import nltk
from nltk.corpus import stopwords
import re
from sklearn.feature_extraction.text import TfidfVectorizer

from .modules_detection.modules_detection import ModulesDetection
from .modules_detection.metasploit_bm25 import MetasploitBM25
msf_user = 'msf'
msf_pass = 'msf'
msf_host = '127.0.0.1'
msf_port = 55552

client = MsfRpcClient(msf_pass, port=msf_port,
                      username=msf_user, server=msf_host)
host = "192.168.1.27"
port = "8888"
host_name = host + ":" + port


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


class Home_View(View):
    def get(self, request, **kwargs):
        return render(request, "dashboard/home.html")


class Auto_View(View):
    def get(self, request, id1, **kwargs):
        host = request.get_host()
        username = request.user.username

        # init module detection
        modules_detection = ModulesDetection(client)

        # get vulnerability details
        vuln_details = modules_detection.get_vulnerability_details(id1)
        name, description, port, cve, host, et = vuln_details.values()

        # search cve
        search_cve = modules_detection.extract_cve_ids(cve)

        top_cve_modules = modules_detection.search_cves(search_cve)
        cve_result = modules_detection.format_module_data(top_cve_modules)[:5]

        print("Core\\views\Auto\cve_result: ", end=" ")
        print(cve_result, end='\n\n')

        # search exploit modules by base method
        exploits = modules_detection.base_search_exploits(name, description)

        # search exploit modules by BM25 method
        metasploitBM25 = MetasploitBM25(client)
        metasploit_modules = metasploitBM25.get_metasploit_modules()
        gvm_vulnerabilities = [name]
        bm25_corpus = metasploitBM25.prepare_bm25_data(metasploit_modules)
        processed_vulnerabilities = metasploitBM25.process_gvm_vulnerabilities(gvm_vulnerabilities)
        mapping_results = metasploitBM25.map_vulnerabilities_to_modules(
            gvm_vulnerabilities, metasploit_modules, bm25_corpus
        )

        print(f"Vulnerability: {mapping_results[    0]['vulnerability']}")
        print(f"Matched Module: {mapping_results[0]['matched_module']}")
        print(f"Matched RPORT: {mapping_results[0]['rport']}")
        print(f"Score: {mapping_results[0]['score']:.2f}\n")
        formatted_exploits = [
            {"name": f"{mapping_results[0]['vulnerability']} : {mapping_results[0]['matched_module']}", "module": {mapping_results[0]['matched_module']}}
        ]
        # extract targetURI
        targetURI = modules_detection.extract_target_uri(et.find('description').text, et.find('host').text)
        print(targetURI)
        #exploits.insert(0, "")
        #print("exploits: ", exploits)
        #print("targetURI: ", targetURI)
        return render(request, "core/auto.html",
                      {"username": username, "exploits": formatted_exploits, 'host': host, 'name': name, "port": port,
                       "targetURI": targetURI})

def analyze_with_tfidf(text, top_n=5):
    stop_words = set(stopwords.words('english'))
    tfidf = TfidfVectorizer(max_features=top_n, stop_words=stop_words)
    tfidf_matrix = tfidf.fit_transform([text])
    keywords = tfidf.get_feature_names_out()
    print("AI Keywords: ", keywords)
    return keywords