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

        vuln = gvm.get_result(id=id1)
        et = ET.fromstring(vuln).find("result")
        name = et.find('name').text
        description = et.find('description').text
        port = et.find('port').text.split('/')[0]
        cve = None if et.find('nvt').find('refs') is None else et.find('nvt').find("refs").findall('ref')

        # search cve
        search_cve = []
        # print full et details
        print(ET.tostring(et).decode("utf-8"))
        if cve is not None:
            search_cve = [child.attrib['id'] for child in cve if child.attrib['type'] == "cve"]

        cve_results = []
        for child in search_cve:
            results = client.call('module.search', [child])
            results = [str(child) for child in results]
            cve_results.extend(results)
        counter = Counter(list(cve_results))
        cve_result = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        cve_result = [eval(child[0]) for child in cve_result[0:5] if child[1] == cve_result[0][1]]
        cve_result = [{"name": child['name'] + " : " + child["fullname"], "module": child["fullname"]} for child in
                      cve_result][0:5]
        print("Core\\views\Auto\cve_result: ", end=" ")

        print(cve_result, end='\n\n')

        # search exploit
        search_term = []
        if name is not None:
            search_term = extract_keywords(name)
        if description is not None:
            search_term += extract_keywords(description)
        print("search team: ", search_term)

        search_results = []
        for child in search_term:
            results = client.call('module.search', [child])
            results = [str(child) for child in results]
            search_results.extend(results)
        counter = Counter(list(search_results))
        search_results = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        results = []
        for child in search_results[0:100]:
            if child[1] == search_results[0][1]:
                evaluated_child = eval(child[0])
                results.append(evaluated_child)
        exploits = [{"name": child['name'] + " : " + child["fullname"], "module": child["fullname"]} for child in
                    results][0:1]
        host = et.find('host').text
        targetURI = ""
        try:
            targetURI = re.split(rf"{host}|port:", et.find('description').text)[-1].strip()
        except:
            pass
        if "/" not in targetURI:
            targetURI = ""
        print(targetURI)
        exploits.insert(0, "")
        print("exploits: ", exploits)
        print(host)
        print("targetURI: ", targetURI)
        return render(request, "dashboard/home.html",
                      {"username": username, "exploits": exploits, 'host': host, 'name': name, "port": port,
                       "targetURI": targetURI})
