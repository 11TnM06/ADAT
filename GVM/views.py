from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.template import loader
from django.views import View
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_protect
import GVM.GVM.gvm as gvm
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

class Target_View(View):
    def get(self, request):
        targets = gvm.get_targets()
        targets = ET.fromstring(targets).findall('target')
        
        targets = [{"name": child.find('name').text, "id": child.attrib['id'],
        "hosts": child.find('hosts').text, "comment": child.find('comment').text,
        "port_list": child.find('port_list').find('name').text,
        "hosts": child.find('hosts').text,
        "in_use": child.find('in_use').text,
        } for child in targets]

        port_lists = gvm.get_port_lists()
        port_lists = ET.fromstring(port_lists)
        port_lists = port_lists.findall("port_list")
        port_lists_id = [{'name': child.find(
            'name').text, "id": child.attrib['id']} for child in port_lists]
        return render(request, "gvm-ui/target.html", 
        {"port_lists": port_lists_id, "targets":targets})
    def post(self, request):
        name = request.POST.get('name', None)
        comment = request.POST.get("comment", "")
        hosts = request.POST.get('hosts', None)
        port_lists = request.POST.get("port_lists", None)
        if (name or hosts) is None:
            port_lists = gvm.get_port_lists()
            port_lists = ET.fromstring(port_lists)
            port_lists = port_lists.findall("port_list")
            port_lists_id = [{'name': child.find(
                'name').text, "id": child.attrib['id']} for child in port_lists]
            return render(request, "gvm/target.html", {"port_lists": port_lists_id})
        gvm.create_target(hosts=[hosts], comment=comment,
                          name=name, port_list_id=port_lists)
        return self.get(request)
    def delete(self, request, id):
        gvm.delete_target(id)
        return self.get(request)
class Task_View(View):
    def get(self, request):
        return render(request, "gvm-ui/task.html")
class Report_View(View):
    def get(self, request):
        return render(request, "gvm-ui/report.html")
        

    