from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.template import loader
from django.views import View
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_protect
import GVM.GVM.gvm as gvm
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import time

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
            return render(request, "gvm-ui/target.html", {"port_lists": port_lists_id})

        create_target_response = gvm.create_target(hosts=[hosts], comment=comment, name=name, port_list_id=port_lists)
        create_target_response = ET.fromstring(create_target_response)
        body_html = {"status": create_target_response.attrib['status'], 
        "status_text": create_target_response.attrib['status_text']} 
        if  create_target_response.attrib['status'] == "201":
            target_id = create_target_response.attrib['id']
            target = gvm.get_target(target_id)
            target = ET.fromstring(target).find('target')
            target_data = {"name": target.find('name').text, "id": target.attrib['id'],
                "hosts": target.find('hosts').text, "comment": target.find('comment').text,
                "port_list": target.find('port_list').find('name').text,
                "hosts": target.find('hosts').text,
                "in_use": target.find('in_use').text,
            }        
            body_html.update({"target": target_data})
        response = JsonResponse(body_html) 
        return response
    def delete(self, request, id):
        delete_response = gvm.delete_target(id)
        delete_response = ET.fromstring(delete_response)
        body_html = {"status": delete_response.attrib["status"], "status_text": delete_response.attrib["status_text"]}
        response = JsonResponse(body_html) 
        return response
class Report_View(View):
    def get(self, request, id):
        response = gvm.get_report(id=id)
        task_name = ET.fromstring(response).find('report').find('task').find("name").text
        response = ET.fromstring(response).find('report').find(
            'report').find('results').findall('result')
        all=0
        high =0
        medium =0
        low =0
        for child in response:
            all+=1
            text = child.find('threat').text
            print(child.find('port').text)
            if text=="High":
                high+=1
            elif text == "Medium":
                medium+=1
            elif text == "Low":
                low+=1
        response = [
            {
                "id":child.attrib['id'],
                "name":child.find('name').text, 
                "threat":child.find('threat').text,
                "severity":float(child.find("severity").text),  
                "host":child.find("host").text, 
                "port":child.find("port").text, 
                # "detection":[
                #                 {
                #                 "id":child.find("detection").find("result").attrib['id'] if child.find('detection') is not None else None,
                #                 "details":{[
                #                                 {'name':x.find("result").find("details").findall('detail').find("name") if child.find('detection') is not None else None, 
                #                                 "value":x.find("result").find("details").findall('detail').find("value") if child.find('detection') is not None else None } for x in child.find("detection")
                #                 ]
                                                
                #                         }
                #                 }
                #             ]
                "description":child.find("description").text, 
            }
            for child in response
            ]
        return render(request, "gvm-ui/report.html", {"response": response,"task_name":task_name, "counts":{"All":all, "High":high, "Medium": medium, "Low":low}})
class Task_View(View):
    def get(self, request):
        scancofig = gvm.get_scan_configs()
        scancofig= ET.fromstring(scancofig).findall('config')
        scancofig=[{"id":child.attrib['id'],"name":child.find('name').text} for child in scancofig]

        scanners = gvm.get_scanners()
        scanners= ET.fromstring(scanners).findall('scanner')
        scanners=[{"id":child.attrib['id'],"name":child.find('name').text} for child in scanners]

        targets = gvm.get_targets()
        targets = ET.fromstring(targets).findall('target')
        targets = [{"name": child.find('name').text, "id": child.attrib['id']} for child in targets]

        response = gvm.get_tasks()
        tasks = ET.fromstring(response).findall('task')
        tasks = [{"name": child.find("name").text, "id": child.attrib['id'],"comment":child.find("comment").text,"target": child.find('target').find('name').text,"scanner":child.find('scanner').find('name').text,"config":child.find("config").find('name').text, 'status':child.find("status").text, "progress": child.find('progress').text, "report": "None" if len([x.find('report') for x in child.findall('last_report') if int(child.find('report_count').text) > 0])==0 else [x.find('report').attrib['id'] for x in child.findall('last_report') if int(child.find('report_count').text)][0] }
                   for child in tasks]
        print(tasks)
        return render(request, "gvm-ui/task.html",{'scanner_lists':scancofig,"scanners":scanners, "targets":targets, "tasks":tasks})
    def post(self, request):
        
        name=request.POST.get("name", None)
        config_id= request.POST.get("config_id", None)
        target_id=request.POST.get("target_id", None)
        scanner_id=request.POST.get("scanner_id", None)
        comment=request.POST.get("comment", None)
        print(name, config_id, target_id, scanner_id)
        body_html = {}
        if (name and config_id and target_id and scanner_id) is None:
            message = "Please fill all the fields name, config_id, target_id, scanner_id"
            body_html.update({"status": "404", "status_text": message})
        else:
            create_task_response = gvm.create_task(name, config_id, target_id, scanner_id, comment)
            create_task_response = ET.fromstring(create_task_response)
            body_html = {"status": create_task_response.attrib['status'],
            "status_text": create_task_response.attrib['status_text']}
            if create_task_response.attrib['status'] == "201":
                task_id = create_task_response.attrib['id']
                task = gvm.get_task(task_id)
                task = ET.fromstring(task).find('task')
                task_data = {"name": task.find('name').text, "id": task.attrib['id'],
                    "comment": task.find('comment').text, "status": task.find('status').text,
                    "target": task.find('target').find('name').text, "scanner": task.find('scanner').find('name').text,
                    "config": task.find('config').find('name').text, "report": "None" if len([x.find('report') for x in task.findall('last_report') if int(task.find('report_count').text) > 0])==0 else [x.find('report').attrib['id'] for x in task.findall('last_report') if int(task.find('report_count').text)][0]}
                body_html.update({"task": task_data})
        response = JsonResponse(body_html) 
        
        return response

    def delete(self, request, id):
        delete_response = gvm.delete_task(id)
        delete_response = ET.fromstring(delete_response)
        body_html = {"status": delete_response.attrib["status"], "status_text": delete_response.attrib["status_text"]}
        response = JsonResponse(body_html) 
        print(response)
        return response

class ActionTask_View(View):
    def get(self, request, action, id):
        if action =="status":
            response = gvm.get_task(id=id)
            response= ET.fromstring(response)
            status = response.find('task').find("status").text
            if status == 'Running':
                progress = response.find('task').find("progress").text
                return JsonResponse({"status":status, "progress":progress}, safe=False)
            time.sleep(2)
            return JsonResponse({"status":status}, safe=False)
        
    def post(self, request, action):
        task_id=request.POST.get("task_id", None)
        if action == "start":
            body_html=gvm.start_task(id=task_id)
            body_html=ET.fromstring(body_html)
            response = {"status": body_html.attrib['status'], "status_text": body_html.attrib['status_text']}
            return JsonResponse(response)
        elif action=="stop":
            response=gvm.stop_task(id=task_id)
            return HttpResponse(response)
        return HttpResponse(status=404)

    def delete(self, request, action):
        task_id=request.POST.get("task_id", None)
        gvm.delete_task(task_id)
        print(action)

        return HttpResponse(status=200) 