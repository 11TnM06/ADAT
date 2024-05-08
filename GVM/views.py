from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.template import loader
from django.views import View
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_protect
class Target_View(View):
    def get(self, request):
        return render(request, "gvm-ui/target.html")
    def post(self, request):
        return render(request, "gvm-ui/target.html")
    
        

    