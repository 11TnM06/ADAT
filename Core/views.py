from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.template import loader
from django.views import View
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_protect
class Home_View(View):
    def get(self, request, **kwargs):
        return render(request, "dashboard/home.html")
    
        

    