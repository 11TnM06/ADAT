from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.template import loader
from django.views import View
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_protect
class Home_View(View):
    def get(self, request, **kwargs):
        return render(request, "dashboard/home.html")
    def post(self, request, **kwargs):
        if request.user.is_authenticated:
            logout(request)
            # release authenticated user and log out
        return redirect("../accounts/login")
        

    