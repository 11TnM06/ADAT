from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.template import loader
from .forms import LoginForm, SignUpForm
from django.views import View
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.models import User

class Login_View(View):
    def get(self, request):
        form = LoginForm(request.POST or None)
        msg = None
        return render(request, "accounts/login.html", {"form": form, "msg": msg})
    def post(self, request):
        form = LoginForm(request.POST or None)
        msg = None
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect("../../home")
            else:
                msg = "Error: Username or Password is incorrect"
        return render(request, "accounts/login.html", {"form": form, "msg": msg})
class Register_User(View):
    def get(self, request):
        form = SignUpForm()
        msg = None
        success = False
        return render(request, "accounts/register.html", {"form": form, "msg": msg})
    def post(self, request):
        msg=None
        success=False
        form = SignUpForm(request.POST)
        print(form)
        if form.is_valid():
            print("valid")
        else:
            print("not valid")
        if form.is_valid():
            #form.save()
            print("valid")
            username = form.cleaned_data.get("username")
            raw_password = form.cleaned_data.get("password1")
            #user = authenticate(username=username, password=raw_password)
            print("username + password + user: ")
            print(username, + " " + raw_password)
            print(user)
            if user is not None:
                msg = 'User created.'
                success = True
        else:
            msg = 'Form is not valid'
        return render(request, "accounts/register.html", {"form": form, "msg": msg, "success": success})


    