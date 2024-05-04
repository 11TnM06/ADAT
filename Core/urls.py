from django.urls import path
from . import views
from django.contrib.auth.decorators import login_required

urlpatterns = [
    path('home/', login_required(views.Home_View), name='home')
]
