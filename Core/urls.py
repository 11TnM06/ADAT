from django.urls import path
from django.contrib.auth.decorators import login_required
from .views import Home_View, Auto_View

urlpatterns = [
    path('', login_required(Home_View.as_view(), "Home")),
    path('auto/<str:id1>/', login_required(Auto_View.as_view(), "Auto")),
]
