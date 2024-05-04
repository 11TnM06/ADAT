from django.urls import path
from .views import Login_View, Register_User
from django.contrib.auth.views import LogoutView
urlpatterns = [
    path('login/', Login_View.as_view(), name='login'),
    path('register/', Register_User.as_view(), name='register'),
    path("logout/", LogoutView.as_view(), name="logout"),
]
