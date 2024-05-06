from django.urls import path
from .views import Login_View, Register_User, Logout_View
urlpatterns = [
    path('login/', Login_View.as_view(), name='login'),
    path('register/', Register_User.as_view(), name='register'),
    path("logout/", Logout_View.as_view(), name="logout"),
]
