from django.urls import path
from django.contrib.auth.decorators import login_required
from .views import Target_View

urlpatterns = [
    path('target/', login_required(Target_View.as_view()), name='target')
]
