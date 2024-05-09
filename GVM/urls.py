from django.urls import path
from django.contrib.auth.decorators import login_required
from .views import Target_View, Task_View, Report_View, TaskDetail_View

urlpatterns = [
    path('target/', login_required(Target_View.as_view()), name='target'),
    path('target/<str:id>', login_required(Target_View.as_view())),
    path('task/', login_required(TaskDetail_View.as_view()), name='target'),
    path('report/', login_required(Report_View.as_view()), name='target')
]
