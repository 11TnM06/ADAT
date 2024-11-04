from django.urls import path
from django.contrib.auth.decorators import login_required
from .views import Target_View, Task_View, Report_View, ActionTask_View

urlpatterns = [
    path('target/', login_required(Target_View.as_view()), name='target'),
    path('target/<str:id>', login_required(Target_View.as_view())),
    path('task/', login_required(Task_View.as_view())),
    path('task/<str:id>', login_required(Task_View.as_view())),
    path('report/', login_required(Report_View.as_view())),
    path('report/<str:id>', login_required(Report_View.as_view())),
    path('action_task/<str:action>', login_required(ActionTask_View.as_view())),
    path('action_task/<str:action>/<str:id>', login_required(ActionTask_View.as_view()))
    
]
