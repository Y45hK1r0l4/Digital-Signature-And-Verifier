from django.urls import path
from .views import sign_file_view, verify_file_view, home

urlpatterns = [
    path("", home),
    path("sign/", sign_file_view, name="sign"),
    path("sign/verify/", verify_file_view, name="verify"),  
]
