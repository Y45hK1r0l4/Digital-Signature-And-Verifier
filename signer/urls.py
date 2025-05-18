from django.urls import path
from . import views

urlpatterns = [
    path("", views.home),
    path('home/', views.redirect_home, name='redirect_home'),
    path("sign/", views.sign_file_view, name="sign"),
    path("sign/verify/", views.verify_file_view, name="verify"), 
    path('custom_verify/', views.custom_file_verify, name='custom_verify'),
    path('custom_sign/', views.custom_file_sign, name='custom_sign'),
    path('generate_keys/', views.generate_keys, name='generate_keys'),
]
