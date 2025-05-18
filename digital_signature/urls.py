# digital_signature/urls.py

from django.contrib import admin
from django.urls import path, include  # Add 'include' here
# from signer.views import sign_file_view, verify_file_view  # No need to import these views here

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include('signer.urls')),  # Use include() to refer to signer app's URLs
     
]
