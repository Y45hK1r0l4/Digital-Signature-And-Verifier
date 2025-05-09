from django import forms
from .models import SignedFile

class FileUploadForm(forms.ModelForm):
    class Meta:
        model = SignedFile
        fields = ["file"]
