from django.db import models

class SignedFile(models.Model):
    file = models.FileField(upload_to="signed_files/")
    signature = models.TextField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.file.name
