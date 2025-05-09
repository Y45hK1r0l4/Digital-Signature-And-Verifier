import hashlib
import os
from django.core.files.storage import FileSystemStorage
from django.core.files.base import ContentFile
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.encoding import smart_str
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Get the absolute path of the current file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def home(request):
    return render(request, "signer/home.html")

# Load the private key
def load_private_key():
    key_path = os.path.join(BASE_DIR, "private_key.pem")  
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Private key not found: {key_path}")
    
    with open(key_path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

# Load the public key
def load_public_key():
    key_path = os.path.join(BASE_DIR, "public_key.pem") 
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Public key not found: {key_path}")
    
    with open(key_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

# View to sign a file
def sign_file_view(request):
    if request.method == "POST" and request.FILES.get("file"):
        uploaded_file = request.FILES["file"]
        fs = FileSystemStorage()

        file_path = fs.save(uploaded_file.name, uploaded_file)  
        file_path = fs.path(file_path)

        print(f"File saved at: {file_path}")  
        try:
            # Read file content and compute hash
            with open(file_path, "rb") as f:
                file_content = f.read()
                file_hash = hashlib.sha256(file_content).digest() 

            # Load private key
            private_key = load_private_key()

            # Sign the hash
            signature = private_key.sign(
                file_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            # Save the signature as a separate file
            signature_file_name = uploaded_file.name + ".sig"
            signature_path = fs.save(signature_file_name, ContentFile(signature))  
            signature_path = fs.path(signature_path)

            print(f"Saving signature to: {signature_path}")  

            # Serve the signature for download
            with open(signature_path, "rb") as f:
                response = HttpResponse(f.read(), content_type="application/octet-stream")
                response["Content-Disposition"] = f'attachment; filename="{smart_str(signature_file_name)}"'
                return response

        except Exception as e:
            print(f"Error signing file: {e}")  
            return HttpResponse(f"Error: {str(e)}", status=500)

    return render(request, "signer/sign.html")


# Function to verify a signature
def verify_signature(file_path, signature_path):
    print("Verifying signature...")  

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return False

    if not os.path.exists(signature_path):
        print(f"Signature file not found: {signature_path}")
        return False

    public_key = load_public_key()

    with open(file_path, "rb") as f:
        file_data = f.read()

    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()

    try:
        file_hash = hashlib.sha256(file_data).digest()  
        public_key.verify(
            signature,
            file_hash,  
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Verification successful!")
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False


# View to verify a file signature
def verify_file_view(request):
    if request.method == "POST" and request.FILES.get("file") and request.FILES.get("signature"):
        uploaded_file = request.FILES["file"]
        uploaded_signature = request.FILES["signature"]

        fs = FileSystemStorage()
        file_path = fs.save(uploaded_file.name, uploaded_file)
        signature_path = fs.save(uploaded_signature.name, uploaded_signature)

        file_path = fs.path(file_path)
        signature_path = fs.path(signature_path)

        # Compute file hash (Ensure it's the same format as signing)
        with open(file_path, "rb") as f:
            file_content = f.read()
            file_hash = hashlib.sha256(file_content).digest()  

        # Compute signature hash
        with open(signature_path, "rb") as sig_file:
            signature_content = sig_file.read()
            signature_hash = hashlib.sha256(signature_content).hexdigest()  

        # Verify the signature
        is_valid = verify_signature(file_path, signature_path)

        # Set status & message
        if is_valid:
            status = "success"
            message = "Signature is valid!"
            signed_message = "This document is verified successfully."
        else:
            status = "`````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````error"
            message = "Signature is invalid!"
            signed_message = "Verification failed. The signature does not match."

        return render(request, "signer/verify_result.html", {
            "status": status,
            "message": message,
            "file_name": uploaded_file.name,
            "file_hash": file_hash.hex(),  
            "signature_hash": signature_hash,  
            "signed_message": signed_message
        })

    return render(request, "signer/verify.html")
