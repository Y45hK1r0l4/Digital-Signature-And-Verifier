import hashlib
import os
import logging
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.core.files.base import ContentFile
from django.utils.encoding import smart_str
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
logger = logging.getLogger(__name__)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from django.shortcuts import redirect
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import serialization




# Get the absolute path of the current file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def redirect_home(request):
    return redirect('/') 


def home(request):
    return render(request, "signature_app/home.html")


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
    

def generate_keys(request):
    """Generate RSA key pair and display to the user"""
    if request.method == 'POST':
        # Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Serialize private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        # Generate and serialize public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Store keys in session or database as needed
        request.session['private_key'] = private_pem
        request.session['public_key'] = public_pem
        
        return render(request, "signature_app/generate_keys.html", {
            "private_key": private_pem,
            "public_key": public_pem
        })
    else:
        # Handle GET request - just display the form without keys
        return render(request, "signature_app/generate_keys.html", {
            "private_key": "",
            "public_key": ""
        })


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
                os.remove(file_path)
                return response
 

        except Exception as e:
            print(f"Error signing file: {e}")  
            return HttpResponse(f"Error: {str(e)}", status=500)

    return render(request, "signature_app/sign.html")

def custom_file_sign(request):
    if request.method == 'POST':
        uploaded_file = request.FILES.get('file_to_sign')
        private_key_text = request.POST.get('private_key')
        private_key_file = request.FILES.get('private_key_file')
        hash_algo = request.POST.get('hash_algo', 'SHA256')

        if not uploaded_file:
            return HttpResponse("No file was uploaded", status=400)

        fs = FileSystemStorage()
        file_path = fs.save(uploaded_file.name, uploaded_file)
        file_path = fs.path(file_path)

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
        except Exception as e:
            os.remove(file_path)
            return HttpResponse(f"Failed to read file: {str(e)}", status=500)

        # Get private key from either text input or file
        if private_key_text and private_key_text.strip():
            key_data = private_key_text.strip().encode()
        elif private_key_file:
            private_key_path = fs.save(private_key_file.name, private_key_file)
            private_key_path = fs.path(private_key_path)
            with open(private_key_path, "rb") as f:
                key_data = f.read()
        else:
            os.remove(file_path)
            os.remove(private_key_path)
            return HttpResponse("No private key provided", status=400)

        try:
            private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
        except Exception as e:
            logger.error(f"Error loading private key: {e}")
            os.remove(file_path)
            os.remove(private_key_path)
            return HttpResponse(f"Error loading private key: {e}", status=400)

        # Choose hash algorithm
        if hash_algo == 'SHA256':
            hash_func = hashes.SHA256()
        elif hash_algo == 'SHA384':
            hash_func = hashes.SHA384()
        elif hash_algo == 'SHA512':
            hash_func = hashes.SHA512()
        else:
            os.remove(file_path)
            os.remove(private_key_path)
            return HttpResponse(f"Unsupported hash algorithm: {hash_algo}", status=400)

        try:
            # Create hash
            digest = hashes.Hash(hash_func, backend=default_backend())
            digest.update(file_data)
            file_hash = digest.finalize()

            # Sign the hash
            signature = private_key.sign(
                file_hash,
                padding.PKCS1v15(),
                Prehashed(hash_func)
            )

            # Save and return signature
            signature_file_name = uploaded_file.name + ".sig"
            signature_path = fs.save(signature_file_name, ContentFile(signature))
            signature_path = fs.path(signature_path)

            with open(signature_path, "rb") as f:
                response = HttpResponse(f.read(), content_type="application/octet-stream")
                response["Content-Disposition"] = f'attachment; filename="{smart_str(signature_file_name)}"'
                os.remove(file_path)
                return response
            

        except Exception as e:
            logger.error(f"Error during signing: {e}")
            return HttpResponse(f"Signing failed: {e}", status=500)

    return render(request, 'signature_app/custom_sign.html')


def custom_verify_signature(file_path, signature_path, public_key, hashfunc):
    print("Verifying signature...")

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return False

    if not os.path.exists(signature_path):
        print(f"Signature file not found: {signature_path}")
        return False

    with open(file_path, "rb") as f:
        file_data = f.read()

    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()

    try:
        # Verify the signature over the original file data with PKCS1v15 padding and chosen hash
        public_key.verify(
            signature,
            file_data,
            padding.PKCS1v15(),
            hashfunc
        )
        print("Verification successful!")
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False


def custom_file_verify(request):
    if request.method == 'POST':
        try:
            # Get public key input: either text or file
            public_key_text = request.POST.get('public_key_text')
            public_key_file = request.FILES.get('public_key_file')

            # Hash algorithm choice (default SHA256)
            hash_algo = request.POST.get('hash_algo', 'SHA256')

            # Get document and signature files uploaded
            document_file = request.FILES.get('document_file')
            signature_file = request.FILES.get('signature_file')

            if not document_file or not signature_file:
                return JsonResponse({'success': False, 'error': 'Document or signature file missing.'}, status=400)

            fs = FileSystemStorage()
            file_path = fs.save(document_file.name, document_file)
            signature_path = fs.save(signature_file.name, signature_file)

            file_path = fs.path(file_path)
            signature_path = fs.path(signature_path)

            # Read public key data from text or file
            if public_key_text and public_key_text.strip():
                key_data = public_key_text.strip().encode()
            elif public_key_file:
                public_key_path = fs.save(public_key_file.name, public_key_file)
                public_key_path = fs.path(public_key_path)
                with open(public_key_path, "rb") as f:
                    key_data = f.read()
                # Clean up uploaded public key file
                os.remove(public_key_path)
            else:
                os.remove(file_path)
                os.remove(signature_path)
                return HttpResponse("No public key provided", status=400)

            # Load public key
            try:
                public_key = load_pem_public_key(key_data)
            except Exception as e:
                logger.error(f"Error loading public key: {e}")
                os.remove(file_path)
                os.remove(signature_path)
                return HttpResponse(f"Error loading public key: {e}", status=400)

            # Choose hash function
            if hash_algo == 'SHA256':
                hash_func = hashes.SHA256()
            elif hash_algo == 'SHA384':
                hash_func = hashes.SHA384()
            elif hash_algo == 'SHA512':
                hash_func = hashes.SHA512()
            else:
                os.remove(file_path)
                os.remove(signature_path)
                return HttpResponse(f"Unsupported hash algorithm: {hash_algo}", status=400)

            # Verify the signature
            is_valid = custom_verify_signature(file_path, signature_path, public_key, hash_func)

            # Compute file hash and signature hash for showing to user
            with open(file_path, "rb") as f:
                file_content = f.read()
                file_hash = hashlib.sha256(file_content).digest()

            with open(signature_path, "rb") as sig_file:
                signature_content = sig_file.read()
                signature_hash = hashlib.sha256(signature_content).hexdigest()

            # Clean up uploaded files
            os.remove(file_path)
            os.remove(signature_path)

            # Prepare response status and messages
            if is_valid:
                status = "success"
                message = "Signature is valid!"
                signed_message = "This document is verified successfully."
            else:
                status = "error"
                message = "Signature is invalid!"
                signed_message = "Verification failed. The signature does not match."

            return render(request, "signature_app/verify_result.html", {
                "status": status,
                "message": message,
                "file_name": document_file.name,
                "file_hash": file_hash.hex(),
                "signature_hash": signature_hash,
                "signed_message": signed_message
            })

        except Exception as e:
            logger.error(f"Unexpected error during verification: {e}")
            return HttpResponse(f"Unexpected error: {e}", status=500)

    # If GET request, render the upload form
    return render(request, "signature_app/custom_verify.html")


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


        os.remove(file_path)
        os.remove(signature_path)

        return render(request, "signature_app/verify_result.html", {
            "status": status,
            "message": message,
            "file_name": uploaded_file.name,
            "file_hash": file_hash.hex(),  
            "signature_hash": signature_hash,  
            "signed_message": signed_message
        })

    return render(request, "signature_app/verify.html")

