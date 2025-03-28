import jwt
import json
from datetime import datetime, timedelta, timezone
from django.http import JsonResponse
from pymongo import MongoClient
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.csrf import csrf_exempt
from urllib.parse import urlparse, parse_qs
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from bson import ObjectId
import os , dotenv
import traceback
import re
from django.conf import settings
import boto3
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.http import HttpResponse
import uuid

# Initialize S3 Client
s3_client = boto3.client(
    "s3",
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    region_name=settings.AWS_S3_REGION_NAME
)

RESEND_API_KEY = "re_MtbY6VN7_2iBhBL2z76kyhDEsvqWZ53Jx"

# Gmail SMTP Authentication
GMAIL_EMAIL = "snsinnovationhub@gmail.com"
GMAIL_APP_PASSWORD = "cmmy zvdt bdsd zgoc"

# JWT Configuration
JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"

# MongoDB connection
client = MongoClient("mongodb+srv://ihub:ihub@harlee.6sokd.mongodb.net/")
db = client["GENAI"]
user_collection = db["users"]
admin_collection = db["admin"]
superadmin_collection = db["superadmin"]
products_collection = db["products"]
products_collection1 = db["products1"]
appointments_collection=db["appointments"]
contact_us_collection = db["contact_us"]
newsletters_collection = db["newsletters"]

collections = {
    "user": user_collection, 
    "admin": admin_collection,
    "superadmin": superadmin_collection
}

# Generate JWT Token
def generate_tokens(user_id, name, role):
    access_payload = {
        "id": str(user_id),
        "name": name,
        "role": role,  # Store role in JWT
        "exp": (datetime.now() + timedelta(hours=10)).timestamp(),
        "iat": datetime.now().timestamp(),
    }
    token = jwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"jwt": token}

#================================================================ADMIN=====================================================================

@csrf_exempt
def admin_signup(request):
    """
    Registers a new admin user.

    Expects JSON payload with keys:
      - first_name
      - last_name
      - email
      - phone_number
      - password
      - confirm_password

    Returns a JSON response indicating success or an error.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body or "{}")
        first_name = data.get("first_name", "").strip()
        last_name = data.get("last_name", "").strip()
        email = data.get("email", "").strip()
        phone = data.get("phone_number", "").strip()
        password = data.get("password", "")
        confirm_password = data.get("confirm_password", "")

        # Input validation and email format check
        if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return JsonResponse({"error": "Valid email is required"}, status=400)
        if password != confirm_password:
            return JsonResponse({"error": "Passwords do not match"}, status=400)
        if admin_collection.find_one({"email": email}):
            return JsonResponse({"error": "Admin with this email already exists"}, status=400)

        hashed_password = make_password(password)
        admin_data = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "phone_number": phone,
            "password": hashed_password,
            "role": "admin",
            "status": "Active",
            "created_at": datetime.now(),
            "last_login": None,
        }

        admin_collection.insert_one(admin_data)
        return JsonResponse({"message": "Admin registered successfully"}, status=201)

    except Exception:
        # Log the exception internally for debugging purposes
        return JsonResponse({"error": "An unexpected error occurred. Please try again."}, status=500)

@csrf_exempt
def admin_login(request):
    """
    Authenticates an admin user.

    Expects JSON payload with 'email' and 'password'.
    Returns a JWT token on successful authentication.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body or "{}")
        email = data.get("email", "").strip()
        password = data.get("password", "")

        if not email or not password:
            return JsonResponse({"error": "Email and password are required"}, status=400)

        admin = admin_collection.find_one({"email": email})
        if not admin:
            return JsonResponse({"error": "Email not found"}, status=404)

        if admin.get("status") == "Inactive":
            return JsonResponse({"error": "Account is inactive. Contact superadmin."}, status=403)

        if check_password(password, admin["password"]):
            admin_collection.update_one({"email": email}, {"$set": {"last_login": datetime.now()}})
            tokens = generate_tokens(admin["_id"], admin["first_name"], "admin")
            return JsonResponse({"message": "Login successful", "token": tokens}, status=200)
        else:
            return JsonResponse({"error": "Invalid password"}, status=401)

    except Exception:
        # Log exception details internally
        return JsonResponse({"error": "An unexpected error occurred."}, status=500)

@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def google_admin_login(request):
    try:
        data = json.loads(request.body)
        email = data.get("email")

        if not email:
            return JsonResponse({"error": "Email is required"}, status=400)

        admin = admin_collection.find_one({"email": email})

        if not admin:
            return JsonResponse({"error": "No account found! Please contact your admin."}, status=404)

        token = generate_tokens(admin["_id"], admin.get("first_name", ""), "admin")
        return JsonResponse({"message": "Login successful", "token": token}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

#================================================================SUPER ADMIN=====================================================================

@csrf_exempt
def superadmin_signup(request):
    """
    Registers a new superadmin user.

    Expects JSON payload with keys:
      - first_name
      - last_name
      - email
      - phone_number
      - password
      - confirm_password

    Returns a JSON response indicating success or an error.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body or "{}")
        first_name = data.get("first_name", "").strip()
        last_name = data.get("last_name", "").strip()
        email = data.get("email", "").strip()
        phone = data.get("phone_number", "").strip()
        password = data.get("password", "")
        confirm_password = data.get("confirm_password", "")

        # Input validation and email format check
        if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return JsonResponse({"error": "Valid email is required"}, status=400)
        if password != confirm_password:
            return JsonResponse({"error": "Passwords do not match"}, status=400)
        if superadmin_collection.find_one({"email": email}):
            return JsonResponse({"error": "Superadmin with this email already exists"}, status=400)

        hashed_password = make_password(password)
        superadmin_data = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "phone_number": phone,
            "password": hashed_password,
            "role": "superadmin",
            "created_at": datetime.now(),
            "last_login": None,
        }

        superadmin_collection.insert_one(superadmin_data)
        return JsonResponse({"message": "Superadmin registered successfully"}, status=201)

    except Exception:
        # Log the exception internally for debugging purposes
        return JsonResponse({"error": "An unexpected error occurred. Please try again."}, status=500)

@csrf_exempt
def superadmin_login(request):
    """
    Authenticates a superadmin user.

    Expects JSON payload with 'email' and 'password'.
    Returns a JWT token on successful authentication.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body or "{}")
        email = data.get("email", "").strip()
        password = data.get("password", "")

        if not email or not password:
            return JsonResponse({"error": "Email and password are required"}, status=400)

        superadmin = superadmin_collection.find_one({"email": email})
        if not superadmin:
            return JsonResponse({"error": "Email not found"}, status=404)

        if check_password(password, superadmin["password"]):
            superadmin_collection.update_one({"email": email}, {"$set": {"last_login": datetime.now()}})
            tokens = generate_tokens(superadmin["_id"], superadmin["first_name"], "superadmin")
            return JsonResponse({"message": "Login successful", "token": tokens}, status=200)
        else:
            return JsonResponse({"error": "Invalid password"}, status=401)

    except Exception:
        # Log exception details internally
        return JsonResponse({"error": "An unexpected error occurred."}, status=500)
    
@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def google_superadmin_login(request):
    try:
        data = json.loads(request.body)
        email = data.get("email")

        if not email:
            return JsonResponse({"error": "Email is required"}, status=400)

        superadmin = superadmin_collection.find_one({"email": email})

        if not superadmin:
            return JsonResponse({"error": "You're not a valid super admin."}, status=403)

        full_name = f"{superadmin.get('first_name', '')} {superadmin.get('last_name', '')}".strip()
        token = generate_tokens(superadmin["_id"], full_name, "superadmin")

        return JsonResponse({"message": "Login successful", "token": token}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
@api_view(["GET"])
def get_admin_details(request):
    """
    Retrieves details of all admin users.

    Requires a valid authorization token with superadmin role.
    Returns a JSON response with admin details.
    """
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token:
        return Response({"error": "Authorization token required"}, status=401)

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_role = decoded_token.get("role")
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return Response({"error": "Invalid token"}, status=401)

    if user_role != "superadmin":
        return Response({"error": "Unauthorized access"}, status=403)

    try:
        admins = list(admin_collection.find(
            {},
            {"_id": 1, "first_name": 1, "last_name": 1, "email": 1, "phone_number": 1, "created_at": 1, "status": 1, "profileimage": 1}
        ))

        for admin in admins:
            admin["_id"] = str(admin["_id"])

        return Response({"message": "Admin details retrieved successfully.", "admins": admins}, status=200)

    except Exception:
        # Log the exception internally for debugging purposes
        return Response({"error": "An unexpected error occurred. Please try again."}, status=500)

@csrf_exempt
@api_view(["GET"])
def get_profile(request, user_id):
    """
    Retrieves the profile for the specified user.

    Authorization token must be provided in the header.
    Enforces role-based access control.
    """
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token:
        return JsonResponse({"error": "Authorization token required"}, status=401)

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        logged_in_user_id = decoded_token.get("id")
        logged_in_role = decoded_token.get("role")
    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "Invalid token"}, status=401)

    # Fetch the target user from appropriate collection
    target_user, target_role = None, None
    for role, collection in collections.items():
        user = collection.find_one({"_id": ObjectId(user_id)}, {"password": 0})
        if user:
            target_user = user
            target_role = role
            break

    if not target_user:
        return JsonResponse({"error": "User not found"}, status=404)

    # Role-based access control checks
    if logged_in_role == "user" and logged_in_user_id != user_id:
        return JsonResponse({"error": "Unauthorized access"}, status=403)
    if logged_in_role == "admin":
        if target_role not in ["user", "admin"] or (target_role == "admin" and logged_in_user_id != user_id):
            return JsonResponse({"error": "Unauthorized access"}, status=403)
        admin_products = list(products_collection.find({"user_id": str(user_id)}))
        for product in admin_products:
            product["_id"] = str(product["_id"])
            product["user_id"] = str(product["user_id"])
        target_user["admin_products"] = admin_products if admin_products else "No products created"
    elif logged_in_role == "superadmin":
        if target_role == "admin":
            admin_products = list(products_collection.find({"user_id": str(user_id)}))
            for product in admin_products:
                product["_id"] = str(product["_id"])
                product["user_id"] = str(product["user_id"])
            target_user["admin_products"] = admin_products if admin_products else "No products created"
        if logged_in_user_id == user_id:
            superadmin_products = list(products_collection.find({"user_id": str(user_id)}))
            for product in superadmin_products:
                product["_id"] = str(product["_id"])
                product["user_id"] = str(product["user_id"])
            target_user["superadmin_products"] = superadmin_products if superadmin_products else "No products created"
    elif logged_in_role not in ["user", "admin", "superadmin"]:
        return JsonResponse({"error": "Invalid role"}, status=403)

    target_user["profileimage"] = target_user.get("profileimage", None)
    target_user["_id"] = str(target_user["_id"])
    return JsonResponse({"message": "Profile retrieved successfully.", "profile": target_user}, status=200)

@csrf_exempt
@api_view(["PUT"])
def edit_profile(request, user_id):
    """
    Updates the profile information of a user.

    Expects multipart/form-data with keys:
      - first_name, last_name, phone_number
      - Optional: profile_image, remove_image
    Authorization token must be provided in headers.
    Role-based updates: users can update their own profile; admins and superadmins have extended permissions.
    """
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token:
        return JsonResponse({"error": "Authorization token required"}, status=401)

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        logged_in_user_id = decoded_token.get("id")
        logged_in_role = decoded_token.get("role")
    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "Invalid token"}, status=401)

    # Locate target user and corresponding collection
    target_user, target_role, target_collection = None, None, None
    for role, collection in collections.items():
        user = collection.find_one({"_id": ObjectId(user_id)})
        if user:
            target_user = user
            target_role = role
            target_collection = collection
            break
    if not target_user:
        return JsonResponse({"error": "User not found"}, status=404)

    data = request.POST
    updated_fields = {}

    # Role-based field updates
    if logged_in_role == "user":
        if logged_in_user_id != user_id:
            return JsonResponse({"error": "Unauthorized access"}, status=403)
        updated_fields["first_name"] = data.get("first_name", target_user.get("first_name"))
        updated_fields["last_name"] = data.get("last_name", target_user.get("last_name"))
        updated_fields["phone_number"] = data.get("phone_number", target_user.get("phone_number"))
    elif logged_in_role == "admin":
        if logged_in_user_id != user_id and target_role != "user":
            return JsonResponse({"error": "Unauthorized access"}, status=403)
        updated_fields["first_name"] = data.get("first_name", target_user.get("first_name"))
        updated_fields["last_name"] = data.get("last_name", target_user.get("last_name"))
        updated_fields["phone_number"] = data.get("phone_number", target_user.get("phone_number"))
    elif logged_in_role == "superadmin":
        updated_fields["first_name"] = data.get("first_name", target_user.get("first_name"))
        updated_fields["last_name"] = data.get("last_name", target_user.get("last_name"))
        updated_fields["phone_number"] = data.get("phone_number", target_user.get("phone_number"))
        if "status" in data:
            updated_fields["status"] = data["status"]
    else:
        return JsonResponse({"error": "Invalid role"}, status=403)

    # Handle profile image upload or removal
    profile_image = request.FILES.get("profile_image")
    remove_image = data.get("remove_image", "false").lower()
    if profile_image:
        s3_key = f"Profile_Images/{user_id}.png"
        s3_client.upload_fileobj(profile_image, settings.AWS_STORAGE_BUCKET_NAME, s3_key)
        profile_image_url = f"{settings.AWS_S3_CUSTOM_DOMAIN}/{s3_key}"
        updated_fields["profileimage"] = profile_image_url
    elif remove_image == "true":
        updated_fields["profileimage"] = None
        try:
            s3_key = f"Profile_Images/{user_id}.png"
            s3_client.delete_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=s3_key)
        except Exception:
            # Log the error internally without exposing details
            pass

    target_collection.update_one({"_id": ObjectId(user_id)}, {"$set": updated_fields})
    return JsonResponse({"message": "Profile updated successfully."}, status=200)

@csrf_exempt
@api_view(["GET"])
def get_subscribers(request):
    """
    Retrieves the list of subscribed user emails.

    Requires a valid authorization token with superadmin role.
    Returns a JSON response with subscriber emails.
    """
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token:
        return Response({"error": "Authorization token required"}, status=401)

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_role = decoded_token.get("role")
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return Response({"error": "Invalid token"}, status=401)

    if user_role != "superadmin":
        return Response({"error": "Unauthorized access"}, status=403)

    try:
        subscribed_users = list(user_collection.find({"is_subscribed": True}, {"email": 1, "_id": 0}))

        if not subscribed_users:
            return Response({"error": "No subscribed users found"}, status=404)

        subscriber_emails = [user["email"] for user in subscribed_users]
        return Response({"emails": subscriber_emails}, status=200)

    except Exception:
        # Log the exception internally for debugging purposes
        return Response({"error": "An unexpected error occurred. Please try again."}, status=500)
    
@csrf_exempt
@api_view(["POST"])
def send_newsletter(request):
    """
    Sends a newsletter email to all subscribed users.

    Requires a valid authorization token (superadmin only).
    Expects a JSON payload with 'subject' and 'message'.
    """
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token:
        return Response({"error": "Authorization token required"}, status=401)

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_role = decoded_token.get("role")
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return Response({"error": "Invalid token"}, status=401)

    if user_role != "superadmin":
        return Response({"error": "Unauthorized access"}, status=403)

    data = request.data
    subject = data.get("subject", "").strip()
    message = data.get("message", "").strip()
    banner_url = "https://harlee-product-media.s3.eu-north-1.amazonaws.com/Banner.jpeg"
    logo_url = "https://harlee-product-media.s3.eu-north-1.amazonaws.com/logo.png"

    if not subject or not message:
        return Response({"error": "Subject and message are required"}, status=400)

    subscribed_users = list(user_collection.find({"is_subscribed": True}, {"email": 1}))
    if not subscribed_users:
        return Response({"error": "No subscribed users found"}, status=404)

    recipient_emails = [user["email"] for user in subscribed_users]

    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(GMAIL_EMAIL, GMAIL_APP_PASSWORD)

        html_template = f"""
        <html>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; text-align: center;">
          <div style="padding: 20px 0;">
            <img src="{logo_url}" width="150" style="display: block; margin: 0 auto;" />
          </div>
          <div style="width: 100%; display: flex; justify-content: center; align-items: center; padding: 10px 0;">
            <img src="{banner_url}" width="90%" style="border-radius: 10px; max-width: 600px;" />
          </div>
          <h2 style="color: #333; font-size: 22px; margin-top: 20px;">{subject}</h2>
          <p style="font-size: 16px; line-height: 1.6; color: #444; max-width: 600px; margin: 0 auto;">
            {message}
          </p>
          <hr style="margin: 30px auto; width: 80%; border: 0; border-top: 1px solid #ccc;">
          <footer style="font-size: 14px; color: #888; text-align: center; padding-bottom: 20px;">
            <p>&copy; 2025 Your Company</p>
          </footer>
        </body>
        </html>
        """

        for recipient in recipient_emails:
            msg = MIMEMultipart()
            msg["From"] = GMAIL_EMAIL
            msg["To"] = recipient
            msg["Subject"] = subject
            msg.attach(MIMEText(html_template, "html"))
            server.sendmail(GMAIL_EMAIL, recipient, msg.as_string())

        server.quit()

        newsletter_entry = {
            "subject": subject,
            "message": message,
            "banner_url": banner_url,
            "logo_url": logo_url,
            "sent_at": datetime.now(),
        }
        newsletters_collection.insert_one(newsletter_entry)

        return Response({"message": "Newsletter sent and stored successfully!"}, status=200)

    except Exception:
        # Log the exception details internally
        return Response({"error": "An unexpected error occurred."}, status=500)


    
#===================================================P  R   O   D   U   C   T   S=====================================================================

import traceback
import uuid
from datetime import datetime, timezone

@csrf_exempt
def upload_to_s3(file, filename):
    """
    Uploads a file to an S3 bucket.

    Args:
        file (File): The file object to upload.
        filename (str): The desired filename for the uploaded file.

    Returns:
        str: The URL of the uploaded file, or None if the upload fails.
    """
    try:
        bucket_name = settings.AWS_STORAGE_BUCKET_NAME
        safe_filename = filename.replace(" ", "_")
        s3_client.upload_fileobj(file, bucket_name, safe_filename)
        file_url = f"{settings.AWS_S3_CUSTOM_DOMAIN}/{safe_filename}"
        print(f"✅ Uploaded {safe_filename} to S3: {file_url}")
        return file_url
    except Exception as e:
        print(f"❌ S3 Upload Error: {str(e)}")
        return None

@csrf_exempt
def delete_from_s3(file_url):
    """
    Deletes a file from an S3 bucket.

    Args:
        file_url (str): The URL of the file to delete.
    """
    try:
        bucket_name = settings.AWS_STORAGE_BUCKET_NAME
        file_key = file_url.split(f"{settings.AWS_S3_CUSTOM_DOMAIN}/")[-1]
        s3_client.delete_object(Bucket=bucket_name, Key=file_key)
        print(f"✅ Deleted {file_key} from S3")
    except Exception as e:
        print(f"❌ S3 Delete Error: {str(e)}")

@csrf_exempt
def post_product(request):
    """
    Creates a new product with the provided data and files.

    Expects multipart/form-data with keys:
      - data (JSON string): Product details.
      - demo_video (File): Demo video file.
      - thumbnail (File): Thumbnail image file.
      - screenshot_* (File): Screenshot files.

    Returns a JSON response indicating success or an error.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method."}, status=405)

    try:
        data = json.loads(request.POST.get("data", "{}"))
        demo_video = request.FILES.get("demo_video")
        thumbnail = request.FILES.get("thumbnail")
        product_name = data.get("product_name", "Unknown_Product")

        existing_product = products_collection.find_one({"product_data.product_name": product_name})
        if existing_product:
            return JsonResponse({"error": "Product name already exists. Choose a different name."}, status=400)

        video_url = upload_to_s3(demo_video, f"{product_name}_demo_video.mp4") if demo_video else None
        thumbnail_url = upload_to_s3(thumbnail, f"{product_name}_thumbnail.png") if thumbnail else None

        screenshots = []
        for key, file in request.FILES.items():
            if key.startswith("screenshot_"):
                file_url = upload_to_s3(file, f"{product_name}_{key}.png")
                if file_url:
                    screenshots.append(file_url)

        user_journey = []
        for i in range(1, 7):
            journey_name = data.get(f"user_journey_{i}", "").strip()
            journey_desc = data.get(f"user_journey_description_{i}", "").strip()
            if journey_name and journey_desc:
                user_journey.append({"journey_name": journey_name, "journey_description": journey_desc})

        product_features = []
        for i in range(1, 9):
            feature_name = data.get(f"product_feature_{i}", "").strip()
            feature_desc = data.get(f"product_feature_description_{i}", "").strip()
            if feature_name and feature_desc:
                product_features.append({"feature_name": feature_name, "feature_description": feature_desc})

        is_publish = None if data.get("role") == "admin" else True
        created_by = "admin_id" if data.get("role") == "admin" else "superadmin_id"

        product_data = {
            "product_name": product_name,
            "product_description": data.get("product_description", ""),
            "category": data.get("category", ""),
            "demo_video": video_url,
            "screenshots": screenshots,
            "thumbnail": thumbnail_url,
        }

        product_entry = {
            "user_id": data.get("userId"),
            "product_data": product_data,
            "user_journey": user_journey,
            "product_features": product_features,
            "created_by": created_by,
            "is_publish": is_publish,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }

        products_collection.insert_one(product_entry)
        return JsonResponse({"message": "Product created successfully."}, status=200)

    except Exception as e:
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def edit_product(request, product_id):
    """
    Edits an existing product with the provided data and files.

    Expects multipart/form-data with keys:
      - data (JSON string): Product details.
      - demo_video (File): Demo video file.
      - thumbnail (File): Thumbnail image file.
      - screenshot_* (File): Screenshot files.

    Returns a JSON response indicating success or an error.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method."}, status=405)

    try:
        data = json.loads(request.POST.get("data", "{}"))
        demo_video = request.FILES.get("demo_video")
        thumbnail = request.FILES.get("thumbnail")
        product_name = data.get("product_name", "Unknown_Product")
        edited_by = data.get("edited_by")
        edited_role = data.get("edited_role")

        product = products_collection.find_one({"_id": ObjectId(product_id)})
        if not product:
            return JsonResponse({"error": "Product not found"}, status=404)

        existing_product = products_collection.find_one(
            {"product_data.product_name": product_name, "_id": {"$ne": ObjectId(product_id)}}
        )
        if existing_product:
            return JsonResponse({"error": "Product name already exists. Choose a different name."}, status=400)

        video_url = product["product_data"].get("demo_video")
        thumbnail_url = product["product_data"].get("thumbnail")

        if demo_video:
            video_url = upload_to_s3(demo_video, f"{product_name}_demo_video.mp4")

        if thumbnail:
            thumbnail_url = upload_to_s3(thumbnail, f"{product_name}_thumbnail.png")

        screenshots = product["product_data"].get("screenshots", [])

        if "deleted_screenshots" in data and data["deleted_screenshots"]:
            for url in data["deleted_screenshots"]:
                if url in screenshots:
                    screenshots.remove(url)
                    delete_from_s3(url)

        for key, file in request.FILES.items():
            if key.startswith("screenshot_"):
                unique_code = uuid.uuid4()
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                file_name = f"{product_name}_{timestamp}_{unique_code}.png"
                file_url = upload_to_s3(file, file_name)
                if file_url:
                    screenshots.append(file_url)

        user_journey = data.get("user_journey", product.get("user_journey", []))
        product_features = data.get("product_features", product.get("product_features", []))

        product_data = {
            "product_name": product_name,
            "product_description": data.get("product_description", product["product_data"].get("product_description", "")),
            "category": data.get("category", product["product_data"].get("category", "")),
            "demo_video": video_url,
            "screenshots": screenshots,
            "thumbnail": thumbnail_url,
        }

        is_publish = None if edited_role == "admin" else product.get("is_publish", True)

        product_entry = {
            "user_id": data.get("userId", product["user_id"]),
            "product_data": product_data,
            "user_journey": user_journey,
            "product_features": product_features,
            "created_by": product["created_by"],
            "edited_by": edited_by,
            "edited_role": edited_role,
            "is_publish": is_publish,
            "created_at": product["created_at"],
            "edited_at": datetime.now(timezone.utc),
        }

        products_collection.update_one({"_id": ObjectId(product_id)}, {"$set": product_entry})
        return JsonResponse({"message": "Product updated successfully."}, status=200)

    except Exception as e:
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def get_products(request):
    """Retrieve all product details including file URLs and _id from MongoDB where is_publish is True."""
    if request.method == "GET":
        try:
            # Fetch products from MongoDB where is_publish is True and include `_id`
            products = list(products_collection.find(
                {"is_publish": True},
                {"_id": 1, "user_id": 1, "product_data": 1, "user_journey": 1, "product_features": 1, "created_by": 1, "is_publish": 1, "created_at": 1, "updated_at": 1}
            ))

            # Convert `_id` from ObjectId to string for frontend compatibility
            for product in products:
                product["_id"] = str(product["_id"])

            return JsonResponse({"message": "Products retrieved successfully.", "products": products}, status=200)
        except Exception as e:
            traceback.print_exc()
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method."}, status=405)

def delete_from_s3(file_url):
    """
    Delete a file from the S3 bucket given its URL.
    Assumes file_url is in the format: {settings.AWS_S3_CUSTOM_DOMAIN}/{safe_filename}
    """
    try:
        # Extract the safe filename from the URL
        safe_filename = file_url.split("/")[-1]
        bucket_name = settings.AWS_STORAGE_BUCKET_NAME
        s3_client.delete_object(Bucket=bucket_name, Key=safe_filename)

        return True
    except Exception as e:
        return False

@csrf_exempt
def delete_product(request, product_id):
    """
    Deletes a product and its associated media from the database and S3.

    Args:
        request (HttpRequest): The request object.
        product_id (str): The ID of the product to delete.

    Returns:
        JsonResponse: A JSON response indicating success or an error.
    """
    if request.method != "DELETE":
        return JsonResponse({"error": "Invalid request method."}, status=405)

    try:
        product = products_collection.find_one({"_id": ObjectId(product_id)})
        if not product:
            return JsonResponse({"error": "Product not found"}, status=404)

        product_data = product.get("product_data", {})

        demo_video_url = product_data.get("demo_video")
        if demo_video_url:
            delete_from_s3(demo_video_url)

        thumbnail_url = product_data.get("thumbnail")
        if thumbnail_url:
            delete_from_s3(thumbnail_url)

        screenshots = product_data.get("screenshots", [])
        for screenshot_url in screenshots:
            delete_from_s3(screenshot_url)

        products_collection.delete_one({"_id": ObjectId(product_id)})
        return JsonResponse({"message": "Product and associated media deleted successfully"}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@api_view(["GET"])
@permission_classes([AllowAny])
def get_all_products(request):
    """
    Retrieves all published products.

    Returns:
        Response: A JSON response containing the list of products.
    """
    try:
        products = list(products_collection.find(
            {"is_publish": True},
            {"_id": 1, "user_id": 1, "product_data": 1, "is_publish": 1, "created_at": 1, "starred": 1}
        ))

        for product in products:
            product["_id"] = str(product["_id"])

        return Response({"products": products}, status=200)

    except Exception as e:
        return Response({"error": str(e)}, status=500)
    
@csrf_exempt
@api_view(["POST"])
def review_product(request, product_id):
    """
    Reviews a product by approving or rejecting it.

    Requires a valid authorization token (superadmin only).
    Expects a JSON payload with 'action' and optional 'reason'.
    """
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token:
        return Response({"error": "Authorization token required"}, status=401)

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_role = decoded_token.get("role")
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return Response({"error": "Invalid token"}, status=401)

    if user_role != "superadmin":
        return Response({"error": "Unauthorized"}, status=403)

    data = json.loads(request.body)
    action = data.get("action")
    reason = data.get("reason", None)

    if action not in ["approve", "reject"]:
        return Response({"error": "Invalid action"}, status=400)

    product = products_collection.find_one({"_id": ObjectId(product_id)})
    if not product:
        return Response({"error": "Product not found"}, status=404)

    if action == "approve":
        products_collection.update_one(
            {"_id": ObjectId(product_id)},
            {"$set": {"is_publish": True, "updated_at": datetime.now(), "rejection_reason": None}}
        )
        return Response({"message": "Product approved and published successfully"}, status=200)

    elif action == "reject":
        update_data = {
            "is_publish": False,
            "updated_at": datetime.now(),
            "rejection_reason": reason
        }
        products_collection.update_one(
            {"_id": ObjectId(product_id)},
            {"$set": update_data}
        )
        return Response({"message": "Product rejected successfully", "reason": reason}, status=200)

@csrf_exempt
@api_view(["GET"])
def get_admin_products(request):
    """
    Retrieves products based on the logged-in user's role.

    Requires a valid authorization token.
    Admins can fetch their own products, while superadmins can fetch all products.
    """
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token:
        return Response({"error": "Authorization token required"}, status=401)

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        logged_in_user_id = decoded_token.get("id")
        logged_in_role = decoded_token.get("role")
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return Response({"error": "Invalid token"}, status=401)

    if logged_in_role not in ["admin", "superadmin"]:
        return Response({"error": "Unauthorized"}, status=403)

    query_filter = {}
    if logged_in_role == "admin":
        query_filter = {"user_id": logged_in_user_id}

    products = list(products_collection.find(query_filter, {"password": 0}))
    for product in products:
        product["_id"] = str(product["_id"])

    if not products:
        return Response({"message": "No products found"}, status=200)

    return Response({"products": products}, status=200)

@csrf_exempt
@api_view(["GET"])
def get_superadmin_products(request):
    """
    Retrieves products created by the logged-in superadmin.

    Requires a valid authorization token (superadmin only).
    """
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token:
        return Response({"error": "Authorization token required"}, status=401)

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        logged_in_user_id = decoded_token.get("id")
        logged_in_role = decoded_token.get("role")
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return Response({"error": "Invalid token"}, status=401)

    if logged_in_role != "superadmin":
        return Response({"error": "Unauthorized"}, status=403)

    query_filter = {"user_id": logged_in_user_id}
    products = list(products_collection.find(query_filter, {"password": 0}))

    for product in products:
        product["_id"] = str(product["_id"])

    if not products:
        return Response({"message": "No products found"}, status=200)

    return Response({"products": products}, status=200)

@csrf_exempt
def toggle_bookmark(request, product_id):
    """
    Toggles the bookmark status of a product.

    Expects a JSON payload with 'action' (either 'bookmark' or 'unbookmark').
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method."}, status=405)

    try:
        data = json.loads(request.body)
        action = data.get("action")

        if action not in ["bookmark", "unbookmark"]:
            return JsonResponse({"error": "Invalid action."}, status=400)

        product = products_collection.find_one({"_id": ObjectId(product_id)})
        if not product:
            return JsonResponse({"error": "Product not found."}, status=404)

        new_value = True if action == "bookmark" else False
        products_collection.update_one(
            {"_id": ObjectId(product_id)},
            {"$set": {"starred": new_value}}
        )

        return JsonResponse({"message": f"Product {'bookmarked' if new_value else 'unbookmarked'} successfully."}, status=200)

    except Exception as e:
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def premium_product(request, product_id):
    """
    Toggles the premium status of a product.

    Expects a JSON payload with 'action' (either 'showcase' or 'hide').
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method."}, status=405)

    try:
        data = json.loads(request.body)
        action = data.get("action")

        if action not in ["showcase", "hide"]:
            return JsonResponse({"error": "Invalid action."}, status=400)

        product = products_collection.find_one({"_id": ObjectId(product_id)})
        if not product:
            return JsonResponse({"error": "Product not found."}, status=404)

        new_value = True if action == "showcase" else False
        products_collection.update_one(
            {"_id": ObjectId(product_id)},
            {"$set": {"premium": new_value}}
        )

        return JsonResponse({"message": f"Product {'showcased' if new_value else 'hidden'} successfully."}, status=200)

    except Exception as e:
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def get_products_by_category(request):
    """
    Retrieves products by category with pagination.

    Expects query parameters 'category' and 'page'.
    """
    try:
        url = request.get_full_path()
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        category = query_params.get('category', [None])[0]
        page = int(query_params.get('page', [1])[0])
        limit = 8  # Number of items per page

        if not category:
            return JsonResponse({"error": "Category parameter is missing."}, status=400)

        offset = (page - 1) * limit

        products = list(products_collection.find({
            "product_data.category": category,
            "is_publish": True
        }).skip(offset).limit(limit))

        total_products = products_collection.count_documents({
            "product_data.category": category,
            "is_publish": True
        })
        total_pages = (total_products + limit - 1) // limit  # Ceiling division

        for product in products:
            product["_id"] = str(product["_id"])

        return JsonResponse({
            "products": products,
            "total_pages": total_pages,
            "current_page": page
        }, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

#===========================================================  INBOX  ===========================================================================

@csrf_exempt
@api_view(["GET"])
def get_all_contact_us(request):
    """
    Retrieves all contact us messages.

    Requires a valid authorization token (superadmin only).
    """
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token:
        return Response({"error": "Authorization token required"}, status=401)

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_role = decoded_token.get("role")
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return Response({"error": "Invalid token"}, status=401)

    if user_role != "superadmin":
        return Response({"error": "Unauthorized access"}, status=403)

    contact_messages = list(contact_us_collection.find({}, {"_id": 1, "first_name": 1, "last_name": 1, "email": 1, "phone_number": 1, "message": 1, "timestamp": 1}))

    for message in contact_messages:
        message["_id"] = str(message["_id"])

    return Response({"message": "Contact Us data retrieved successfully.", "data": contact_messages}, status=200)

@csrf_exempt
@api_view(["DELETE"])
def delete_contact_message(request, message_id):
    """
    Deletes a contact us message by its ID.

    Requires a valid authorization token (superadmin only).
    """
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token:
        return Response({"error": "Authorization token required"}, status=401)

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_role = decoded_token.get("role")
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return Response({"error": "Invalid token"}, status=401)

    if user_role != "superadmin":
        return Response({"error": "Unauthorized access"}, status=403)

    message = contact_us_collection.find_one({"_id": ObjectId(message_id)})
    if not message:
        return Response({"error": "Message not found"}, status=404)

    contact_us_collection.delete_one({"_id": ObjectId(message_id)})
    return Response({"message": "Message deleted successfully"}, status=200)

@csrf_exempt
@api_view(["GET"])
def get_appointments(request):
    """
    Retrieves appointments for products created by the logged-in user.

    Requires a valid authorization token (admin or superadmin only).
    """
    try:
        token = request.headers.get("Authorization", "").split("Bearer ")[-1]
        if not token:
            return Response({"error": "Authorization token required"}, status=401)

        try:
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            logged_in_user_id = decoded_token.get("id")
            logged_in_role = decoded_token.get("role")
        except jwt.ExpiredSignatureError:
            return Response({"error": "Token has expired"}, status=401)
        except jwt.InvalidTokenError:
            return Response({"error": "Invalid token"}, status=401)

        if logged_in_role not in ["admin", "superadmin"]:
            return Response({"error": "Unauthorized access"}, status=403)

        published_products = products_collection.find(
            {"user_id": logged_in_user_id, "is_publish": True},
            {"_id": 1, "product_data.product_name": 1}
        )
        product_dict = {str(product["_id"]): product["product_data"]["product_name"] for product in published_products}

        if not product_dict:
            return Response({"message": "No published products found for this user."}, status=200)

        admin_appointments = list(appointments_collection.find({"product_id": {"$in": list(product_dict.keys())}}))

        for appointment in admin_appointments:
            appointment["_id"] = str(appointment["_id"])
            appointment["product_id"] = str(appointment["product_id"])
            appointment["product_name"] = product_dict.get(appointment["product_id"])

        return Response({"appointments": admin_appointments}, status=200)

    except Exception as e:
        return Response({"error": str(e)}, status=500)

@csrf_exempt
def mark_appointment_as_read(request, appointment_id):
    """
    Marks an appointment as read.

    Requires a PUT request.
    """
    if request.method != "PUT":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        result = appointments_collection.update_one(
            {"_id": ObjectId(appointment_id)},
            {"$set": {"is_read": True}}
        )
        if result.matched_count == 0:
            return JsonResponse({"error": "Appointment not found"}, status=404)
        return JsonResponse({"message": "Appointment marked as read"}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def mark_appointment_as_unread(request, appointment_id):
    """
    Marks an appointment as unread.

    Requires a PUT request.
    """
    if request.method != "PUT":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        result = appointments_collection.update_one(
            {"_id": ObjectId(appointment_id)},
            {"$set": {"is_read": False}}
        )
        if result.matched_count == 0:
            return JsonResponse({"error": "Appointment not found"}, status=404)
        return JsonResponse({"message": "Appointment marked as unread"}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def delete_appointment(request, appointment_id):
    """
    Deletes an appointment.

    Requires a DELETE request.
    """
    if request.method != "DELETE":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        result = appointments_collection.delete_one({"_id": ObjectId(appointment_id)})
        if result.deleted_count == 0:
            return JsonResponse({"error": "Appointment not found"}, status=404)
        return JsonResponse({"message": "Appointment deleted successfully"}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


#========================================================= NOTIFICATIONS ==================================================================

@csrf_exempt
@api_view(["GET"])
def get_admin_notification(request):
    """
    Retrieves notifications for products created by the logged-in admin or superadmin.

    Requires a valid authorization token (admin or superadmin only).
    """
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token:
        return Response({"error": "Authorization token required"}, status=401)

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        logged_in_user_id = decoded_token.get("id")
        logged_in_role = decoded_token.get("role")
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return Response({"error": "Invalid token"}, status=401)

    if logged_in_role not in ["admin", "superadmin"]:
        return Response({"error": "Unauthorized"}, status=403)

    query_filter = {}
    if logged_in_role == "admin":
        query_filter = {"user_id": logged_in_user_id}

    products = list(products_collection.find(
        query_filter,
        {
            "_id": 1,
            "product_data.product_name": 1,
            "product_data.category": 1,
            "is_publish": 1,
            "created_by": 1,
            "user_id": 1,
            "rejection_reason": 1
        }
    ))

    for product in products:
        product["_id"] = str(product["_id"])
        user_id = product["user_id"]
        created_by = product["created_by"]

        if created_by == "admin_id":
            admin = admin_collection.find_one({"_id": ObjectId(user_id)}, {"first_name": 1, "email": 1})
            if admin:
                product["created_by_name"] = admin["first_name"]
                product["created_by_email"] = admin["email"]
        elif created_by == "superadmin_id":
            superadmin = superadmin_collection.find_one({"_id": ObjectId(user_id)}, {"first_name": 1, "email": 1})
            if superadmin:
                product["created_by_name"] = superadmin["first_name"]
                product["created_by_email"] = superadmin["email"]

    if not products:
        return Response({"message": "No products found"}, status=200)

    return Response({"products": products}, status=200)

@api_view(["GET"])
@permission_classes([AllowAny])
def get_superadmin_notification(request):
    """
    Retrieves notifications for all products.

    No authorization required.
    """
    try:
        products = list(products_collection.find(
            {},
            {
                "_id": 1,
                "product_data.product_name": 1,
                "product_data.category": 1,
                "is_publish": 1,
                "created_by": 1,
                "user_id": 1,
                "rejection_reason": 1
            }
        ))

        for product in products:
            product["_id"] = str(product["_id"])
            user_id = product["user_id"]
            created_by = product["created_by"]

            if created_by == "admin_id":
                admin = admin_collection.find_one({"_id": ObjectId(user_id)}, {"first_name": 1, "email": 1})
                if admin:
                    product["created_by_name"] = admin["first_name"]
                    product["created_by_email"] = admin["email"]
            elif created_by == "superadmin_id":
                superadmin = superadmin_collection.find_one({"_id": ObjectId(user_id)}, {"first_name": 1, "email": 1})
                if superadmin:
                    product["created_by_name"] = superadmin["first_name"]
                    product["created_by_email"] = superadmin["email"]

        if not products:
            return Response({"message": "No products found"}, status=200)

        return Response({"products": products}, status=200)

    except Exception as e:
        return Response({"error": str(e)}, status=500)
    
@csrf_exempt
@api_view(["GET"])
def user_management(request):
    """
    Retrieves all published products.

    Requires a valid authorization token (superadmin only).
    """
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token:
        return Response({"error": "Authorization token required"}, status=401)

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_role = decoded_token.get("role")
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return Response({"error": "Invalid token"}, status=401)

    if user_role != "superadmin":
        return Response({"error": "Unauthorized access"}, status=403)

    try:
        products = list(products_collection.find({"is_publish": True}, {"password": 0}))

        for product in products:
            product["_id"] = str(product["_id"])
            product["user_id"] = str(product["user_id"])

        return Response({
            "message": "Published products retrieved successfully.",
            "products": products
        }, status=200)

    except Exception as e:
        return Response({"error": str(e)}, status=500)