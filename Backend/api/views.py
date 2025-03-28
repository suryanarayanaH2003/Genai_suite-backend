import jwt
import random
import json
import os
import dotenv
from datetime import datetime, timedelta
from django.http import JsonResponse
from pymongo import MongoClient
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from bson import ObjectId
from django.core.mail import EmailMessage
from twilio.rest import Client
import requests

# Load environment variables from a .env file
dotenv.load_dotenv()

# ======================= CONFIGURATION =======================
# JWT Configuration
JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"

# MongoDB Configuration
mongo_url = os.getenv("MONGO_URI")
client = MongoClient(mongo_url)
db = client["GENAI"]
user_collection = db["users"]
appointments_collection = db['appointments']
products_collection = db['products']
contact_us_collection = db["contact_us"]
otp_collection = db["otp_collection"]

# ======================= UTILITY FUNCTIONS =======================
def generate_tokens(user_id, name, role):
    """Generates JWT tokens for authentication."""
    access_payload = {
        "id": str(user_id),
        "name": name,
        "role": role,  # Store role in JWT
        "exp": (datetime.now() + timedelta(hours=10)).timestamp(),
        "iat": datetime.now().timestamp(),
    }
    return {"jwt": jwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)}


def find_user_by_email(email):
    """Fetch a user from the database using email."""
    return user_collection.find_one({"email": email})


def update_user_last_login(email):
    """Update last login timestamp for a user."""
    user_collection.update_one({"email": email}, {"$set": {"last_login": datetime.now()}})


@csrf_exempt
def user_signup(request):
    """Registers a new user with validation and password hashing."""
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            first_name, last_name, email, phone, password, confirm_password = (
                data.get("first_name"), data.get("last_name"), data.get("email"),
                data.get("phone_number"), data.get("password"), data.get("confirm_password")
            )

            if password != confirm_password:
                return JsonResponse({"error": "Passwords do not match"}, status=400)
            
            if find_user_by_email(email):
                return JsonResponse({"error": "User with this email already exists"}, status=400)
            
            user_data = {
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "phone_number": phone,
                "password": make_password(password),
                "created_at": datetime.now(),
                "last_login": None,
            }
            user_collection.insert_one(user_data)
            return JsonResponse({"message": "User registered successfully"}, status=201)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
def user_login(request):
    """
    Authenticates a user.
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

        user = user_collection.find_one({"email": email})
        if not user:
            return JsonResponse({"error": "Email not found"}, status=404)

        if check_password(password, user["password"]):
            user_collection.update_one({"email": email}, {"$set": {"last_login": datetime.now()}})
            tokens = generate_tokens(user["_id"], user["first_name"], "user")
            return JsonResponse({"message": "Login successful", "token": tokens}, status=200)
        else:
            return JsonResponse({"error": "Invalid password"}, status=401)

    except Exception:
        # Log the exception details internally
        return JsonResponse({"error": "An unexpected error occurred. Please try again."}, status=500)

@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def google_login(request):
    """
    Logs in or registers user using Google email.
    """
    try:
        data = json.loads(request.body or "{}")
        email = data.get("email")
        name = data.get("name")

        if not email or not name:
            return JsonResponse({"error": "Email and name required"}, status=400)

        user = user_collection.find_one({"email": email})

        if not user:
            # Auto register
            user_data = {
                "first_name": name.split(" ")[0],
                "last_name": " ".join(name.split(" ")[1:]) if len(name.split(" ")) > 1 else "",
                "email": email,
                "phone_number": "",
                "password": "",  # No password since it's Google
                "created_at": datetime.now(),
                "last_login": datetime.now(),
                "google_login": True
            }
            result = user_collection.insert_one(user_data)
            user_id = result.inserted_id
        else:
            user_id = user["_id"]
            user_collection.update_one({"email": email}, {"$set": {"last_login": datetime.now()}})

        token = generate_tokens(user_id, name, "user")
        return JsonResponse({"message": "Login successful", "token": token}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def check_user(request):
    """
    Check if a user exists by email
    """
    try:
        data = json.loads(request.body)
        email = data.get("email", "").strip()

        if not email:
            return JsonResponse({"error": "Email required"}, status=400)

        user = user_collection.find_one({"email": email})
        if user:
            return JsonResponse({"exists": True})
        else:
            return JsonResponse({"exists": False})

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
@api_view(["POST"])
@permission_classes([AllowAny])
def forgot_password(request):
    """
    Handles the forgot password functionality by sending a reset OTP to the user's email.

    Expects a JSON payload with 'email'.
    """
    try:
        email = request.data.get('email', "").strip()
        if not email:
            return Response({"error": "Email is required"}, status=400)

        user = user_collection.find_one({"email": email})
        if not user:
            return Response({"error": "Email not found"}, status=400)

        reset_token = str(random.randint(100000, 999999))
        expiration_time = datetime.now() + timedelta(minutes=10)

        user_collection.update_one(
            {"email": email},
            {"$set": {
                "password_reset_token": reset_token,
                "password_reset_expires": expiration_time
            }}
        )

        # Send email with error handling
        subject = "Password Reset OTP - GENAI"
        message = f"Your OTP for password reset is: {reset_token}\nThis OTP is valid for 10 minutes."

        try:
            email_obj = EmailMessage(subject, message, to=[email])
            email_obj.send()
        except Exception:
            # Log the exception details internally
            return Response({"error": "Failed to send OTP email."}, status=500)

        return Response({
            "message": "OTP has been sent to your email.",
            "token": reset_token
        }, status=200)

    except Exception:
        # Log the exception details internally
        return Response({"error": "An unexpected error occurred. Please try again."}, status=500)

@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def send_email_otp(request):
    """
    Sends OTP to email and stores it in otp_collection
    """
    try:
        data = json.loads(request.body)
        email = data.get("email", "").strip()

        if not email:
            return Response({"error": "Email is required"}, status=400)

        otp = str(random.randint(100000, 999999))
        expiry = datetime.now() + timedelta(minutes=10)

        otp_collection.update_one(
            {"email": email},
            {"$set": {
                "email_otp": otp,
                "email_otp_expires": expiry
            }},
            upsert=True
        )

        subject = "GenAI-Suite | Email Verification OTP"
        message = (
            f"Dear User,\n\n"
            f"Your One-Time Password (OTP) for verifying your email address with GenAI-Suite is:\n\n"
            f"🔐 OTP: {otp}\n\n"
            f"This OTP is valid for 10 minutes.\n\n"
            f"If you did not request this, please ignore this message.\n\n"
            f"Thank you,\n"
            f"Team GenAI-Suite"
        )

        email_obj = EmailMessage(subject, message, to=[email])
        email_obj.send()

        return Response({"message": "Email OTP sent successfully"}, status=200)

    except Exception as e:
        return Response({"error": f"Failed to send email OTP: {str(e)}"}, status=500)

@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def verify_email_otp(request):
    """
    Verifies OTP for email from otp_collection
    """
    try:
        data = json.loads(request.body)
        email = data.get("email", "").strip()
        otp = data.get("otp", "").strip()

        record = otp_collection.find_one({"email": email})
        if not record:
            return Response({"error": "Email OTP not found"}, status=404)

        if record.get("email_otp") != otp:
            return Response({"error": "Invalid email OTP"}, status=400)

        if datetime.now() > record.get("email_otp_expires"):
            return Response({"error": "Email OTP expired"}, status=403)

        # Clean up verified record
        otp_collection.update_one({"email": email}, {"$unset": {"email_otp": "", "email_otp_expires": ""}})

        return Response({"message": "Email OTP verified successfully"}, status=200)

    except Exception as e:
        return Response({"error": str(e)}, status=500)

@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def send_sms_otp(request):
    """
    Sends OTP via Fast2SMS (IN) or Twilio (global), stores in otp_collection
    """
    try:
        data = json.loads(request.body)
        phone = data.get("phone_number", "").strip()
        email = data.get("email", "").strip()

        if not phone or not email:
            return Response({"error": "Phone and email required"}, status=400)

        otp = str(random.randint(100000, 999999))
        expiry = datetime.now() + timedelta(minutes=10)

        otp_collection.update_one(
            {"email": email},
            {"$set": {
                "phone_otp": otp,
                "phone_otp_expires": expiry,
                "phone": phone
            }},
            upsert=True
        )

        message_text = (
            f"GenAI-Suite Verification:\n"
            f"Your OTP is {otp}. It is valid for 10 minutes.\n"
            f"If not requested, ignore this SMS."
        )

        if phone.startswith("+91"):
            response = requests.post("https://www.fast2sms.com/dev/bulkV2", headers={
                "authorization": os.getenv("FAST2SMS_API_KEY"),
                "Content-Type": "application/x-www-form-urlencoded"
            }, data={
                "route": "q",
                "message": message_text,
                "language": "english",
                "flash": 0,
                "numbers": phone[3:]
            })

            print("Fast2SMS Response:", response.json())
            if response.status_code == 200:
                return Response({"message": "SMS OTP sent via Fast2SMS"}, status=200)
            else:
                return Response({"error": "Fast2SMS failed"}, status=500)
        else:
            client = Client(os.getenv("TWILIO_SID"), os.getenv("TWILIO_AUTH_TOKEN"))
            message = client.messages.create(
                body=message_text,
                from_=os.getenv("TWILIO_PHONE_NUMBER"),
                to=phone
            )

            print("Twilio SID:", message.sid)
            return Response({"message": "SMS OTP sent via Twilio"}, status=200)

    except Exception as e:
        return Response({"error": f"Failed to send SMS OTP: {str(e)}"}, status=500)

@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def verify_sms_otp(request):
    """
    Verifies OTP for phone from otp_collection
    """
    try:
        data = json.loads(request.body)
        email = data.get("email", "").strip()
        otp = data.get("otp", "").strip()

        record = otp_collection.find_one({"email": email})
        if not record:
            return Response({"error": "Phone OTP not found"}, status=404)

        if record.get("phone_otp") != otp:
            return Response({"error": "Invalid phone OTP"}, status=400)

        if datetime.now() > record.get("phone_otp_expires"):
            return Response({"error": "Phone OTP expired"}, status=403)

        # Clean up verified record
        otp_collection.update_one({"email": email}, {"$unset": {"phone_otp": "", "phone_otp_expires": ""}})

        return Response({"message": "Phone OTP verified successfully"}, status=200)

    except Exception as e:
        return Response({"error": str(e)}, status=500)

@csrf_exempt
@api_view(["POST"])
def verify_reset_token(request):
    """
    Verifies the password reset OTP.
    Expects JSON payload with 'email' and 'token'.
    """
    try:
        data = json.loads(request.body or "{}")
        email = data.get("email", "").strip()
        token = data.get("token", "").strip()

        if not email or not token:
            return JsonResponse({"error": "Email and token are required"}, status=400)

        user = user_collection.find_one({"email": email})
        if not user:
            return JsonResponse({"error": "User not found"}, status=404)

        stored_token = user.get("password_reset_token")
        expiration_time = user.get("password_reset_expires")

        if not stored_token or stored_token != token:
            return JsonResponse({"error": "Invalid verification code"}, status=403)

        if expiration_time and datetime.now() > expiration_time:
            return JsonResponse({"error": "Verification code expired"}, status=403)

        return JsonResponse({"message": "Verification successful"}, status=200)

    except Exception:
        # Log the exception details internally
        return JsonResponse({"error": "An unexpected error occurred. Please try again."}, status=500)
    
@csrf_exempt
def reset_password(request):
    """
    Resets the user's password after verifying the reset token.
    Ensures security by hashing the new password before storing it.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            token = data.get("token")
            new_password = data.get("new_password")

            # Fetch user details
            user = user_collection.find_one({"email": email})
            if not user:
                return JsonResponse({"error": "User not found"}, status=404)

            # Validate reset token
            if user.get("password_reset_token") != token:
                return JsonResponse({"error": "Invalid reset token"}, status=403)

            # Hash the new password before storing
            hashed_password = make_password(new_password)

            # Update password in the database
            user_collection.update_one(
                {"email": email},
                {"$set": {
                    "password": hashed_password,
                    "password_reset_token": None,  # Remove token after use
                    "password_reset_expires": None
                }}
            )

            return JsonResponse({"message": "Password reset successfully"}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)

#==================================================================PRODUCTS===================================================================

@api_view(["GET"])
@permission_classes([AllowAny])
def published_products(request):
    """
    Retrieves a list of published products.
    Returns a JSON response with the list of published products.
    """
    try:
        # Fetch only the 'is_publish' field for published products (is_publish=True)
        products = list(products_collection.find({"is_publish": True}, {"_id": 1, "user_id": 1, "product_data": 1, "user_journey": 1, "product_features": 1, "is_publish": 1, "created_at": 1}))

        # Convert `_id` to string
        for product in products:
            product["_id"] = str(product["_id"])

        if not products:
            return Response({"message": "No published products found"}, status=200)

        return Response({"products": products}, status=200)
    except Exception:
        # Log the exception details internally
        return Response({"error": "An unexpected error occurred. Please try again."}, status=500)

@csrf_exempt
def get_product(request, product_id):
    """
    Retrieves details of a specific product by its ID.
    Returns a JSON response with the product details.
    """
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        product = products_collection.find_one({"_id": ObjectId(product_id)})

        if not product:
            return JsonResponse({"error": "Product not found"}, status=404)

        product["_id"] = str(product["_id"])  # Convert ObjectId to string
        return JsonResponse(product, status=200)

    except Exception:
        # Log the exception details internally
        return JsonResponse({"error": "An unexpected error occurred. Please try again."}, status=500)

@csrf_exempt
def get_premium_products(request):
    """
    Retrieves all premium products.

    Returns a JSON response with a list of premium products.
    """
    if request.method != "GET":
        return JsonResponse({"error": "Invalid request method."}, status=405)

    try:
        # Query for premium products only
        premium_products_cursor = products_collection.find({"premium": True})

        # Convert Cursor to a list of dicts and serialize ObjectIds
        premium_products_list = []
        for product in premium_products_cursor:
            product["_id"] = str(product["_id"])  # Convert ObjectId to string
            # Add any additional field formatting if needed
            premium_products_list.append(product)

        return JsonResponse({"products": premium_products_list}, status=200)

    except Exception as e:
        # Log the exception details internally
        return JsonResponse({"error": "An unexpected error occurred. Please try again later."}, status=500)

@csrf_exempt
def request_appointment(request):
    """
    Handles the request for a new appointment.
    Expects JSON payload with keys: product_id, name, email, phoneNumber, appointmentDateTime, message.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        # Parse the JSON data from the request body
        data = json.loads(request.body or "{}")

        # Extract and validate the data
        product_id = data.get('product_id')
        name = data.get('name', "").strip()
        email = data.get('email', "").strip()
        phone_number = data.get('phoneNumber', "").strip()
        appointment_datetime_str = data.get('appointmentDateTime', "").strip()
        message = data.get('message', "").strip()

        if not product_id:
            return JsonResponse({'error': 'Missing product_id'}, status=400)
        if not name:
            return JsonResponse({'error': 'Missing name'}, status=400)
        if not email:
            return JsonResponse({'error': 'Missing email'}, status=400)
        if not phone_number:
            return JsonResponse({'error': 'Missing phoneNumber'}, status=400)
        if not appointment_datetime_str:
            return JsonResponse({'error': 'Missing appointmentDateTime'}, status=400)

        # Convert appointment_datetime_str to a datetime object
        try:
            appointment_datetime = datetime.fromisoformat(appointment_datetime_str)
        except ValueError:
            return JsonResponse({'error': 'Invalid datetime format. Expected format: YYYY-MM-DDTHH:MM:SS'}, status=400)

        # Check if the appointment date is in the past
        current_date = datetime.now().date()
        if appointment_datetime.date() < current_date:
            return JsonResponse({'error': 'Appointment date cannot be in the past'}, status=400)

        # Convert the 24-hour time format to 12-hour format with AM/PM
        appointment_time_12hr = appointment_datetime.strftime('%I:%M %p')
        appointment_date = appointment_datetime.strftime('%Y-%m-%d')

        # Get the current timestamp
        timenow = datetime.now().isoformat()

        # Create a new appointment document
        appointment = {
            'product_id': product_id,
            'name': name,
            'email': email,
            'phone_number': phone_number,
            'appointment_date': appointment_date,
            'appointment_time': appointment_time_12hr,
            'message': message,
            'timenow': timenow,
            'is_read': False  # Mark as unread by default
        }

        # Insert the document into the appointments collection
        appointments_collection.insert_one(appointment)

        # Return a success response
        return JsonResponse({'success': 'Appointment requested successfully', 'timestamp': timenow}, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception:
        # Log the exception details internally
        return JsonResponse({'error': 'An unexpected error occurred. Please try again.'}, status=500)

@csrf_exempt
def submit_contact_us(request):
    """
    Handles the submission of a contact us form.
    Expects JSON payload with keys: first_name, last_name, email, phone_number, message.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        # Parse JSON data
        data = json.loads(request.body or "{}")

        # Extract and validate form fields
        first_name = data.get('first_name', "").strip()
        last_name = data.get('last_name', "").strip()
        email = data.get('email', "").strip()
        phone_number = data.get('phone_number', "").strip()
        message = data.get('message', "").strip()

        if not first_name:
            return JsonResponse({'error': 'First name is required'}, status=400)
        if not email:
            return JsonResponse({'error': 'Email is required'}, status=400)
        if not phone_number:
            return JsonResponse({'error': 'Phone number is required'}, status=400)
        if not message:
            return JsonResponse({'error': 'Message is required'}, status=400)

        # Get the current timestamp
        timestamp = datetime.now().isoformat()

        # Store data in MongoDB
        contact_data = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "phone_number": phone_number,
            "message": message,
            "timestamp": timestamp
        }

        contact_us_collection.insert_one(contact_data)

        # Return success response
        return JsonResponse({'success': 'Message submitted successfully', 'timestamp': timestamp}, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format'}, status=400)
    except Exception:
        # Log the exception details internally
        return JsonResponse({'error': 'An unexpected error occurred. Please try again.'}, status=500)

@csrf_exempt
def subscribe_user(request):
    """
    Subscribes a user to receive newsletters.
    Expects JSON payload with 'email'.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body or "{}")
        email = data.get("email", "").strip()

        if not email:
            return JsonResponse({"error": "Email is required"}, status=400)

        user = user_collection.find_one({"email": email})
        if not user:
            return JsonResponse({"message": "Please Login and Subscribe!"}, status=404)

        if user.get("is_subscribed", False):
            return JsonResponse({"message": "You're already subscribed!"}, status=200)

        user_collection.update_one({"email": email}, {"$set": {"is_subscribed": True}})

        # --- Professional Email Content ---
        subject = "You're Now Subscribed to GenAI-Suite! 🎉"
        message = f"""
Dear {user.get("first_name", "User")},

Thank you for subscribing to GenAI-Suite!

You're now officially part of a growing community exploring the cutting edge of Generative AI.

As a subscriber, you’ll be the first to receive:
- Updates and news
- Product launches
- AI tutorials and insights

We're excited to have you on board and look forward to sharing this journey with you.

Best regards,  
The GenAI-Suite Team
"""

        try:
            email_obj = EmailMessage(
                subject,
                message,
                os.getenv("EMAIL_HOST_USER"),  # ✅ sender
                [email]                        # ✅ recipient
            )
            email_obj.send()
        except Exception as e:
            print(f"Email sending failed: {e}")

        return JsonResponse({"message": "Subscription successful!"}, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON format"}, status=400)
    except Exception as e:
        return JsonResponse({"error": f"An unexpected error occurred: {str(e)}"}, status=500)

@csrf_exempt
def increment_product_view(request, product_id):
    """
    Increments the view count for a product and optionally tracks the user view.
    Expects JSON payload with optional 'user_data'.
    """
    if request.method == "POST":
        try:
            body_data = json.loads(request.body)

            user_data = body_data.get('user_data', None)
            print("user", user_data)

            products_collection.update_one(
                {"_id": ObjectId(product_id)},
                {"$inc": {"view_count": 1}},
                upsert=False
            )

            if user_data:
                view_record = {
                    "user_id": user_data.get('user_id'),
                    "name": user_data.get('name'),
                    "email": user_data.get('email'),
                    "phone_number": user_data.get('phone_number'),
                    "viewed_at": datetime.now()
                }

                product = products_collection.find_one({
                    "_id": ObjectId(product_id),
                    "user_views.user_id": user_data.get('user_id')
                })

                if not product:
                    result = products_collection.update_one(
                        {"_id": ObjectId(product_id)},
                        {"$push": {"user_views": view_record}},
                        upsert=False
                    )

                    if result.modified_count == 0:
                        return JsonResponse({"error": "Failed to update product"}, status=500)

                    return JsonResponse({
                        "success": True,
                        "message": "View count incremented and user view tracked"
                    }, status=200)
                else:
                    return JsonResponse({
                        "success": True,
                        "message": "View count incremented, user already tracked"
                    }, status=200)

            return JsonResponse({
                "success": True,
                "message": "View count incremented"
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)