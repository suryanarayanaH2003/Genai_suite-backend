import jwt
import random
import json
from datetime import datetime, timedelta
from django.http import JsonResponse
from pymongo import MongoClient
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from bson import ObjectId

# ======================= CONFIGURATION =======================
# JWT Configuration
JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"

# MongoDB connection
client = MongoClient("mongodb+srv://ihub:ihub@harlee.6sokd.mongodb.net/")
db = client["GENAI"]
user_collection = db["users"]
appointments_collection = db['appointments']
products_collection = db['products']
contact_us_collection = db["contact_us"]

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

        
@api_view(["POST"])
@permission_classes([AllowAny])
def forgot_password(request):
    try:
        email = request.data.get('email')
        user = user_collection.find_one({"email": email})

        if not user:
            return Response({"error": "Email not found"}, status=400)

        # Generate a 6-digit numeric OTP
        reset_token = str(random.randint(100000, 999999))
        expiration_time = datetime.now() + timedelta(minutes=10)

        user_collection.update_one(
            {"email": email},
            {"$set": {"password_reset_token": reset_token, "password_reset_expires": expiration_time}}
        )

        print(f"[DEBUG] OTP for {email}: {reset_token}")  # Replace with email-sending logic in production

        return Response({
            "message": "OTP has been sent to your email.",
            "token": reset_token  # Optional: only for testing; remove in production
        }, status=200)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@csrf_exempt
@api_view(["POST"])
def verify_reset_token(request):
    try:
        data = json.loads(request.body)
        email = data.get("email")
        token = data.get("token")

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

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)
    
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
    try:
        # Connect to the "products" collection
        products_collection = db["products"]

        # Fetch only the 'is_publish' field for published products (is_publish=True)
        products = list(products_collection.find({"is_publish": True}, {"_id": 1, "user_id": 1, "product_data": 1, "user_journey":1, "product_features":1, "starred": 1, "is_publish": 1, "created_at": 1, "premium": 1}))  # Include only is_publish field and exclude MongoDB ObjectId

        # Convert `_id` to string
        for product in products:
            product["_id"] = str(product["_id"])

        if not products:
            return Response({"message": "No published products found"}, status=200)

        return Response({"products": products}, status=200)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@csrf_exempt
def get_product(request, product_id):
    if request.method == "GET":
        try:
            product = products_collection.find_one({"_id": ObjectId(product_id)})

            if not product:
                return JsonResponse({"error": "Product not found"}, status=404)

            product["_id"] = str(product["_id"])  # Convert ObjectId to string
            return JsonResponse(product, status=200)
        
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)

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
    if request.method == 'POST':
        try:
            # Parse the JSON data from the request body
            data = json.loads(request.body)

            # Extract the data
            product_id = data.get('product_id')
            name = data.get('name')
            email = data.get('email')
            phone_number = data.get('phoneNumber')
            appointment_datetime_str = data.get('appointmentDateTime')
            message = data.get('message')

            # Validate the data
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
                'is_read': False  # ✅ Mark as unread by default
            }

            # Insert the document into the appointments collection
            appointments_collection.insert_one(appointment)

            # Return a success response
            return JsonResponse({'success': 'Appointment requested successfully', 'timestamp': timenow})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            print("Error:", str(e))  # Debugging: Log the error
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def submit_contact_us(request):
    if request.method == 'POST':
        try:
            # Parse JSON data
            data = json.loads(request.body)

            # Extract form fields
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            email = data.get('email')
            phone_number = data.get('phone_number')
            message = data.get('message')

            # Validate required fields
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
        except Exception as e:
            print("Error:", str(e))
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def subscribe_user(request):
    if request.method == "POST":
        try:
            # Parse the request data
            data = json.loads(request.body)
            email = data.get("email")

            if not email:
                return JsonResponse({"error": "Email is required"}, status=400)

            # Check if user exists
            user = user_collection.find_one({"email": email})

            if not user:
                return JsonResponse({"message": "Please Login and Subscribe!"}, status=404)

            # Update the user document to add 'is_subscribed: true'
            user_collection.update_one({"email": email}, {"$set": {"is_subscribed": True}})

            return JsonResponse({"message": "Subscription successful!"}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def increment_product_view(request, product_id):
    if request.method == "POST":
        try:
            # Parse the request body
            body_data = json.loads(request.body)
            
            # Check if we have user data
            user_data = body_data.get('user_data', None)
            print("user", user_data)
            
            # First update the view count
            products_collection.update_one(
                {"_id": ObjectId(product_id)},
                {"$inc": {"view_count": 1}},
                upsert=False
            )
            
            # If we have user data, add it to the product document
            if user_data:
                # Create a view record
                view_record = {
                    "user_id": user_data.get('user_id'),
                    "name": user_data.get('name'),
                    "email": user_data.get('email'),
                    "viewed_at": datetime.now()
                }
                
                # Check if this user has already viewed this product
                product = products_collection.find_one({
                    "_id": ObjectId(product_id),
                    "user_views.user_id": user_data.get('user_id')
                })
                
                if not product:
                    # Add user view to the product document
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