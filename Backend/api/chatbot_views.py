import os
import threading
from pymongo import MongoClient
from django.http import JsonResponse
from rest_framework.decorators import api_view
from sentence_transformers import SentenceTransformer 
import google.generativeai as genai
import hashlib
import re
import spacy
from datetime import datetime
import requests
from transformers import logging as hf_logging


# 🔹 Suppress Hugging Face transformers logs
hf_logging.set_verbosity_error()

os.environ["GOOGLE_API_KEY"] = "AIzaSyC6-Y0KjdZwB9E0-BLWdhUcAaf92sHJYrM"  # Replace with your actual key
genai.configure(api_key=os.environ["GOOGLE_API_KEY"])

# 🔹 Create Generative Models (Using the Same API Key)
gemini_model = genai.GenerativeModel("gemini-1.5-flash-8b")

# # ✅ Global chat history to track conversation
chat_history = []

client = MongoClient("mongodb+srv://ihub:ihub@harlee.6sokd.mongodb.net/")
db = client["GENAI"]
collection = db["Chatbot_Knowledgebase"]
appointments_collection = db["appointments"]
products_collection = db["products"]

embedding_model = SentenceTransformer('jinaai/jina-embeddings-v2-base-en')
print("Embedding dimension:", embedding_model.get_sentence_embedding_dimension())

data_loaded = threading.Event()
# Ensure chat_history exists
if "chat_history" not in globals():
    chat_history = []
    
nlp = spacy.load("en_core_web_sm")

# 🔹 API Endpoint
API_URL = "http://127.0.0.1:8000/api/published-products/" 

# 🔍 Step 1: Find and print error-causing documents
error_docs = list(collection.find({"$or": [{"product_name": {"$exists": False}}, {"user_id": {"$exists": False}}]}))

if error_docs:
    print("⚠️ Found error-causing documents:")
    for doc in error_docs:
        print(doc)

    # 🔥 Step 2: Delete faulty documents
    delete_result = collection.delete_many({"$or": [{"product_name": {"$exists": False}}, {"user_id": {"$exists": False}}]})
    print(f"🗑 Deleted {delete_result.deleted_count} faulty documents.")

    # 🔍 Step 3: Verify deletion
    remaining_errors = list(collection.find({"$or": [{"product_name": {"$exists": False}}, {"user_id": {"$exists": False}}]}))
    if not remaining_errors:
        print("✅ All faulty documents removed successfully!")
    else:
        print("⚠️ Some faulty documents still exist. Please check manually.")
else:
    print("✅ No error documents found! Database is clean.")

# ✅ **1. Compute Hash**
def compute_hash(content):
    return hashlib.sha256(content.encode()).hexdigest()

# ✅ **2. Fetch JSON Data from API**
def fetch_data_from_api():
    try:
        response = requests.get(API_URL)
        response.raise_for_status()  # Raise error for HTTP issues
        data = response.json()  # Convert response to JSON
        return data.get("products", [])  # Extract the "products" list
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching data from API: {e}")
        return []
    
# ✅ **3. Store Embeddings in MongoDB**
def store_embeddings_in_mongo():
    products = fetch_data_from_api()
    api_product_keys = set()  # To track valid product entries from API

    for product in products:
        user_id = product.get("user_id", "unknown_user")
        product_data = product.get("product_data", {})
        product_name = product_data.get("product_name", "")
        product_description = product_data.get("product_description", "")
        category = product_data.get("category", "")

        user_journey = product.get("user_journey", [])
        product_features = product.get("product_features", [])

        # 🔹 Convert user journey & features into text format
        user_journey_text = "\n".join([f"{j['journey_name']}: {j['journey_description']}" for j in user_journey])
        product_features_text = "\n".join([f"{f['feature_name']}: {f['feature_description']}" for f in product_features])

        # 🔹 Combine all content for embedding
        full_content = f"Product Name: {product_name}\nDescription: {product_description}\nCategory: {category}\nUser Journey: {user_journey_text}\nFeatures: {product_features_text}"

        # 🔹 Compute hash for content
        content_hash = compute_hash(full_content)

        # 🔹 Check if the content already exists in MongoDB
        existing_doc = collection.find_one({"user_id": user_id, "product_name": product_name}, {"_id": 1, "content_hash": 1})

        if existing_doc:
            # ✅ If content hash matches → Data is unchanged, skip processing
            if existing_doc["content_hash"] == content_hash:
                print(f"✅ Skipping {product_name} (Data unchanged)")
                api_product_keys.add((user_id, product_name))
                continue

            # 🔹 If content changed → Delete old entry before updating
            print(f"🗑 Deleting outdated entry for {product_name}")
            collection.delete_one({"user_id": user_id, "product_name": product_name})

        # 🔹 Compute embeddings
        embedding = embedding_model.encode(full_content).tolist()  # Convert NumPy array to list

        # 🔹 Store in MongoDB
        try:
            collection.update_one(
                {"user_id": user_id, "product_name": product_name},  # Search condition
                {"$set": {
                    "user_id": user_id,
                    "product_name": product_name,
                    "description": product_description,
                    "category": category,
                    "user_journey": user_journey,
                    "product_features": product_features,
                    "content": full_content,
                    "embedding": embedding,
                    "content_hash": content_hash
                }},
                upsert=True,  # Insert if not exists
            )
            print(f"✅ Stored/Updated {product_name} in MongoDB")
            api_product_keys.add((user_id, product_name))

        except Exception as e:
            print(f"❌ Error storing {product_name} in MongoDB: {e}")

    # ✅ **4. Delete Stale Data (Not in API Response)**
    all_db_products = collection.find({}, {"user_id": 1, "product_name": 1})
    for db_product in all_db_products:
        user_id = db_product.get("user_id", "unknown_user")
        product_name = db_product.get("product_name", "unknown_product")
        
        if user_id == "unknown_user" or product_name == "unknown_product":
            print(f"⚠️ Warning: Document missing required fields -> {db_product}")

        db_key = (user_id, product_name)

        if db_key not in api_product_keys:
            print(f"🗑 Removing stale product: {db_product['product_name']}")
            collection.delete_one({"user_id": db_product["user_id"], "product_name": db_product["product_name"]})

    print("✅ Knowledge base synced successfully!")

    print("✅ Knowledge base processed successfully!")
    data_loaded.set()

# ✅ **4. Search Data in MongoDB**
def search_mongo_vector(query, top_k=3):
    try:
        # Ensure MongoDB collection is initialized
        if collection is None:
            print("❌ Error: MongoDB collection is not initialized.")
            return []

        # Convert query to embedding
        query_embedding = embedding_model.encode([query]).tolist()[0]

        # Ensure stored embeddings exist and are of the same length
        sample_doc = collection.find_one({}, {"embedding": 1, "_id": 0})
        if not sample_doc or "embedding" not in sample_doc:
            print("❌ Error: No documents with embeddings found in MongoDB.")
            return []

        stored_embedding_length = len(sample_doc["embedding"])
        query_embedding_length = len(query_embedding)

        if stored_embedding_length != query_embedding_length:
            print(f"❌ Error: Query embedding size ({query_embedding_length}) does not match stored embeddings ({stored_embedding_length}).")
            return []

        # Ensure numCandidates is always >= top_k
        num_candidates = max(top_k, 10)  # Increased to 10 for better results

        # Vector search pipeline
        pipeline = [
            {
                "$vectorSearch": {
                    "index": "updated_vector",  # Ensure vector index exists
                    "path": "embedding",
                    "queryVector": query_embedding,
                    "numCandidates": num_candidates,
                    "limit": top_k,
                    "similarity": "cosine"
                }
            }
        ]

        results_cursor = collection.aggregate(pipeline)  # Run vector search query
        results = list(results_cursor)  # Convert cursor to list to prevent cursor exhaustion

        if not results:
            print("⚠️ No relevant documents found in the MongoDB.")
            return []
        
        # Extract all relevant fields while preserving order
        extracted_knowledge = []
        seen_contents = set()

        for doc in results:
            product_name = doc.get("product_name", "N/A").strip()  # Use "N/A" if missing
            description = doc.get("description", "No description available").strip()
            category = doc.get("category", "Unknown Category").strip()

            # Extract user journey properly (Avoid missing fields)
            user_journey_list = doc.get("user_journey", [])
            if user_journey_list:
                user_journey_text = "\n".join([f"{j.get('journey_name', 'No Journey')}: {j.get('journey_description', 'No Description')}" for j in user_journey_list])
            else:
                user_journey_text = "No User Journey Available"

            # Extract product features properly (Avoid missing fields)
            product_features_list = doc.get("product_features", [])
            if product_features_list:
                product_features_text = "\n".join([f"{f.get('feature_name', 'No Feature')}: {f.get('feature_description', 'No Description')}" for f in product_features_list])
            else:
                product_features_text = "No Features Available"

            # Construct the final formatted content
            content = f"""Product Name: {product_name}
            Description: {description}
            Category: {category}
            User Journey: {user_journey_text}
            Features: {product_features_text}
            """

            # print(f"🔹 Extracted Content from DB:\n{content}")  # Debugging print

            if content and content not in seen_contents:
                extracted_knowledge.append(content)
                seen_contents.add(content)

        # print(f"✅ Final Extracted Knowledge: {extracted_knowledge}")
        return extracted_knowledge

    except Exception as e:
        print(f"❌ Vector search error: {e}")
        return []
    


# ✅ **5. Generate The Answer with Gemini**
def generate_answer_with_rag(query, closest_knowledge_list, chat_history):
    
        combined_knowledge = "\n\n".join(closest_knowledge_list)
        
        # Truncate knowledge 
        max_knowledge_length = 28000
        if len(combined_knowledge) > max_knowledge_length:
            combined_knowledge = combined_knowledge[:max_knowledge_length]
            
            print(len(combined_knowledge))


        if not chat_history:
            print("⚠️ No chat history available.")
            history_text = "No prior conversation history."
        else:
            history_text = "\n".join([f"{msg['role']}: {msg['content']}" for msg in chat_history[-6:]])
        
            product_names = [prod["product_data"]["product_name"] for prod in products_collection.find({}, {"product_data.product_name": 1})]
            print(f"Knowledge --- The products are : {product_names}")

        
        prompt = f"""
        You are a professional AI assistant for SNS iHub, focused on engaging users and promoting SNS Gen AI Suite, which includes the following:

        - You are a **humanoid chatbot** designed to be indistinguishable from a human in conversation.  
        - You are an expert in **natural, human-like conversations**, ensuring users do not realize you are an AI.  
        - You work **exclusively for the Gen AI Suite**, assisting users with inquiries related to its products and services.  

        1. **Providing Information:** Your primary duty is to **inform users about the products** in the SNS Gen AI Suite.
        2. **Your work:** You are the mediator between the user and the Gen AI Suite platform so solve the queries about the Gen AI Suite products and services.
        

        🚨 **STRICT VALIDATION RULES:**  
        - You **MUST NOT** answer any question **outside the provided knowledge base**.
        - If the user asks about **math, programming, coding, general knowledge, or any irrelevant topics**, reply with:  
        **"I'm sorry, but I can only provide answers about Gen AI Suite Platform!"**  
        - **STRICTLY AVOID** answering **math problems, equations, calculations, or coding requests**.
        - **DO NOT** generate stories, poems, or creative writing.  
        - **DO NOT** provide general knowledge, trivia, or personal opinions. 
        - **DO NOT** provide calculations answers.
        - **DO NOT** Give answer in any other language accent i need only the indian english.
        - Avoid repetitive phrases and answer based on context
        
        
        🚨 **STRICT Response RULES:**
        - You **MUST ONLY** answer using the provided knowledge base , products in the gen ai suite and previous conversation.If the previous conversation is not relevant skip that.
        - Response format : Respond as naturally as possible, like a human in a real conversation.Make sure that the response sounds like english.
        
        Knowledge: {combined_knowledge}
        
        The products in the Gen-AI Suite Platforms are : {product_names} so if the user tells about any other product which are not listed here say that you dont know about that product.You have only the {product_names} in the Gen-Ai Suite Platform

        Previous Conversation:
        {history_text}

        Question: {query}
        The answer should be formatted and not just copied from the knowledge base. Reframe it you should represent as the Gen-Ai suite platform so use words like "We" for some answers which are needed that and provide a concise response but dont remove the necesssary data in it, considering the previous conversation.
        All the products in the Gen AI Suite will have the demo for the {product_names}.
        """

        # Print all content passed to the model
        print("\n🔹 Full Content Sent to Model:\n")

        try:
            response = gemini_model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            print(f"❌ Gemini API Error: {e}")
            return "Sry , Currently we seem a overloading , try again later !!"
        
# ✅ **6. Interest for products**
def check_scheduling_intent(query, chat_history):
    history_text = "\n".join([f"{msg['role']}: {msg['content']}" for msg in chat_history])

    # Debugging: Print the conversation history
    # print("\n🔹 Debug: Conversation History Sent to Scheduling Model 🔹")
    # print(history_text)
    # print("🔹 End of Debugging Output 🔹\n")

    prompt = f"""
    You are an expert at analyzing user engagement and determining their intent to schedule a demo or meeting.
    You are provided with the conversation history.

    🔹 Your task is to analyze the conversation and determine if the user has **shown significant interest in the product**.
    🔹 This can be inferred if the user has:
        - Asked **multiple** detailed questions about the product, its features, or its use cases.
        - Shown **consistent engagement** in learning about the platform.
        - Indicated curiosity about how it works or how they can use it.
        - If the user query direclty ask for the demo , im interested to have a try like this .Consider this is a strong indicator of interest .
    
    🚫 Do NOT require the user to explicitly ask for a demo or meeting. Instead, infer interest from their behavior.

    Based on the conversation history below, return ONLY "yes" or "no". 

    Conversation:
    {history_text}

    User Query: {query}

    Has the user shown enough interest to be considered for a demo? (yes/no):
    """

    try:
        response = gemini_model.generate_content(prompt)
        intent = response.text.strip().lower()
        print(f"Scheduling Intent Detection: {intent}")
        return "yes" if "yes" in intent else "no"
    except Exception as e:
        print(f"❌ Scheduling Intent API Error: {e}")
        return "no"

# ✅ **7. Demo Confirmation Code**
def schedule_demo(chat_history, query):
    """
    Uses MongoDB products and AI model to determine which product the user is interested in
    and schedules a demo based on user confirmation.
    """

    # 🔹 Step 1: Fetch all product names from MongoDB
    product_names = [prod["product_data"]["product_name"] for prod in products_collection.find({}, {"product_data.product_name": 1})]
    print(f"The products are : {product_names}")

    # 🔹 Step 2: Prepare chat history for AI
    history_text = "\n".join([f"{msg['role']}: {msg['content']}" for msg in chat_history[-20:]])

    # 🔹 Step 3: AI-Powered Prompt for Product Detection
    prompt = f"""
    You are an AI assistant helping users schedule product demos. 
    The user has been chatting about various products. Below is their conversation history.

    🔹 List of Available Products: {', '.join(product_names)}
    🔹 User Conversation:
    {history_text}

    Task:
    1️⃣ Determine if the user is interested in **any specific product** from the list above.If you not find the product name check for the user conversation to find the product what they are interested in.
    2️⃣ If you detect a **clear interest**, return ONLY the product name. The product name should not be edited and must match exactly with the names in the list.
    3️⃣ If you are **unsure**, return "None".

    Answer with just the product name or "None".
    """

    try:
        # 🔹 Step 4: Send Prompt to AI Model
        response = gemini_model.generate_content(prompt)
        interested_product = response.text.strip()

        
        # 🔹 Step 5: Handle AI's response
        if interested_product == "None":
            product_names = [prod["product_data"]["product_name"] for prod in products_collection.find({}, {"product_data.product_name": 1})]
            
            # 🔹 Generate AI prompt for matching
            analyzing_prompt = f"""
            You are an expert at matching user queries with product names.
            Given the product names: {', '.join(product_names)},
            and the last two user messages: "{history_text}",
            determine the most relevant product name.
            If no match is found, return 'None'.
            """
            print(history_text)
            # 🔹 Get AI response
            response = gemini_model.generate_content(analyzing_prompt)
            interested_product = response.text.strip()

            # 🔹 If a match is found, trigger confirmation
            if interested_product != "None":
                confirmation_message = f"It sounds like you're interested in a demo for '{interested_product}'. If you'd like to schedule one, say 'Yes'. Otherwise, say 'No'."
                return confirmation_message, {}

            # 🔹 If no match is found, ask the user again
            return f"I see you're interested in a demo, but I couldn't identify the product. Can you specify? Like {', '.join(product_names)}?", {}

        # 🔹 Step 6: Confirm with the user
        confirmation_message = f"It sounds like you're interested in a demo for '{interested_product}'. If you'd like to schedule one, say 'Yes'. Otherwise, say 'No'."
        
        # 🔹 Step 7: Get user's latest response
        user_response = query.strip().lower()

        if user_response == "yes":
            # 🔹 Step 8: Store scheduling data
            scheduling_data = {"product_name": interested_product, "step": "confirmation"}
            return f"It sounds like you're interested in a demo for '{interested_product}'. If you'd like to schedule one, say 'Yes'. Otherwise, say 'No'.", scheduling_data

        elif user_response == "no":
            return "No problem! Let us know if you need a demo in the future.", {}

        else:
            return confirmation_message, {}

    except Exception as e:
        print(f"❌ AI Error: {e}")
        return "There was an issue detecting your product interest. Can you specify which product you need a demo for?", {}

# ✅ **8. User Data Collection Code**
def validate_name(name):
    return bool(re.match(r"^[A-Za-z][A-Za-z._]*$", name))

def validate_phone_number(phone_number):
    return phone_number.isdigit() and len(phone_number) == 10

def validate_email(email):
    return isinstance(email, str) and "@" in email and "." in email

def validate_appointment_time(appointment_time):
    # Normalize input: Remove spaces and convert to uppercase
    appointment_time = appointment_time.strip().upper()

    # Regular expression to match both "1:30AM" and "01:30 AM" formats
    match = re.match(r"^([1-9]|0[1-9]|1[0-2]):([0-5][0-9])\s?(AM|PM)$", appointment_time)

    if match:
        hour, minute, period = match.groups()
        formatted_time = f"{int(hour):02}:{minute} {period}"  # Ensure two-digit hour format
        return formatted_time  # Return corrected time format

    return None  # Return None if invalid

def validate_appointment_date(appointment_date):
    # Normalize delimiters (replace / or space with -)
    appointment_date = re.sub(r"[\/ ]", "-", appointment_date.strip())

    # Match formats like YYYY-MM-DD, YYYY-M-D, YYYY-MM-D, YYYY-M-DD
    match = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})$", appointment_date)
    if match:
        year, month, day = map(int, match.groups())
        try:
            # Convert to datetime object
            parsed_date = datetime(year, month, day)

            # Get today's date (without time)
            today = datetime.today().date()

            # Check if the date is in the future
            if parsed_date.date() > today:
                return parsed_date.strftime("%Y-%m-%d")  # Return formatted date
            
            return None  # ❌ Reject past or today’s date

        except ValueError:
            return None  # ❌ Invalid date (e.g., 2025-02-30)
    
    return None  # ❌ Invalid format

def validate_message(message):
    return isinstance(message, str) and len(message.split()) > 1  # At least two words

def get_details(schedule_data, user_response=None):
    global chat_history

    product_name = schedule_data.get("product_name")
    if not product_name:
        return "Error: Product name is missing. Please provide the product name."

    required_fields = ["name", "phone_number", "email", "appointment_time", "appointment_date", "message"]
    
    if "collected_details" not in schedule_data:
        schedule_data["collected_details"] = {}

    collected_details = schedule_data["collected_details"]

    if user_response and user_response.strip().lower() in ["yes", "no"] and not collected_details:
        return "Enter your name:"  

    if user_response is not None:
        for field in required_fields:
            if field not in collected_details:
                value = user_response.strip()
                
                if field == "name" and not validate_name(value):
                    return "Please type your name."
                elif field == "phone_number" and not validate_phone_number(value):
                    return "Please enter a 10-digit phone number."
                elif field == "email" and not validate_email(value):
                    return "Please enter a valid email ID."
                elif field == "appointment_time":
                    formatted_time = validate_appointment_time(value)
                    if not formatted_time:
                        return "Please enter in format 'hh:mm AM/PM' (e.g., 11:12 AM/PM)."
                    collected_details[field] = formatted_time  # Store the corrected format
                    continue  
                elif field == "appointment_date":
                    formatted_date = validate_appointment_date(value)
                    if not formatted_date:
                        return "Please enter in format 'YYYY-MM-DD' (e.g., 2025-03-14)."
                    collected_details[field] = formatted_date  # Store the corrected format
                    continue  
                elif field == "message" and not validate_message(value):
                    return "Please enter a message regarding the demo in one or two lines"

                collected_details[field] = value  # Store valid input
                print(f"{collected_details} is the data")
                break  # Move to the next missing field


    for field in required_fields:
        if field not in collected_details:
            return f"Enter your {field.replace('_', ' ')}:"

    confirmation_message = (
        "These are the details collected:\n"
        f"1. Name: {collected_details['name']}\n"
        f"2. Phone Number: {collected_details['phone_number']}\n"
        f"3. Email: {collected_details['email']}\n"
        f"4. Appointment Time: {collected_details['appointment_time']}\n"
        f"5. Appointment Date: {collected_details['appointment_date']}\n"
        f"6. Message: {collected_details['message']}\n\n"
        "Are these details correct? (yes/no)"
    )

    if "confirmed" not in schedule_data:
        schedule_data["confirmed"] = False
        return confirmation_message

    if user_response and user_response.strip().lower() == "yes":
        timenow = datetime.utcnow().isoformat()

        # Fetch the correct product_id (ObjectId) from products collection
        product = products_collection.find_one({"product_data.product_name": product_name})

        if not product:
            return "Error: Product not found in the database."

        product_id = product["_id"]  # Extract the ObjectId

        try:
            appointments_collection.insert_one({
                "product_id": str(product_id),  # Convert ObjectId to string
                **collected_details,
                "timenow": timenow,
                "is_read": bool(False)  # Explicitly setting as boolean
            })
            schedule_data["confirmed"] = True  # Prevent further correction prompts
        except Exception as e:
            return f"Error saving to database: {str(e)}"

        return "✅ Your details have been saved successfully. We will contact you soon."

    if user_response and user_response.strip().lower() == "no":
        return "Which details are incorrect? Enter the numbers pointing to the details (e.g., 1,3,5) to correct."

    if user_response:
        try:
            incorrect_fields = user_response.split(",")
            incorrect_fields = [int(num.strip()) for num in incorrect_fields if num.strip().isdigit()]
        except ValueError:
            return "Invalid input. Please enter valid numbers separated by commas (e.g., 1,3,5)."

        if incorrect_fields:
            for num in incorrect_fields:
                if 1 <= num <= 6:
                    field = required_fields[num - 1]
                    collected_details.pop(field, None)  # Remove incorrect field so user can re-enter it

            # Prompt for the first incorrect field only
            next_field = required_fields[incorrect_fields[0] - 1]
            return f"Enter your {next_field.replace('_', ' ')}:"

        # **After updating the details, return the confirmation message again**
        confirmation_message = (
            "These are the updated details collected:\n"
            f"1. Name: {collected_details.get('name', 'Not provided')}\n"
            f"2. Phone Number: {collected_details.get('phone_number', 'Not provided')}\n"
            f"3. Email: {collected_details.get('email', 'Not provided')}\n"
            f"4. Appointment Time: {collected_details.get('appointment_time', 'Not provided')}\n"
            f"5. Appointment Date: {collected_details.get('appointment_date', 'Not provided')}\n"
            f"6. Message: {collected_details.get('message', 'Not provided')}\n\n"
            "Are these details correct now? (yes/no)"
        )
        return confirmation_message 

    return "Invalid input. Please enter the numbers corresponding to incorrect details."

# ✅ **9. Chatbot Main Function**
@api_view(["POST"])
def chatbot_view(request):
    global chat_history , current_email  

    data_loaded.wait()
    query = request.data.get("query")
    email = request.data.get("email")


    if not query or not email:
        return JsonResponse({"error": "Query or email missing"}, status=400)

    try:
        # ✅ Check if the email has changed
        if "current_email" not in globals() or current_email != email:
            chat_history = []  
            current_email = email  
        
        # print(f"{chat_history} is the history")
        # print(f"{current_email} is the current email id")
        # Step 1: Store user query in chat history
        chat_history.append({"role": "user", "content": query})

        # ✅ Step 2: Check if we need to collect more details before scheduling
        scheduling_data = next((msg["scheduling_data"] for msg in reversed(chat_history) if "scheduling_data" in msg), None)
        
        if scheduling_data:
            response = get_details(scheduling_data, query)  # Collect user details
            chat_history.append({"role": "assistant", "content": response})
            chat_history.append({"role": "user", "content": query})
            print(f"{chat_history} is the data")

            # ✅ If all details have been collected, remove scheduling_data & return to normal flow
            if "✅ Your details have been saved successfully. We will contact you soon." in response:
                print("✅ Your details have been saved successfully. We will contact you soon. It is called")
                for msg in reversed(chat_history):  
                    if "scheduling_data" in msg:
                        msg.pop("scheduling_data")  # Remove scheduling data
                        break  # Only remove the latest scheduling_data

                return JsonResponse({"answer": response})  # Stop further processing

            return JsonResponse({"answer": response})  # Ask for next missing detail


        # ✅ Step 3: Detect scheduling intent only if all details are collected
        scheduling_intent = check_scheduling_intent(query, chat_history[-20:])

        if scheduling_intent == "yes":
            schedule_result, schedule_data = schedule_demo(chat_history[-20:],query)

            chat_history.append({"role": "assistant", "content": schedule_result, "scheduling_data": schedule_data})
            print(f"{chat_history} is the chat history")

            # ✅ Step 9: Check if user confirms scheduling
            if query.strip().lower() == "yes" and schedule_data:
                confirmation_response = get_details(schedule_data, query)
                print(f"{confirmation_response} is the confirmation response")
                chat_history.append({"role": "assistant", "content": confirmation_response})
                return JsonResponse({"answer": confirmation_response})

            return JsonResponse({"answer": schedule_result})

        # ✅ Step 4: Retrieve relevant knowledge if no scheduling intent
        closest_knowledge_list = search_mongo_vector(query)

        # ✅ Step 5: Generate a response using RAG
        answer = generate_answer_with_rag(query, closest_knowledge_list, chat_history[-6:])

        # ✅ Step 6: Store assistant response
        chat_history.append({"role": "assistant", "content": answer})

        # ✅ Step 7: Trim chat history to last 6 messages
        chat_history = chat_history[-6:]

        return JsonResponse({"answer": answer})

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

        


# 🔹 Connect to MongoDB
client = MongoClient("mongodb+srv://ihub:ihub@harlee.6sokd.mongodb.net/")
db = client["GENAI"]
products_collection = db["products"]

# ✅ Function to listen for ANY change in `products_collection`
def watch_product_changes():
    pipeline = [{"$match": {"operationType": {"$in": ["insert", "update", "delete"]}}}]
    
    with products_collection.watch(pipeline) as stream:
        for change in stream:
            print(f"🔔 Change detected in 'products' collection! Type: {change['operationType']}")

            # ✅ Start embedding process in a background thread
            embedding_thread = threading.Thread(target=store_embeddings_in_mongo, daemon=True)
            embedding_thread.start()

# ✅ Start listening for changes in a background thread
listener_thread = threading.Thread(target=watch_product_changes, daemon=True)
listener_thread.start()

# ✅ Load existing data on startup (Optional)
loading_thread = threading.Thread(target=store_embeddings_in_mongo, daemon=True)
loading_thread.start()

print("✅ MongoDB Change Stream Listener started!")