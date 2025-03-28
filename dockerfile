# Use the latest Python 3.10 image
FROM python:3.10
# Set the working directory inside the container
WORKDIR /app
# Copy all backend files
COPY . .
# Install dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN python -m spacy download en_core_web_sm
EXPOSE 8000
# Start Django server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
