# Base Python image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy only requirements first (for better layer caching)
COPY requirements.txt ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Download NLTK data
RUN python -m nltk.downloader punkt stopwords

# Copy the rest of the app files
COPY . .

# Expose the port FastAPI will run on
EXPOSE 8000

# Start the FastAPI application using Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
