# Use Python 3.10 base image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy everything into container
COPY . /app

# Install dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Download NLTK data
RUN python -m nltk.downloader punkt stopwords

# Expose port
EXPOSE 8000

# Run the app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
