FROM python:3.11-slim

# Install system dependencies for OpenCV and Nginx
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libglib2.0-0 \
    nginx \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
COPY requirements-vision.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-vision.txt

# Copy the rest of the application
COPY . .

# Setup Nginx configuration
COPY tools/nginx.conf /etc/nginx/sites-available/default

# Create an entrypoint script
RUN echo '#!/bin/bash\n\
service nginx start\n\
python -m vision.service & \n\
python run_local.py --no-browser --port 8080' > /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Hugging Face Spaces usually runs on port 7860
# But our internal gateway is on 8080. We will map them in the entrypoint if needed.
# For HF, we usually just need to serve the UI on port 7860.
EXPOSE 7860

# Start the services
CMD ["/app/entrypoint.sh"]
