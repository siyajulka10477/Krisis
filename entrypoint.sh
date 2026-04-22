#!/bin/bash

# Start Nginx in the background
echo "Starting Nginx..."
service nginx start

# Start the Vision Service in the background
echo "Starting AI Vision Service..."
python -m vision.service &

# Start the main Krisis Application
echo "Starting Krisis Engine..."
# Note: We bind to 7860 as it is the default port for Hugging Face Spaces
python run_local.py --port 7860 --no-browser
