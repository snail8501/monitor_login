FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir pyinotify requests

# Copy the current directory contents into the container at /app
COPY monitor.py /app