
# 1. Start with a Python base image (fixes your current error!)
FROM python:3.11-slim

# Install Tor and required Robin dependencies
RUN DEBIAN_FRONTEND="noninteractive" apt-get update && \
    apt-get install -y --no-install-recommends \
      tor \
      build-essential \
      curl \
      libssl-dev \
      libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# 2. Set the working directory inside the container
WORKDIR /app

# 3. Copy your requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy the rest of your backend code into the container
COPY . .

# Change the CMD to point to an entrypoint script
RUN chmod +x entrypoint.sh
CMD ["./entrypoint.sh"]
