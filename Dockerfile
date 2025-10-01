FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install only essential dependencies for Playwright Firefox
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Basic tools
    wget ca-certificates \
    # Firefox dependencies (minimal set)
    libgtk-3-0 libdbus-glib-1-2 libxt6 libpci3 \
    libasound2 libx11-xcb1 libxcomposite1 libxcursor1 \
    libxdamage1 libxi6 libxtst6 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxrandr2 libgbm1 libxss1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Firefox for Playwright
RUN playwright install firefox

# Camoufox needs to fetch its fingerprints
RUN python3 -m camoufox fetch

# Add app files
COPY . .

# Launch script
CMD ["python3", "main.py"]