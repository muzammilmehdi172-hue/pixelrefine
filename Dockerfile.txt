# Use Python 3.9 (required for basicsr + torch 1.13)
FROM python:3.9-slim

# Install OpenCV and other system dependencies
RUN apt-get update && apt-get install -y \
    libgl1 libglib2.0-0 wget curl sqlite3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Upgrade pip
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# ✅ Install PyTorch 1.13.1 (last version compatible with basicsr)
RUN pip install --no-cache-dir \
    torch==1.13.1+cpu \
    torchvision==0.14.1+cpu \
    torchaudio==0.13.1+cpu \
    -f https://download.pytorch.org/whl/cpu/torch_stable.html

# ✅ Install other dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create folders (Render safety)
RUN mkdir -p uploads results models templates static

EXPOSE 8000

# Initialize database
RUN python init_db.py

CMD ["python", "app.py"]