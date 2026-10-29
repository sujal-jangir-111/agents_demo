# Deliberately insecure demo image (Sentinel should flag this).
FROM python:latest
WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .
EXPOSE 5678
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5678"]
