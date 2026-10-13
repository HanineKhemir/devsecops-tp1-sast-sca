FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vulnbank/ ./vulnbank/

ENV PYTHONPATH=/app
ENV FLASK_APP=vulnbank.app

EXPOSE 5000

CMD ["python", "-m", "vulnbank.app"]
