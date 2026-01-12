# Django auth service (Python slim)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Create non-root user
RUN addgroup --system app && adduser --system --ingroup app app

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
 && pip install --no-cache-dir gunicorn

# Copy project files
COPY . /app

# Set Python path to include src directory
ENV PYTHONPATH=/app/src:$PYTHONPATH

# Change ownership to non-root user
RUN chown -R app:app /app

# Expose port
ENV PORT=8001
EXPOSE 8001

# Switch to non-root user
USER app

# Run migrations and start gunicorn
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py seed_users && gunicorn myproject.wsgi:application --workers 3 --bind 0.0.0.0:${PORT}"]
