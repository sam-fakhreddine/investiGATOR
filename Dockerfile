FROM python:3.13-slim

WORKDIR /app

# Install system dependencies and poetry
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir poetry

# Configure poetry
RUN poetry config virtualenvs.create false \
    && poetry config virtualenvs.in-project false

# Copy dependency files
COPY pyproject.toml poetry.lock ./

# Install dependencies (without dev dependencies and without installing the project itself)
RUN poetry install --only=main --no-interaction --no-ansi --no-root

# Copy source code
COPY src/ ./src/
COPY config/ ./config/
COPY README.md ./

# Install the project itself
RUN poetry install --only=main --no-interaction --no-ansi

EXPOSE 8000

CMD ["python", "-m", "vpc_flow_investigator.web"]