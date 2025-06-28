FROM python:3.13-slim

WORKDIR /app

RUN pip install poetry

COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false \
    && poetry install --only=main

COPY src/ ./src/
COPY config/ ./config/

EXPOSE 8000

CMD ["python", "-m", "vpc_flow_investigator.web"]