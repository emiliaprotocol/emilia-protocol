# Official multi-platform Python 3.12.14 slim image, pinned by OCI index digest.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

RUN useradd --create-home --uid 1000 user
USER 1000
RUN mkdir -p /home/user/app
WORKDIR /home/user/app

ENV PATH="/home/user/venv/bin:/home/user/.local/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GRADIO_SERVER_NAME=0.0.0.0 \
    GRADIO_SERVER_PORT=7860 \
    GRADIO_ANALYTICS_ENABLED=False \
    HF_HUB_DISABLE_TELEMETRY=1

# Copy only the reviewed bundle inventory, including local wheels, before pip.
COPY --chown=1000:1000 app.py demo.py test_demo.py requirements.txt README.md ADAPTER.md LICENSE BUNDLE.json SHA256SUMS Dockerfile ./
COPY --chown=1000:1000 wheels/*.whl ./wheels/

RUN sha256sum --check SHA256SUMS \
    && python -m venv /home/user/venv \
    && python -m pip install --no-cache-dir --upgrade pip==26.2.1 \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && python -m pip check

EXPOSE 7860
CMD ["python", "app.py"]
