FROM python:3.9.7-slim
RUN mkdir app
COPY app /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT ["./gunicorn_starter.sh"]