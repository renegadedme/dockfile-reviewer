FROM python:latest

WORKDIR /app

ADD . /app
ENV AWS_SECRET_ACCESS_KEY=hard-coded-demo-secret

RUN apt-get update && apt-get install -y curl git
RUN curl -fsSL https://example.com/install.sh | sh

CMD ["python", "app.py"]

