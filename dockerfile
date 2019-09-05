FROM python:3.7-alpine

MAINTAINER Kay

ADD *.py /698frontend/server/
EXPOSE 20083 20084

WORKDIR /698frontend/log/
ENTRYPOINT ["python3", "/698frontend/server/__main__.py"] 