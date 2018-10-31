FROM python:3.7.1-alpine3.8 as base


FROM base as builder

RUN mkdir /install

WORKDIR /install

RUN apk add build-base python3-dev libffi-dev libressl-dev git openssh

RUN pip install -U pip &&\
    git clone https://github.com/SamP20/asyncservice.git &&\
    cd asyncservice &&\
    pip install --install-option="--prefix=/install" . &&\
    cd .. &&\
    rm -r asyncservice


FROM base

COPY --from=builder /install /usr/local

COPY src /app

WORKDIR /app

ENV ROUTING_KEY example.key

ENV MESSAGE="{\"message\": \"hello world\"}"

USER 999:999

CMD ["python", "amqp_send.py", "config.json"]