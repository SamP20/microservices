import json
import sys
import os
import asyncio
import logging
import aio_pika
import msgpack
from samp20.asyncservice import run
from samp20.asyncservice.amqp import AmqpService, AmqpLogHandler


class AmqpSend:
    def __init__(self, amqp, routing_key, message):
        self.amqp = amqp
        self.routing_key = routing_key
        self.message = message
        self.log = logging.getLogger("amqp_send")

    async def start(self):
        self.channel = await self.amqp.channel()
        exchange = await self.channel.declare_exchange(
            name="amq.topic", type=aio_pika.ExchangeType.TOPIC, durable=True
        )

        body = msgpack.packb(self.message, use_bin_type=True, default=str)

        await exchange.publish(
            aio_pika.Message(body=body, delivery_mode=aio_pika.DeliveryMode.PERSISTENT),
            routing_key=self.routing_key,
        )

        asyncio.get_running_loop().stop()

    async def stop(self):
        await self.channel.close()


def main():
    with open(sys.argv[1], "r") as fh:
        config = json.load(fh)

    service_name = config["service_name"]

    logging.basicConfig(level=logging.INFO)

    amqpService = AmqpService(config["amqp"])
    amqpLogger = AmqpLogHandler(service=amqpService, client_name=service_name)
    amqpSend = AmqpSend(
        amqpService, os.environ["ROUTING_KEY"], json.loads(os.environ["MESSAGE"])
    )

    run(amqpService, amqpLogger, amqpSend)


if __name__ == "__main__":
    main()
