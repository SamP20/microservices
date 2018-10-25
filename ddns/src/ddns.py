import json
import sys
import asyncio
import logging
import aiohttp
import aio_pika
from samp20.asyncservice import run
from samp20.asyncservice.logger import DictFormatter
from samp20.asyncservice.amqp import AmqpService, AmqpLogHandler


class DdnsService:
    def __init__(self, amqp, listen_queue='ddns', url="https://dynamicdns.park-your-domain.com/update", **kwargs):
        self.amqp = amqp
        self.url = url
        self.payload = kwargs
        self.listen_queue = listen_queue
        self.log = logging.getLogger("ddns")

    async def start(self):
        self.log.info("starting ddns")
        self.channel = await self.amqp.channel()
        queue = await self.channel.declare_queue(
            name=self.listen_queue,
            durable=True,
        )

        exchange = await self.channel.declare_exchange(
            name="amq.topic",
            type=aio_pika.ExchangeType.TOPIC,
            durable=True,
        )

        await queue.bind(exchange, routing_key='network.up')

        await queue.consume(self.on_message)

    async def stop(self):
        await self.channel.close()

    async def on_message(self, message: aio_pika.IncomingMessage):
        with message.process():
            async with aiohttp.ClientSession() as session:
                async with session.get(self.url, params=self.payload) as resp:
                    self.log.info("Dns update request sent. Status %s", resp.status)

def main():
    with open(sys.argv[1], "r") as fh:
        config = json.load(fh)

    service_name = config["service_name"]

    logging.basicConfig(level=logging.INFO)

    amqpService = AmqpService(config["amqp"])
    amqpLogger = AmqpLogHandler(service=amqpService, client_name=service_name)
    ddnsService = DdnsService(amqpService, **config["ddns"])

    run(amqpService, amqpLogger, ddnsService)

if __name__ == "__main__":
    main()