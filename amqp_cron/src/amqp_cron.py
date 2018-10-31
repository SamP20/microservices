import ast
import json
import sys
import os
import asyncio
import logging
import aio_pika
import msgpack
from heapq import heappush, heappop, heappushpop, heapreplace
from datetime import datetime
from dateutil.rrule import rrule, rrulestr
from samp20.asyncservice import run
from samp20.asyncservice.amqp import AmqpService, AmqpLogHandler

class CronTask:
    def __init__(self, exchange, routing_key, body, rule_str, now):
        self.exchange = exchange
        self.routing_key = routing_key
        self.body = msgpack.packb(body, use_bin_type=True, default=str)
        self.rrule_iter = iter(rrulestr(rule_str))
        self.due = next(self.rrule_iter)
        self.next_occurence(now)

    def next_occurence(self, now):
        while now >= self.due:
            self.due = next(self.rrule_iter)
        return self.due

    async def run(self):
        await self.exchange.publish(
            aio_pika.Message(body=self.body, delivery_mode=aio_pika.DeliveryMode.PERSISTENT),
            content_type='application/msgpack',
            routing_key=self.routing_key,
        )

    def __lt__(self, other):
        return self.due < other.due


class AmqpCronService:
    def __init__(self, amqp, cronfile):
        self.amqp = amqp
        self.cronfile = cronfile
        self.log = logging.getLogger("amqp_send")

    async def start(self):
        self.channel = await self.amqp.channel()
        self.exchange = await self.channel.declare_exchange(
            name="amq.topic", type=aio_pika.ExchangeType.TOPIC, durable=True
        )

        now = datetime.now()

        self.tasks = []
        for task in self.cronfile["tasks"]:
            routing_key = task["routing_key"]
            body = task["body"]
            rule_str = task["rrule"]
            heappush(self.tasks, CronTask(self.exchange, routing_key, body,  rule_str, now))

        self.poll_future = asyncio.create_task(self.do_poll())
        self.task_future = None

    async def stop(self):
        self.poll_future.cancel()
        try:
            await self.poll_future
        except asyncio.CancelledError:
            pass
        if self.task_future is not None:
            await self.task_future
        await self.channel.close()

    async def do_poll(self):
        task = None
        while True:
            task = heappop(self.tasks)
            now = datetime.now()
            if now >= task.due:
                self.task_future = asyncio.create_task(task.run())
                await asyncio.shield(self.task_future)
                self.task_future = None
                task.next_occurence(now)
                heappush(self.tasks, task)
            else:
                await asyncio.sleep((task.due-now).total_seconds())


def main():
    with open(sys.argv[1], "r") as fh:
        config = json.load(fh)

    with open(config["cronfile"], "r") as fh:
        cronfile = json.load(fh)

    service_name = config["service_name"]

    logging.basicConfig(level=logging.INFO)

    amqpService = AmqpService(config["amqp"])
    amqpLogger = AmqpLogHandler(service=amqpService, client_name=service_name)
    amqpCron = AmqpCronService(amqpService, cronfile)

    run(amqpService, amqpLogger, amqpCron)


if __name__ == "__main__":
    main()
