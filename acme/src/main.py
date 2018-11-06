import sys
import json
import logging
from samp20.asyncservice import run
from samp20.asyncservice.logger import DictFormatter
from samp20.asyncservice.amqp import AmqpService, AmqpLogHandler
from acme import AcmeService


def main():
    with open(sys.argv[1], "r") as fh:
        config = json.load(fh)

    service_name = config["service_name"]

    logging.basicConfig(level=logging.INFO)

    amqpService = AmqpService(config["amqp"])
    amqpLogger = AmqpLogHandler(service=amqpService, client_name=service_name)
    acmeService = AcmeService(**config["acme"])

    run(amqpService, amqpLogger, acmeService)


if __name__ == "__main__":
    main()
