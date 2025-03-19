from aws_cdk import Stack
from aws_cdk import aws_sqs as sqs
from constructs import Construct


class SQSStack(Stack):
    def __init__(self, scope: Construct, id: str, config, lambda_fn, **kwargs):
        super().__init__(scope, id, **kwargs)

        sqs_config = config.get("services", {}).get("sqs", {})

        if not sqs_config.get("enabled", False):
            print(
                "❌ SQS no está habilitado en config.json. Omitiendo la creación de la cola."
            )
            return

        queue = sqs.Queue(
            self, "SQSQueue", queue_name=sqs_config.get("queue_name", "default-queue")
        )
        queue.grant_send_messages(lambda_fn)
