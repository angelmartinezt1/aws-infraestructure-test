from aws_cdk import Stack
from aws_cdk import aws_sns as sns
from constructs import Construct


class SNSStack(Stack):
    def __init__(self, scope: Construct, id: str, config, lambda_fn, **kwargs):
        super().__init__(scope, id, **kwargs)

        sns_config = config.get("services", {}).get("sns", {})

        if not sns_config.get("enabled", False):
            print(
                "❌ SNS no está habilitado en config.json. Omitiendo la creación del tópico."
            )
            return

        topic = sns.Topic(
            self, "SNSTopic", topic_name=sns_config.get("topic_name", "default-topic")
        )
        topic.grant_publish(lambda_fn)
