from aws_cdk import Stack
from aws_cdk import aws_dynamodb as dynamodb
from constructs import Construct


class DynamoDBStack(Stack):
    def __init__(self, scope: Construct, id: str, config, lambda_fn, **kwargs):
        super().__init__(scope, id, **kwargs)

        dynamo_config = config.get("services", {}).get("dynamodb", {})

        if not dynamo_config.get("enabled", False):
            print(
                "❌ DynamoDB no está habilitado en config.json. Omitiendo la creación de la tabla."
            )
            return

        table = dynamodb.Table(
            self,
            "DynamoTable",
            table_name=dynamo_config.get("table_name", "default-table"),
            partition_key=dynamodb.Attribute(
                name=dynamo_config.get("partition_key", "id"),
                type=dynamodb.AttributeType.STRING,
            ),
        )

        table.grant_read_write_data(lambda_fn)
