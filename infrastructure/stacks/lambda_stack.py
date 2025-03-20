from aws_cdk import Stack, Duration
from aws_cdk import aws_lambda as _lambda
from constructs import Construct
from aws_cdk import aws_apigateway as apigateway


class LambdaStack(Stack):
    def __init__(
        self, scope: Construct, id: str, config, vpc=None, db_stack=None, **kwargs
    ):
        super().__init__(scope, id, **kwargs)

        lambda_config = config.get("services", {}).get("lambda", {})

        if not lambda_config.get("enabled", False):
            print(
                "❌ Lambda no está habilitado en config.json. Omitiendo la creación de la función Lambda."
            )
            return

        # Configurar variables de entorno desde config.json
        lambda_env = lambda_config.get("environment", {})

        self.lambda_fn = _lambda.Function(
            self,
            "ServiceLambda",
            function_name=lambda_config.get("function_name", "default-function"),
            runtime=_lambda.Runtime(lambda_config.get("runtime", "NODEJS_18_X")),
            handler="index.handler",  # O "app.handler" si usas Python
            code=_lambda.Code.from_asset("./lambda"),
            vpc=vpc if vpc and lambda_config.get("vpc_enabled", False) else None,
            environment=lambda_env,
            timeout=Duration.seconds(lambda_config.get("timeout", 30)),
            memory_size=lambda_config.get("memory_size", 1024),
            reserved_concurrent_executions=lambda_config.get(
                "reserved_concurrency", None
            ),
        )

        if lambda_config.get("api_gateway", {}).get("enabled", False):
            apigateway.LambdaRestApi(self, "ApiGateway", handler=self.lambda_fn)
