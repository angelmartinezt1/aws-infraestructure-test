from aws_cdk import Stack
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_apigateway as apigateway
from constructs import Construct


class LambdaStack(Stack):
    def __init__(self, scope: Construct, id: str, config, vpc, db_stack, **kwargs):
        super().__init__(scope, id, **kwargs)

        lambda_config = config.get("services", {}).get("lambda", {})

        if not lambda_config.get("enabled", False):
            print(
                "❌ Lambda no está habilitada en config.json. Omitiendo la creación de la función Lambda."
            )
            return

        self.lambda_fn = _lambda.Function(
            self,
            "LambdaFunction",
            runtime=_lambda.Runtime.NODEJS_18_X,
            handler="app.handler",
            code=_lambda.Code.from_asset("./lambda"),
            vpc=vpc,
            environment={
                "CORS_ENABLED": lambda_config.get("cors_enabled", "false"),
            },
        )

        if lambda_config.get("api_gateway", {}).get("enabled", False):
            apigateway.LambdaRestApi(self, "ApiGateway", handler=self.lambda_fn)
