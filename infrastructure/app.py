import json
import sys
import os

from aws_cdk import App, Environment
from stacks.vpc_stack import VpcStack
from stacks.database_stack import DatabaseStack
from stacks.lambda_stack import LambdaStack
from stacks.dynamodb_stack import DynamoDBStack
from stacks.sqs_stack import SQSStack
from stacks.sns_stack import SNSStack
from stacks.s3_stack import S3Stack
from stacks.stepfunctions_stack import StepFunctionsStack
from stacks.cloudfront_stack import CloudFrontStack
from stacks.waf_stack import WAFStack

config_path = os.path.join(os.path.dirname(__file__), "config.json")

with open(config_path, "r") as f:
    config = json.load(f)

app = App()

# Crear stacks para cada entorno
for env_name, env_config in config["environments"].items():
    aws_env = Environment(account=env_config["account_id"], region=env_config["region"])

    # Stacks individuales
    vpc_stack = VpcStack(app, f"VpcStack-{env_name}", env_config, env=aws_env)
    db_stack = None
    if vpc_stack and vpc_stack.vpc:
        db_stack = DatabaseStack(
            app, f"DatabaseStack-{env_name}", env_config, vpc_stack.vpc, env=aws_env
        )
    lambda_stack = LambdaStack(
        app, f"LambdaStack-{env_name}", env_config, vpc_stack.vpc, db_stack, env=aws_env
    )
    DynamoDBStack(
        app,
        f"DynamoDBStack-{env_name}",
        env_config,
        lambda_stack.lambda_fn,
        env=aws_env,
    )
    SQSStack(
        app, f"SQSStack-{env_name}", env_config, lambda_stack.lambda_fn, env=aws_env
    )
    SNSStack(
        app, f"SNSStack-{env_name}", env_config, lambda_stack.lambda_fn, env=aws_env
    )
    S3Stack(app, f"S3Stack-{env_name}", env_config, lambda_stack.lambda_fn, env=aws_env)
    StepFunctionsStack(
        app,
        f"StepFunctionsStack-{env_name}",
        env_config,
        lambda_stack.lambda_fn,
        env=aws_env,
    )
    CloudFrontStack(app, f"CloudFrontStack-{env_name}", env_config, env=aws_env)
    WAFStack(app, f"WAFStack-{env_name}", env_config, env=aws_env)

app.synth()
