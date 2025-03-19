from aws_cdk import Stack
from aws_cdk import aws_stepfunctions as sfn
from constructs import Construct


class StepFunctionsStack(Stack):
    def __init__(self, scope: Construct, id: str, config, lambda_fn, **kwargs):
        super().__init__(scope, id, **kwargs)

        sf_config = config["services"]["step_functions"]
        if sf_config.get("enabled", False):
            state_machine = sfn.StateMachine(
                self,
                "StateMachine",
                state_machine_name=sf_config["name"],
                definition=sfn.Pass(self, "StartState"),
            )
