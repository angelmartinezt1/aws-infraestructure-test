from aws_cdk import Stack
from aws_cdk import aws_stepfunctions as sfn
from constructs import Construct


class StepFunctionsStack(Stack):
    def __init__(self, scope: Construct, id: str, config, lambda_fn=None, **kwargs):
        super().__init__(scope, id, **kwargs)

        sf_config = config.get("services", {}).get("step_functions", {})

        if not sf_config.get("enabled", False):
            print(
                "❌ Step Functions no está habilitado en config.json. Omitiendo la creación de la máquina de estado."
            )
            return

        state_machine_name = sf_config.get("name", "default-step-function")

        state_machine = sfn.StateMachine(
            self,
            "StateMachine",
            state_machine_name=state_machine_name,
            definition=sfn.Pass(self, "StartState"),
        )
