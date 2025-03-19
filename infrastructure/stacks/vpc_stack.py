from aws_cdk import Stack
from aws_cdk import aws_ec2 as ec2
from constructs import Construct


class VpcStack(Stack):
    def __init__(self, scope: Construct, id: str, config, **kwargs):
        super().__init__(scope, id, **kwargs)

        vpc_config = config.get("services", {}).get("vpc", {})

        # Siempre define self.vpc aunque no se cree la VPC
        self.vpc = None

        if not vpc_config.get("enabled", False):
            print(
                "❌ VPC no está habilitada en config.json. Omitiendo la creación de la VPC."
            )
            return

        if vpc_config.get("use_existing", False):
            self.vpc = ec2.Vpc.from_lookup(
                self, "ExistingVPC", vpc_id=vpc_config["vpc_id"]
            )
        else:
            self.vpc = ec2.Vpc(
                self,
                "NewVPC",
                max_azs=2,
                subnet_configuration=[
                    ec2.SubnetConfiguration(
                        name="public", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24
                    ),
                    ec2.SubnetConfiguration(
                        name="private",
                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                        cidr_mask=24,
                    ),
                ],
            )
