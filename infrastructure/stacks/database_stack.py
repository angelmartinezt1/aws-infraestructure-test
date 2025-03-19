from aws_cdk import Stack
from aws_cdk import aws_rds as rds
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_ec2 as ec2
from constructs import Construct


class DatabaseStack(Stack):
    def __init__(self, scope: Construct, id: str, config, vpc=None, **kwargs):
        super().__init__(scope, id, **kwargs)

        db_config = config.get("services", {}).get("aurora", {})

        if not db_config.get("enabled", False):
            print(
                "❌ Aurora no está habilitado en config.json. Omitiendo la creación de la base de datos."
            )
            return

        if vpc is None:
            print("⚠️ No hay VPC disponible. Omitiendo la creación de Aurora.")
            return

        self.aurora_secret = None

        if db_config.get("use_existing", False):
            self.aurora_secret = secretsmanager.Secret.from_secret_name_v2(
                self, "AuroraSecret", db_config["secret_name"]
            )
        else:
            self.aurora_secret = secretsmanager.Secret(
                self,
                "AuroraSecret",
                secret_name=db_config.get("secret_name", "default-secret"),
            )

            rds.DatabaseCluster(
                self,
                "AuroraCluster",
                engine=rds.DatabaseClusterEngine.AURORA_MYSQL,
                credentials=rds.Credentials.from_secret(self.aurora_secret),
                vpc=vpc,
                default_database_name=db_config.get("database_name", "defaultdb"),
            )
