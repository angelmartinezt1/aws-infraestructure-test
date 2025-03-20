from aws_cdk import Stack
from aws_cdk import aws_s3 as s3
from constructs import Construct


class S3Stack(Stack):
    def __init__(self, scope: Construct, id: str, config, lambda_fn=None, **kwargs):
        super().__init__(scope, id, **kwargs)

        s3_config = config.get("services", {}).get("s3", {})

        if not s3_config.get("enabled", False):
            print(
                "❌ S3 no está habilitado en config.json. Omitiendo la creación del bucket."
            )
            return

        bucket_name = s3_config.get("bucket_name", "default-bucket")

        bucket = s3.Bucket(
            self,
            "S3Bucket",
            bucket_name=bucket_name,
            versioned=s3_config.get("versioning", False),
        )

        if lambda_fn:
            bucket.grant_read_write(lambda_fn)
