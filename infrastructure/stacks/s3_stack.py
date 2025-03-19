from aws_cdk import Stack
from aws_cdk import aws_s3 as s3
from constructs import Construct


class S3Stack(Stack):
    def __init__(self, scope: Construct, id: str, config, lambda_fn, **kwargs):
        super().__init__(scope, id, **kwargs)

        s3_config = config["services"]["s3"]
        if s3_config.get("enabled", False):
            bucket = s3.Bucket(
                self, "S3Bucket", bucket_name=s3_config["bucket_name"], versioned=True
            )

            bucket.grant_read_write(lambda_fn)
