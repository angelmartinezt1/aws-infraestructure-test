from aws_cdk import Stack
from aws_cdk import aws_cloudfront as cloudfront
from constructs import Construct


class CloudFrontStack(Stack):
    def __init__(self, scope: Construct, id: str, config, **kwargs):
        super().__init__(scope, id, **kwargs)

        cf_config = config["services"]["cloudfront"]
        if cf_config.get("enabled", False):
            distribution = cloudfront.CloudFrontWebDistribution(
                self,
                "CloudFrontDistribution",
                origin_configs=[
                    cloudfront.SourceConfiguration(
                        behaviors=[cloudfront.Behavior(is_default_behavior=True)],
                        origin_path="/",
                    )
                ],
            )
