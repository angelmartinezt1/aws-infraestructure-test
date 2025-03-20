from aws_cdk import Stack
from aws_cdk import aws_cloudfront as cloudfront
from constructs import Construct


class CloudFrontStack(Stack):
    def __init__(self, scope: Construct, id: str, config, **kwargs):
        super().__init__(scope, id, **kwargs)

        cf_config = config.get("services", {}).get("cloudfront", {})

        if not cf_config.get("enabled", False):
            print(
                "❌ CloudFront no está habilitado en config.json. Omitiendo la creación de la distribución."
            )
            return

        self.distribution = cloudfront.CloudFrontWebDistribution(
            self,
            "CloudFrontDistribution",
            comment="CloudFront distribution for the application",
            price_class=getattr(
                cloudfront.PriceClass, cf_config.get("price_class", "PRICE_CLASS_100")
            ),
            origin_configs=[
                cloudfront.SourceConfiguration(
                    behaviors=[cloudfront.Behavior(is_default_behavior=True)],
                    origin_path="/",
                )
            ],
            default_root_object=cf_config.get("default_root_object", "index.html"),
        )
