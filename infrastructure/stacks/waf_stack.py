from aws_cdk import Stack
from aws_cdk import aws_wafv2 as wafv2
from constructs import Construct


class WAFStack(Stack):
    def __init__(self, scope: Construct, id: str, config, **kwargs):
        super().__init__(scope, id, **kwargs)

        waf_config = config["services"]["waf"]
        if waf_config.get("enabled", False):
            waf_acl = wafv2.CfnWebACL(
                self,
                "WAF",
                name=waf_config["name"],
                default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
                scope="REGIONAL",
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    cloud_watch_metrics_enabled=True,
                    metric_name="waf-metrics",
                    sampled_requests_enabled=True,
                ),
            )
