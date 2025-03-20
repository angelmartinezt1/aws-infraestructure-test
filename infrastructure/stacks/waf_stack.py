from aws_cdk import Stack
from aws_cdk import aws_wafv2 as wafv2
from constructs import Construct


class WAFStack(Stack):
    def __init__(self, scope: Construct, id: str, config, **kwargs):
        super().__init__(scope, id, **kwargs)

        waf_config = config.get("services", {}).get("waf", {})

        if not waf_config.get("enabled", False):
            print(
                "❌ WAF no está habilitado en config.json. Omitiendo la creación del WAF."
            )
            return

        rules = []
        for rule_config in waf_config.get("rules", []):
            rule = wafv2.CfnWebACL.RuleProperty(
                name=rule_config["name"],
                priority=rule_config["priority"],
                action=wafv2.CfnWebACL.RuleActionProperty(
                    block={} if rule_config["action"] == "block" else None,
                    allow={} if rule_config["action"] == "allow" else None,
                    count={} if rule_config["action"] == "count" else None,
                ),
                statement=self._create_waf_statement(rule_config["statement"]),
            )
            rules.append(rule)

        waf_acl = wafv2.CfnWebACL(
            self,
            "WAF",
            name=waf_config.get("name", "default-waf"),
            default_action=wafv2.CfnWebACL.DefaultActionProperty(
                allow=(
                    {} if waf_config.get("default_action", "allow") == "allow" else None
                ),
                block=(
                    {} if waf_config.get("default_action", "allow") == "block" else None
                ),
            ),
            scope="REGIONAL",
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="waf-metrics",
                sampled_requests_enabled=True,
            ),
            rules=rules,
        )

    def _create_waf_statement(self, statement_config):
        """Helper method para crear una declaración de WAF"""
        if "rate_based" in statement_config:
            return wafv2.CfnWebACL.StatementProperty(
                rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                    limit=statement_config["rate_based"]["limit"],
                    aggregate_key_type=statement_config["rate_based"][
                        "aggregate_key_type"
                    ],
                )
            )
        return None
