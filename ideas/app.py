# infrastructure/app.py
import os
from aws_cdk import (
    App,
    Stack,
    Duration,
    RemovalPolicy,
    Environment,
    aws_lambda as _lambda,
    aws_ec2 as ec2,
    aws_rds as rds,
    aws_secretsmanager as secretsmanager,
    aws_iam as iam,
    aws_dynamodb as dynamodb,
    aws_sqs as sqs,
    aws_sns as sns,
    aws_s3 as s3,
    aws_ssm as ssm,
    aws_elasticache as elasticache,
    aws_apigateway as apigateway,
    aws_stepfunctions as sfn,
    aws_events as events,
    aws_events_targets as targets,
    aws_cloudfront as cloudfront,
    aws_wafv2 as wafv2
)
from constructs import Construct
import json

class ConfigLoader:
    def __init__(self, config_path):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
    
    def get_environment_config(self, env_name):
        return self.config['environments'][env_name]
    
    def get_service_name(self):
        return self.config['service_name']

class MicroserviceInfrastructureStack(Stack):
    def __init__(self, scope: Construct, id: str, service_name: str, env_config, **kwargs):
        super().__init__(scope, id, **kwargs)
        
        # Extract configuration
        service_config = env_config['services']
        vpc = None
        lambda_fn = None
        
        # Setup VPC if enabled
        if service_config.get('vpc', {}).get('enabled', False):
            if service_config['vpc'].get('use_existing', False):
                vpc = ec2.Vpc.from_lookup(
                    self, "VPC",
                    vpc_id=service_config['vpc']['vpc_id']
                )
            else:
                # Create new VPC
                vpc = ec2.Vpc(
                    self, "VPC",
                    max_azs=2,
                    subnet_configuration=[
                        ec2.SubnetConfiguration(
                            name="public",
                            subnet_type=ec2.SubnetType.PUBLIC,
                            cidr_mask=24
                        ),
                        ec2.SubnetConfiguration(
                            name="private",
                            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                            cidr_mask=24
                        )
                    ]
                )
        
        # Setup Aurora if enabled
        aurora_secret = None
        if service_config.get('aurora', {}).get('enabled', False):
            if service_config['aurora'].get('use_existing', False):
                aurora_secret = secretsmanager.Secret.from_secret_name_v2(
                    self, "AuroraSecret",
                    service_config['aurora']['secret_name']
                )
            else:
                # Create Aurora cluster (implementation omitted for brevity)
                pass
        
        # Setup MongoDB Secret if enabled
        mongo_secret = None
        if service_config.get('mongo', {}).get('enabled', False):
            if service_config['mongo'].get('use_existing', False):
                mongo_secret = secretsmanager.Secret.from_secret_name_v2(
                    self, "MongoSecret",
                    service_config['mongo']['secret_name']
                )
            else:
                # Create MongoDB Secret (implementation omitted for brevity)
                pass
        
        # Setup environment variables
        lambda_env = {}
        if service_config.get('env_variables'):
            lambda_env.update(service_config['env_variables'])
        
        # Add secrets to environment if configured
        if service_config.get('aurora', {}).get('enabled', False):
            lambda_env["AURORA_SECRET_NAME"] = service_config['aurora']['secret_name']
        
        if service_config.get('mongo', {}).get('enabled', False):
            lambda_env["MONGO_SECRET_NAME"] = service_config['mongo']['secret_name']
        
        # Create Lambda function if enabled
        if service_config.get('lambda', {}).get('enabled', False):
            lambda_config = service_config['lambda']
            
            lambda_fn = _lambda.Function(
                self, "ServiceLambda",
                function_name=lambda_config['function_name'],
                runtime=_lambda.Runtime(lambda_config.get('runtime', 'nodejs18.x')),
                handler="app.handler",
                code=_lambda.Code.from_asset("../lambda"),
                vpc=vpc if vpc and service_config.get('vpc', {}).get('enabled', False) else None,
                environment=lambda_env,
                timeout=Duration.seconds(lambda_config.get('timeout', 30)),
                memory_size=lambda_config.get('memory_size', 1024),
                reserved_concurrent_executions=lambda_config.get('reserved_concurrency', -1)
            )
            
            # Create API Gateway if enabled
            if lambda_config.get('api_gateway', {}).get('enabled', False):
                api = apigateway.RestApi(
                    self, "ServiceApi",
                    rest_api_name=f"{service_name}-api",
                    description=f"API Gateway for {service_name}",
                    deploy_options=apigateway.StageOptions(
                        stage_name=env_config['profile']
                    )
                )
                
                integration = apigateway.LambdaIntegration(lambda_fn)
                api.root.add_proxy(
                    default_integration=integration,
                    any_method=True
                )
                
                # Enable CORS if requested
                if lambda_config['api_gateway'].get('cors', False):
                    api.root.add_cors_preflight(
                        allow_origins=["*"],
                        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                        allow_headers=["*"]
                    )
            
            # Create Lambda version and alias
            version = lambda_fn.current_version
            alias = _lambda.Alias(
                self, "LambdaAlias",
                alias_name=lambda_config['alias'],
                version=version
            )
            
            # Setup provisioned concurrency if configured
            if lambda_config.get('provisioned_concurrency', 0) > 0:
                alias.add_auto_scaling(
                    min_capacity=1,
                    max_capacity=lambda_config['provisioned_concurrency']
                )
        
        # Grant secret access if applicable
        if lambda_fn and aurora_secret:
            aurora_secret.grant_read(lambda_fn)
        
        if lambda_fn and mongo_secret:
            mongo_secret.grant_read(lambda_fn)
        
        # Create DynamoDB tables if enabled
        if service_config.get('dynamodb', {}).get('enabled', False) and lambda_fn:
            for table_config in service_config['dynamodb']['tables']:
                partition_key_props = table_config['partition_key']
                sort_key_props = table_config.get('sort_key')
                
                # Determine attribute type
                attribute_type_map = {
                    'string': dynamodb.AttributeType.STRING,
                    'number': dynamodb.AttributeType.NUMBER,
                    'binary': dynamodb.AttributeType.BINARY
                }
                
                partition_key_type = attribute_type_map.get(
                    partition_key_props.get('type', 'string').lower(), 
                    dynamodb.AttributeType.STRING
                )
                
                # Create table parameters
                table_params = {
                    "table_name": table_config['name'],
                    "partition_key": dynamodb.Attribute(
                        name=partition_key_props['name'],
                        type=partition_key_type
                    ),
                    "removal_policy": RemovalPolicy.RETAIN if env_config['profile'] == 'prod' else RemovalPolicy.DESTROY,
                    "point_in_time_recovery": table_config.get('point_in_time_recovery', False)
                }
                
                # Add sort key if specified
                if sort_key_props:
                    sort_key_type = attribute_type_map.get(
                        sort_key_props.get('type', 'string').lower(), 
                        dynamodb.AttributeType.STRING
                    )
                    table_params["sort_key"] = dynamodb.Attribute(
                        name=sort_key_props['name'],
                        type=sort_key_type
                    )
                
                # Configure billing mode
                if table_config.get('billing_mode', 'PAY_PER_REQUEST').upper() == 'PROVISIONED':
                    table_params["billing_mode"] = dynamodb.BillingMode.PROVISIONED
                    table_params["read_capacity"] = table_config.get('read_capacity', 5)
                    table_params["write_capacity"] = table_config.get('write_capacity', 5)
                else:
                    table_params["billing_mode"] = dynamodb.BillingMode.PAY_PER_REQUEST
                
                # Add stream configuration if enabled
                if table_config.get('stream_enabled', False):
                    stream_view_types = {
                        'NEW_IMAGE': dynamodb.StreamViewType.NEW_IMAGE,
                        'OLD_IMAGE': dynamodb.StreamViewType.OLD_IMAGE,
                        'NEW_AND_OLD_IMAGES': dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
                        'KEYS_ONLY': dynamodb.StreamViewType.KEYS_ONLY
                    }
                    view_type = table_config.get('stream_view_type', 'NEW_AND_OLD_IMAGES')
                    table_params["stream"] = stream_view_types.get(
                        view_type,
                        dynamodb.StreamViewType.NEW_AND_OLD_IMAGES
                    )
                
                # Create the table
                table = dynamodb.Table(
                    self, f"Table-{table_config['name']}",
                    **table_params
                )
                
                # Add TTL if specified
                if table_config.get('ttl_attribute'):
                    table.add_time_to_live_attribute(
                        attribute_name=table_config['ttl_attribute']
                    )
                
                # Add GSIs if specified
                if table_config.get('gsi'):
                    for gsi_config in table_config['gsi']:
                        gsi_partition_key_props = gsi_config['partition_key']
                        gsi_sort_key_props = gsi_config.get('sort_key')
                        
                        gsi_partition_key_type = attribute_type_map.get(
                            gsi_partition_key_props.get('type', 'string').lower(), 
                            dynamodb.AttributeType.STRING
                        )
                        
                        # Create GSI parameters
                        gsi_params = {
                            "index_name": gsi_config['name'],
                            "partition_key": dynamodb.Attribute(
                                name=gsi_partition_key_props['name'],
                                type=gsi_partition_key_type
                            ),
                            "projection_type": getattr(
                                dynamodb.ProjectionType, 
                                gsi_config.get('projection_type', 'ALL')
                            )
                        }
                        
                        # Add sort key if specified
                        if gsi_sort_key_props:
                            gsi_sort_key_type = attribute_type_map.get(
                                gsi_sort_key_props.get('type', 'string').lower(), 
                                dynamodb.AttributeType.STRING
                            )
                            gsi_params["sort_key"] = dynamodb.Attribute(
                                name=gsi_sort_key_props['name'],
                                type=gsi_sort_key_type
                            )
                        
                        # Configure read/write capacity if using provisioned billing
                        if table_params.get("billing_mode") == dynamodb.BillingMode.PROVISIONED:
                            gsi_params["read_capacity"] = gsi_config.get('read_capacity', 5)
                            gsi_params["write_capacity"] = gsi_config.get('write_capacity', 5)
                        
                        # Add the GSI to the table
                        table.add_global_secondary_index(**gsi_params)
                
                # Grant Lambda access to the table
                table.grant_read_write_data(lambda_fn)
        
        # Create SQS queues if enabled
        if service_config.get('sqs', {}).get('enabled', False) and lambda_fn:
            for queue_config in service_config['sqs']['queues']:
                queue_props = {
                    "queue_name": queue_config['name'],
                    "visibility_timeout": Duration.seconds(queue_config.get('visibility_timeout', 30)),
                    "retention_period": Duration.seconds(queue_config.get('message_retention_seconds', 345600))
                }
                
                # Configure FIFO if requested
                if queue_config.get('fifo', False):
                    queue_props["fifo"] = True
                    if not queue_props["queue_name"].endswith(".fifo"):
                        queue_props["queue_name"] += ".fifo"
                
                # Create the queue
                queue = sqs.Queue(
                    self, f"Queue-{queue_config['name']}",
                    **queue_props
                )
                
                # Create DLQ if enabled
                if queue_config.get('dlq', {}).get('enabled', False):
                    dlq_props = {
                        "queue_name": f"dlq-{queue_config['name']}",
                        "retention_period": Duration.days(14)
                    }
                    
                    if queue_props.get("fifo", False):
                        dlq_props["fifo"] = True
                        if not dlq_props["queue_name"].endswith(".fifo"):
                            dlq_props["queue_name"] += ".fifo"
                    
                    dlq = sqs.Queue(
                        self, f"DLQ-{queue_config['name']}",
                        **dlq_props
                    )
                    
                    # Configure redrive policy
                    queue.add_redrive_policy(
                        max_receive_count=queue_config['dlq'].get('max_receive_count', 3),
                        dead_letter_queue=dlq
                    )
                
                # Grant Lambda access to the queue
                queue.grant_send_messages(lambda_fn)
                queue.grant_consume_messages(lambda_fn)
        
        # Create SNS topics if enabled
        if service_config.get('sns', {}).get('enabled', False) and lambda_fn:
            for topic_config in service_config['sns']['topics']:
                topic_props = {
                    "topic_name": topic_config['name']
                }
                
                # Configure FIFO if requested
                if topic_config.get('fifo', False):
                    topic_props["fifo"] = True
                    if not topic_props["topic_name"].endswith(".fifo"):
                        topic_props["topic_name"] += ".fifo"
                
                # Create the topic
                topic = sns.Topic(
                    self, f"Topic-{topic_config['name']}",
                    **topic_props
                )
                
                # Set up subscriptions if specified
                if topic_config.get('subscriptions'):
                    for sub_config in topic_config['subscriptions']:
                        protocol = sub_config['protocol']
                        endpoint = sub_config['endpoint']
                        
                        # Handle SQS subscriptions
                        if protocol == 'sqs':
                            # Find the queue by name
                            queue_id = f"Queue-{endpoint}"
                            if queue_id in self.node.find_all():
                                queue = self.node.find_child(queue_id)
                                topic.add_subscription(sns.SqsSubscription(queue))
                
                # Grant Lambda access to the topic
                topic.grant_publish(lambda_fn)
        
        # Create S3 buckets if enabled
        if service_config.get('s3', {}).get('enabled', False) and lambda_fn:
            for bucket_config in service_config['s3']['buckets']:
                bucket_props = {
                    "bucket_name": bucket_config['name'],
                    "removal_policy": RemovalPolicy.RETAIN, 
                    "auto_delete_objects": False, # Never auto-delete in production
                    "versioned": bucket_config.get('versioning', False)
                }
                
                # Encryption configuration
                encryption_type = bucket_config.get('encryption')
                if encryption_type:
                    if encryption_type == 'AES256':
                        bucket_props["encryption"] = s3.BucketEncryption.S3_MANAGED
                    elif encryption_type == 'KMS':
                        bucket_props["encryption"] = s3.BucketEncryption.KMS_MANAGED
                
                # Create the bucket
                bucket = s3.Bucket(
                    self, f"Bucket-{bucket_config['name']}",
                    **bucket_props
                )
                
                # Configure CORS if requested
                if bucket_config.get('cors_enabled', False):
                    bucket.add_cors_rule(
                        allowed_methods=[
                            s3.HttpMethods.GET,
                            s3.HttpMethods.PUT,
                            s3.HttpMethods.POST,
                            s3.HttpMethods.DELETE,
                            s3.HttpMethods.HEAD
                        ],
                        allowed_origins=["*"],
                        allowed_headers=["*"]
                    )
                
                # Configure public access if requested
                if bucket_config.get('public_read', False):
                    bucket.grant_public_access()
                
                # Configure lifecycle rules if specified
                if bucket_config.get('lifecycle_rules'):
                    for rule_config in bucket_config['lifecycle_rules']:
                        bucket.add_lifecycle_rule(
                            prefix=rule_config.get('prefix', ''),
                            expiration=Duration.days(rule_config.get('expiration_days', 365))
                        )
                
                # Grant Lambda access to the bucket
                bucket.grant_read_write(lambda_fn)
        
        # Create Redis ElastiCache if enabled
        if service_config.get('redis', {}).get('enabled', False) and vpc:
            redis_config = service_config['redis']
            
            if not redis_config.get('use_existing', False):
                # Create security group for Redis
                redis_sg = ec2.SecurityGroup(
                    self, "RedisSecurityGroup",
                    vpc=vpc,
                    description="Security group for Redis ElastiCache"
                )
                
                # Create subnet group
                subnet_group = elasticache.CfnSubnetGroup(
                    self, "RedisSubnetGroup",
                    description=f"Subnet group for {service_name} Redis",
                    subnet_ids=vpc.private_subnets.map(lambda s: s.subnet_id)
                )
                
                # Create Redis cluster
                redis = elasticache.CfnCacheCluster(
                    self, "RedisCluster",
                    cache_node_type=redis_config.get('node_type', 'cache.t3.micro'),
                    engine="redis",
                    num_cache_nodes=redis_config.get('num_nodes', 1),
                    cache_subnet_group_name=subnet_group.ref,
                    vpc_security_group_ids=[redis_sg.security_group_id]
                )
                
                # Allow Lambda to connect to Redis
                if lambda_fn:
                    redis_sg.add_ingress_rule(
                        ec2.Peer.security_group_id(lambda_fn.connections.security_groups[0].security_group_id),
                        ec2.Port.tcp(6379),
                        "Allow Lambda to connect to Redis"
                    )
                    
                   # infrastructure/app.py (continued from existing code)

                # Store Redis endpoint in SSM Parameter Store
                redis_endpoint = ssm.StringParameter(
                    self, "RedisEndpoint",
                    parameter_name=f"/{env_config['profile']}/{service_name}/redis-endpoint",
                    string_value=redis.attr_redis_endpoint_address,
                    description=f"Redis endpoint for {service_name}"
                )
                
                # Add Redis endpoint to Lambda environment variables
                if lambda_fn:
                    lambda_fn.add_environment("REDIS_ENDPOINT", redis_endpoint.string_value)
        
        # Create Step Functions state machines if enabled
        if service_config.get('step_functions', {}).get('enabled', False) and lambda_fn:
            for state_machine_config in service_config['step_functions']['state_machines']:
                # Load state machine definition from file
                with open(state_machine_config['definition_file'], 'r') as f:
                    definition = json.load(f)
                
                # Create the state machine
                state_machine = sfn.CfnStateMachine(
                    self, f"StateMachine-{state_machine_config['name']}",
                    state_machine_name=state_machine_config['name'],
                    definition=definition,
                    role_arn=lambda_fn.role.role_arn
                )
                
                # Store state machine ARN in SSM Parameter Store
                ssm.StringParameter(
                    self, f"StateMachineArn-{state_machine_config['name']}",
                    parameter_name=f"/{env_config['profile']}/{service_name}/state-machine/{state_machine_config['name']}",
                    string_value=state_machine.attr_arn,
                    description=f"State machine ARN for {state_machine_config['name']}"
                )
        
        # Create EventBridge rules if enabled
        if service_config.get('event_bridge', {}).get('enabled', False) and lambda_fn:
            for rule_config in service_config['event_bridge']['rules']:
                # Create the rule
                rule = events.Rule(
                    self, f"Rule-{rule_config['name']}",
                    rule_name=rule_config['name'],
                    schedule=events.Schedule.expression(rule_config['schedule'])
                )
                
                # Add target to the rule
                if rule_config.get('target', {}).get('lambda'):
                    target_lambda_name = rule_config['target']['lambda']
                    # Assuming the target Lambda function is already created
                    target_lambda = _lambda.Function.from_function_name(
                        self, f"TargetLambda-{target_lambda_name}",
                        function_name=target_lambda_name
                    )
                    rule.add_target(targets.LambdaFunction(target_lambda))
        
        # Create CloudFront distribution if enabled
        if service_config.get('cloudfront', {}).get('enabled', False):
            cloudfront_config = service_config['cloudfront']['distribution']
            
            # Create origins
            origins = []
            for origin_config in cloudfront_config.get('origins', []):
                # Create origin identity
                origin = cloudfront.OriginConfig(
                    domain_name=origin_config['domain_name'],
                    id=origin_config['id'],
                    origin_path=origin_config.get('origin_path', '')
                )
                origins.append(origin)
            
            # Create distribution
            distribution = cloudfront.CloudFrontWebDistribution(
                self, "CloudFrontDistribution",
                comment=cloudfront_config.get('comment', f"CloudFront distribution for {service_name}"),
                price_class=getattr(
                    cloudfront.PriceClass, 
                    cloudfront_config.get('price_class', 'PRICE_CLASS_100')
                ),
                origin_configs=origins,
                default_root_object=cloudfront_config.get('default_root_object', '')
            )
            
            # Store distribution domain name in SSM Parameter Store
            ssm.StringParameter(
                self, "CloudFrontDomain",
                parameter_name=f"/{env_config['profile']}/{service_name}/cloudfront-domain",
                string_value=distribution.distribution_domain_name,
                description=f"CloudFront domain for {service_name}"
            )
        
        # Create WAF if enabled
        if service_config.get('waf', {}).get('enabled', False):
            waf_config = service_config['waf']['acl']
            
            # Create WAF rules
            rules = []
            for rule_config in waf_config.get('rules', []):
                waf_rule = wafv2.CfnWebACL.RuleProperty(
                    name=rule_config['name'],
                    priority=rule_config['priority'],
                    action=wafv2.CfnWebACL.RuleActionProperty(
                        block={} if rule_config['action'] == 'block' else None,
                        allow={} if rule_config['action'] == 'allow' else None,
                        count={} if rule_config['action'] == 'count' else None
                    ),
                    statement=self._create_waf_statement(rule_config['statement'])
                )
                rules.append(waf_rule)
            
            # Create WAF ACL
            waf_acl = wafv2.CfnWebACL(
                self, "WAF",
                name=f"{service_name}-waf",
                default_action=wafv2.CfnWebACL.DefaultActionProperty(
                    allow={} if waf_config.get('default_action', 'allow') == 'allow' else None,
                    block={} if waf_config.get('default_action', 'allow') == 'block' else None
                ),
                scope="REGIONAL",
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    cloud_watch_metrics_enabled=True,
                    metric_name=f"{service_name}-waf-metrics",
                    sampled_requests_enabled=True
                ),
                rules=rules
            )
            
            # Store WAF ARN in SSM Parameter Store
            ssm.StringParameter(
                self, "WafArn",
                parameter_name=f"/{env_config['profile']}/{service_name}/waf-arn",
                string_value=waf_acl.attr_arn,
                description=f"WAF ACL ARN for {service_name}"
            )
    
    def _create_waf_statement(self, statement_config):
        """Helper method to create WAF statement based on config"""
        if 'rate_based' in statement_config:
            return wafv2.CfnWebACL.StatementProperty(
                rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                    limit=statement_config['rate_based']['limit'],
                    aggregate_key_type=statement_config['rate_based']['aggregate_key_type']
                )
            )
        # Add other statement types as needed
        return None


# Main application entry point
app = App()

# Load configuration
config_loader = ConfigLoader("config.json")
service_name = config_loader.get_service_name()

# Create stacks for each environment
for env_name in config_loader.config['environments']:
    env_config = config_loader.get_environment_config(env_name)
    
    MicroserviceInfrastructureStack(
        app,
        f"{service_name}-{env_name}",
        service_name,
        env_config,
        env=Environment(
            account=env_config['account_id'],
            region=env_config['region']
        )
    )

app.synth()