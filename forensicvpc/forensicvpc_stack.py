from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_dynamodb as _dynamodb,
    aws_ec2 as _ec2,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_glue_alpha as _glue,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_logs_destinations as _destinations,
    aws_s3 as _s3,
    aws_s3_notifications as _notifications,
    aws_sns as _sns,
    aws_sns_subscriptions as _subs,
    aws_ssm as _ssm,
    aws_stepfunctions as _sfn,
    aws_stepfunctions_tasks as _tasks
)

from constructs import Construct

class ForensicvpcStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

### LAYER ###

        if region == 'ap-northeast-1' or region == 'ap-south-1' or region == 'ap-southeast-1' or \
            region == 'ap-southeast-2' or region == 'eu-central-1' or region == 'eu-west-1' or \
            region == 'eu-west-2' or region == 'me-central-1' or region == 'us-east-1' or \
            region == 'us-east-2' or region == 'us-west-2': number = str(1)

        if region == 'af-south-1' or region == 'ap-east-1' or region == 'ap-northeast-2' or \
            region == 'ap-northeast-3' or region == 'ap-southeast-3' or region == 'ca-central-1' or \
            region == 'eu-north-1' or region == 'eu-south-1' or region == 'eu-west-3' or \
            region == 'me-south-1' or region == 'sa-east-1' or region == 'us-west-1': number = str(2)

        layer = _lambda.LayerVersion.from_layer_version_arn(
            self, 'layer',
            layer_version_arn = 'arn:aws:lambda:'+region+':070176467818:layer:getpublicip:'+number
        )

### ERROR ###

        error = _lambda.Function.from_function_arn(
            self, 'error',
            'arn:aws:lambda:'+region+':'+account+':function:shipit-error'
        )

        timeout = _lambda.Function.from_function_arn(
            self, 'timeout',
            'arn:aws:lambda:'+region+':'+account+':function:shipit-timeout'
        )

### VPC ###

        vpc = _ec2.Vpc(
            self, 'vpc',
            cidr = '10.255.255.0/24',
            max_azs = 1,
            nat_gateways = 0,
            enable_dns_hostnames = True,
            enable_dns_support = True,
            subnet_configuration = [
                _ec2.SubnetConfiguration(
                    cidr_mask = 24,
                    name = 'Public',
                    subnet_type = _ec2.SubnetType.PUBLIC
                )
            ],
            gateway_endpoints = {
                'S3': _ec2.GatewayVpcEndpointOptions(
                    service = _ec2.GatewayVpcEndpointAwsService.S3
                )
            }
        )

### NACL ###

        nacl = _ec2.NetworkAcl(
            self, 'nacl',
            vpc = vpc
        )

        nacl.add_entry(
            'ingress100',
            rule_number = 100,
            cidr = _ec2.AclCidr.ipv4('0.0.0.0/0'),
            traffic = _ec2.AclTraffic.all_traffic(),
            rule_action = _ec2.Action.ALLOW,
            direction = _ec2.TrafficDirection.INGRESS
        )

        nacl.add_entry(
            'egress100',
            rule_number = 100,
            cidr = _ec2.AclCidr.ipv4('0.0.0.0/0'),
            traffic = _ec2.AclTraffic.all_traffic(),
            rule_action = _ec2.Action.ALLOW,
            direction = _ec2.TrafficDirection.EGRESS
        )

### FLOWS ###

        flows_name = 'forensicvpc-flow-logs-'+str(account)+'-'+region

        flows = _s3.Bucket(
            self, 'flows',
            bucket_name = flows_name,
            encryption = _s3.BucketEncryption.S3_MANAGED,
            block_public_access = _s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            versioned = True
        )

        flows.add_lifecycle_rule(
            expiration = Duration.days(403),
            noncurrent_version_expiration = Duration.days(1)
        )

        vpcflow = _ec2.CfnFlowLog(
            self, 'vpcflow',
            resource_id = vpc.vpc_id,
            resource_type = 'VPC',
            traffic_type = 'ALL',
            log_destination_type = 's3',
            log_destination = flows.bucket_arn,
            max_aggregation_interval = 600,
            log_format = '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${sublocation-type} ${sublocation-id} ${pkt-src-aws-service} ${pkt-dst-aws-service} ${flow-direction} ${traffic-path}',
            destination_options = {
                'FileFormat': 'parquet',
                'HiveCompatiblePartitions': 'true',
                'PerHourPartition': 'true'
            }
        )

### ATHENA ###

        athena_name = 'forensicvpc-athena-'+str(account)+'-'+region

        athena = _s3.Bucket(
            self, 'athena',
            bucket_name = athena_name,
            encryption = _s3.BucketEncryption.S3_MANAGED,
            block_public_access = _s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            versioned = True
        )

        athena.add_lifecycle_rule(
            expiration = Duration.days(1),
            noncurrent_version_expiration = Duration.days(1)
        )

### IAM ###

        glue = _iam.Role(
            self, 'glue',
            assumed_by = _iam.ServicePrincipal('glue.amazonaws.com')
        ) 

        glue.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSGlueServiceRole'
            )
        )

        glue.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    's3:GetObject'
                ],
                resources = [
                    flows.bucket_arn,
                    flows.arn_for_objects('*')
                ]
            )
        )

        glue.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    's3:GetObject',
                    's3:PutObject'
                ],
                resources = [
                    athena.bucket_arn,
                    athena.arn_for_objects('*')
                ]
            )
        )

### GLUE ###

        database = _glue.Database(
            self, 'database',
            database_name = 'forensicvpc'
        )

        vpcflows =  _glue.Table(
            self, 'vpcflows',
            bucket = flows,
            database = database,
            s3_prefix = 'AWSLogs',
            table_name = 'flowlogs',
            columns = [
                _glue.Column(
                    name = 'version',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'account_id',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'interface_id',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'srcaddr',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'dstaddr',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'srcport',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'dstport',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'protocol',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'packets',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'bytes',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'start',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'end',
                    type = _glue.Schema.BIG_INT
                ),
                _glue.Column(
                    name = 'action',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'log_status',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'vpc_id',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'subnet_id',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'instance_id',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'tcp_flags',
                    type = _glue.Schema.INTEGER
                ),
                _glue.Column(
                    name = 'type',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'pkt_srcaddr',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'pkt_dstaddr',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'region',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'az_id',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'sublocation_type',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'sublocation_id',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'pkt_src_aws_service',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'pkt_dst_aws_service',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'flow_direction',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'traffic_path',
                    type = _glue.Schema.INTEGER
                )
            ],
            partition_keys = [
                _glue.Column(
                    name = 'aws-account-id',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'aws-service',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'aws-region',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'year',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'month',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'day',
                    type = _glue.Schema.STRING
                ),
                _glue.Column(
                    name = 'hour',
                    type = _glue.Schema.STRING
                )
            ],
            data_format = _glue.DataFormat.PARQUET,
            enable_partition_filtering = True
        )

### ROLE ###

        role = _iam.Role(
            self, 'role',
            assumed_by = _iam.CompositePrincipal(
                _iam.ServicePrincipal('glue.amazonaws.com'),
                _iam.ServicePrincipal('lambda.amazonaws.com')
            )
        )

        role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSGlueServiceRole'
            )
        )

        role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole'
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'athena:CreateWorkGroup',
                    'athena:DeleteWorkGroup',
                    'athena:GetWorkGroup',
                    'athena:ListEngineVersions',
                    'athena:StartQueryExecution',
                    'athena:StopQueryExecution',
                    'athena:UpdateWorkGroup',
                    'dynamodb:BatchWriteItem',
                    'glue:GetDatabase',
                    'glue:GetDatabases',
                    'glue:GetTable',
                    'glue:GetTables',
                    'glue:GetPartition',
                    'glue:GetPartitions',
                    'glue:BatchGetPartition',
                    'ssm:GetParameter',
                    'states:StartExecution'
                ],
                resources = [
                    '*'
                ]
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    's3:GetObject'
                ],
                resources = [
                    flows.bucket_arn,
                    flows.arn_for_objects('*')
                ]
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    's3:GetObject',
                    's3:PutObject'
                ],
                resources = [
                    athena.bucket_arn,
                    athena.arn_for_objects('*')
                ]
            )
        )

### REPAIR TABLE ###

        repair = _lambda.Function(
            self, 'repair',
            runtime = _lambda.Runtime.PYTHON_3_9,
            code = _lambda.Code.from_asset('repair'),
            architecture = _lambda.Architecture.ARM_64,
            timeout = Duration.seconds(900),
            handler = 'repair.handler',
            environment = dict(
                BUCKET = athena.bucket_name
            ),
            memory_size = 128,
            role = role,
            layers = [
                layer
            ]
        )

        repairlogs = _logs.LogGroup(
            self, 'repairlogs',
            log_group_name = '/aws/lambda/'+repair.function_name,
            retention = _logs.RetentionDays.ONE_DAY,
            removal_policy = RemovalPolicy.DESTROY
        )

        repairevent = _events.Rule(
            self, 'repairevent',
            schedule = _events.Schedule.cron(
                minute = '1',
                hour = '*',
                month = '*',
                week_day = '*',
                year = '*'
            )
        )

        repairevent.add_target(
            _targets.LambdaFunction(
                repair
            )
        )

        repairsub = _logs.SubscriptionFilter(
            self, 'repairsub',
            log_group = repairlogs,
            destination = _destinations.LambdaDestination(error),
            filter_pattern = _logs.FilterPattern.all_terms('ERROR')
        )

        repairtimesub = _logs.SubscriptionFilter(
            self, 'repairtimesub',
            log_group = repairlogs,
            destination = _destinations.LambdaDestination(timeout),
            filter_pattern = _logs.FilterPattern.all_terms('Task','timed','out')
        )

### PARSE LOGS ###

        parse = _lambda.Function(
            self, 'parse',
            runtime = _lambda.Runtime.PYTHON_3_9,
            code = _lambda.Code.from_asset('parse'),
            architecture = _lambda.Architecture.ARM_64,
            timeout = Duration.seconds(900),
            handler = 'parse.handler',
            environment = dict(
                BUCKET = athena.bucket_name
            ),
            memory_size = 128,
            role = role,
            layers = [
                layer
            ]
        )

        parselogs = _logs.LogGroup(
            self, 'parselogs',
            log_group_name = '/aws/lambda/'+parse.function_name,
            retention = _logs.RetentionDays.ONE_DAY,
            removal_policy = RemovalPolicy.DESTROY
        )

        parseevent = _events.Rule(
            self, 'parseevent',
            schedule = _events.Schedule.cron(
                minute = '5',
                hour = '*',
                month = '*',
                week_day = '*',
                year = '*'
            )
        )

        parseevent.add_target(
            _targets.LambdaFunction(
                parse
            )
        )

        parsesub = _logs.SubscriptionFilter(
            self, 'parsesub',
            log_group = parselogs,
            destination = _destinations.LambdaDestination(error),
            filter_pattern = _logs.FilterPattern.all_terms('ERROR')
        )

        parsetimesub = _logs.SubscriptionFilter(
            self, 'parsetimesub',
            log_group = parselogs,
            destination = _destinations.LambdaDestination(timeout),
            filter_pattern = _logs.FilterPattern.all_terms('Task','timed','out')
        )

### DYNAMODB ###

        table = _dynamodb.Table(
            self, 'table',
            partition_key = {
                'name': 'pk',
                'type': _dynamodb.AttributeType.STRING
            },
            sort_key = {
                'name': 'sk',
                'type': _dynamodb.AttributeType.STRING
            },
            billing_mode = _dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy = RemovalPolicy.DESTROY,
            point_in_time_recovery = True
        )

### START STEP FUNCTION ###

        start = _lambda.Function(
            self, 'start',
            runtime = _lambda.Runtime.PYTHON_3_9,
            code = _lambda.Code.from_asset('start'),
            architecture = _lambda.Architecture.ARM_64,
            timeout = Duration.seconds(900),
            handler = 'start.handler',
            environment = dict(
                DYNAMODB_TABLE = table.table_name,
                STEP_FUNCTION = '/forensicvpc/statemachine'
                
            ),
            memory_size = 128,
            role = role,
            layers = [
                layer
            ]
        )

        startlogs = _logs.LogGroup(
            self, 'startlogs',
            log_group_name = '/aws/lambda/'+start.function_name,
            retention = _logs.RetentionDays.ONE_DAY,
            removal_policy = RemovalPolicy.DESTROY
        )

        notify = _notifications.LambdaDestination(start)
        athena.add_event_notification(_s3.EventType.OBJECT_CREATED, notify)

        startsub = _logs.SubscriptionFilter(
            self, 'startsub',
            log_group = startlogs,
            destination = _destinations.LambdaDestination(error),
            filter_pattern = _logs.FilterPattern.all_terms('ERROR')
        )

        starttimesub = _logs.SubscriptionFilter(
            self, 'starttimesub',
            log_group = startlogs,
            destination = _destinations.LambdaDestination(timeout),
            filter_pattern = _logs.FilterPattern.all_terms('Task','timed','out')
        )

### STEP FUNCTION PASSTHRU ###

        passthru = _lambda.Function(
            self, 'passthru',
            runtime = _lambda.Runtime.PYTHON_3_9,
            code = _lambda.Code.from_asset('passthru'),
            architecture = _lambda.Architecture.ARM_64,
            timeout = Duration.seconds(900),
            handler = 'passthru.handler',
            memory_size = 128,
            role = role,
            layers = [
                layer
            ]
        )

        passthrulogs = _logs.LogGroup(
            self, 'passthrulogs',
            log_group_name = '/aws/lambda/'+passthru.function_name,
            retention = _logs.RetentionDays.ONE_DAY,
            removal_policy = RemovalPolicy.DESTROY
        )

        passthrusub = _logs.SubscriptionFilter(
            self, 'passthrusub',
            log_group = passthrulogs,
            destination = _destinations.LambdaDestination(error),
            filter_pattern = _logs.FilterPattern.all_terms('ERROR')
        )

        passthrutimesub = _logs.SubscriptionFilter(
            self, 'passthrutimesub',
            log_group = passthrulogs,
            destination = _destinations.LambdaDestination(timeout),
            filter_pattern = _logs.FilterPattern.all_terms('Task','timed','out')
        )

### STEP FUNCTION READER LAMBDA ###

        reader = _lambda.DockerImageFunction(
            self, 'reader',
            code = _lambda.DockerImageCode.from_image_asset('reader'),
            timeout = Duration.seconds(900),
            memory_size = 256,
            role = role
        )

        readerlogs = _logs.LogGroup(
            self, 'readerlogs',
            log_group_name = '/aws/lambda/'+reader.function_name,
            retention = _logs.RetentionDays.ONE_DAY,
            removal_policy = RemovalPolicy.DESTROY
        )

        readersub = _logs.SubscriptionFilter(
            self, 'readersub',
            log_group = readerlogs,
            destination = _destinations.LambdaDestination(error),
            filter_pattern = _logs.FilterPattern.all_terms('ERROR')
        )

        readertimesub = _logs.SubscriptionFilter(
            self, 'readertimesub',
            log_group = readerlogs,
            destination = _destinations.LambdaDestination(timeout),
            filter_pattern = _logs.FilterPattern.all_terms('Task','timed','out')
        )

### STEP FUNCTION ###

        initial = _tasks.LambdaInvoke(
            self, 'initial',
            lambda_function = passthru,
            output_path = '$.Payload',
        )

        read = _tasks.LambdaInvoke(
            self, 'read',
            lambda_function = reader,
            output_path = '$.Payload',
        )

        failed = _sfn.Fail(
            self, 'failed',
            cause = 'Failed',
            error = 'FAILED'
        )

        succeed = _sfn.Succeed(
            self, 'succeeded',
            comment = 'SUCCEEDED'
        )

        definition = initial.next(read) \
            .next(_sfn.Choice(self, 'Completed?')
                .when(_sfn.Condition.string_equals('$.status', 'FAILED'), failed)
                .when(_sfn.Condition.string_equals('$.status', 'SUCCEEDED'), succeed)
                .otherwise(read)
            )
            
        statelogs = _logs.LogGroup(
            self, 'statelogs',
            log_group_name = '/aws/state/forensicvpc',
            retention = _logs.RetentionDays.ONE_DAY,
            removal_policy = RemovalPolicy.DESTROY
        )

        statesub = _logs.SubscriptionFilter(
            self, 'statesub',
            log_group = statelogs,
            destination = _destinations.LambdaDestination(error),
            filter_pattern = _logs.FilterPattern.all_terms('ERROR')
        )

        statetimesub = _logs.SubscriptionFilter(
            self, 'statetimesub',
            log_group = statelogs,
            destination = _destinations.LambdaDestination(timeout),
            filter_pattern = _logs.FilterPattern.all_terms('Task','timed','out')
        )
    
        state = _sfn.StateMachine(
            self, 'forensicvpc',
            definition = definition,
            logs = _sfn.LogOptions(
                destination = statelogs,
                level = _sfn.LogLevel.ALL
            )
        )

        statessm = _ssm.StringParameter(
            self, 'statessm',
            description = 'Forensic VPC State Machine',
            parameter_name = '/forensicvpc/statemachine',
            string_value = state.state_machine_arn,
            tier = _ssm.ParameterTier.STANDARD
        )
