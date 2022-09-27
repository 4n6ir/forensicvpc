from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_ec2 as _ec2,
    aws_iam as _iam,
    aws_s3 as _s3
)

from constructs import Construct

class ForensicvpcStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

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
                    's3:PutObject'
                ],
                resources = [
                    athena.bucket_arn,
                    athena.arn_for_objects('*')
                ]
            )
        )


