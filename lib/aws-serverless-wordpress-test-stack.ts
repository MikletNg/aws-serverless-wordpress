import * as cdk from '@aws-cdk/core';
import { CfnOutput, Duration, RemovalPolicy, SecretValue } from '@aws-cdk/core';
import { ARecord, CnameRecord, PrivateHostedZone, PublicHostedZone, RecordTarget } from '@aws-cdk/aws-route53';
import { Certificate, CertificateValidation } from '@aws-cdk/aws-certificatemanager';
import { Bucket, BucketEncryption, StorageClass } from '@aws-cdk/aws-s3';
import { CfnWebACL, CfnWebACLAssociation } from '@aws-cdk/aws-wafv2';
import {
    AclCidr,
    AclTraffic,
    Action,
    CfnFlowLog,
    NetworkAcl,
    Peer,
    Port,
    SecurityGroup,
    SubnetType,
    TrafficDirection,
    Vpc,
    BastionHostLinux
} from '@aws-cdk/aws-ec2';
import { CfnDBCluster, CfnDBClusterParameterGroup, CfnDBSubnetGroup } from '@aws-cdk/aws-rds';
import { Secret } from '@aws-cdk/aws-secretsmanager';
import { CfnCacheCluster, CfnSubnetGroup } from '@aws-cdk/aws-elasticache';
import { FileSystem, LifecyclePolicy, PerformanceMode, ThroughputMode } from '@aws-cdk/aws-efs';
import {
    CfnCluster,
    CfnService,
    Cluster,
    ContainerImage,
    FargateService,
    FargateTaskDefinition,
    LogDriver,
    Protocol,
    Secret as EcsSecret
} from '@aws-cdk/aws-ecs';
import {
    ApplicationLoadBalancer,
    ApplicationProtocol,
    ApplicationTargetGroup,
    CfnListener,
    CfnTargetGroup,
    ListenerAction
} from '@aws-cdk/aws-elasticloadbalancingv2';
import { ManagedPolicy, PolicyDocument, PolicyStatement, Role, ServicePrincipal } from '@aws-cdk/aws-iam';
import { RetentionDays } from '@aws-cdk/aws-logs';
import { PredefinedMetric, ScalableTarget, ServiceNamespace } from '@aws-cdk/aws-applicationautoscaling';
import {
    CloudFrontAllowedCachedMethods,
    CloudFrontAllowedMethods,
    CloudFrontWebDistribution,
    HttpVersion,
    OriginAccessIdentity,
    OriginProtocolPolicy,
    PriceClass,
    ViewerCertificate,
    ViewerProtocolPolicy
} from '@aws-cdk/aws-cloudfront';
import { CloudFrontTarget } from '@aws-cdk/aws-route53-targets';
import { HttpsRedirect } from '@aws-cdk/aws-route53-patterns';
import { BackupPlan, BackupResource, BackupVault } from '@aws-cdk/aws-backup';
import { CloudFormationStackDriftDetectionCheck, ManagedRule } from '@aws-cdk/aws-config';
import { Topic } from '@aws-cdk/aws-sns';
import { EmailSubscription } from '@aws-cdk/aws-sns-subscriptions';
import { SnsTopic } from '@aws-cdk/aws-events-targets';
import { Alias } from '@aws-cdk/aws-kms';
import { Asset } from '@aws-cdk/aws-s3-assets';
import { Repository } from "@aws-cdk/aws-ecr";
import { BuildSpec, Cache, ComputeType, LinuxBuildImage, PipelineProject } from "@aws-cdk/aws-codebuild";
import path = require('path');
import { Artifact, Pipeline } from "@aws-cdk/aws-codepipeline";
import { CodeBuildAction, S3SourceAction } from "@aws-cdk/aws-codepipeline-actions";
import { DockerImageAsset } from "@aws-cdk/aws-ecr-assets";

interface IDatabaseCredential {
    username: string
    defaultDatabaseName: string
}

interface StackProps extends cdk.StackProps {
    domainName: string
    hostname: string
    alternativeHostname: string[]
    databaseCredential: IDatabaseCredential
    resourceDeletionProtection: boolean
    removalPolicy: RemovalPolicy
    snsEmailSubscription: string[]
    cloudFrontHashHeader?: string
}

export class AwsServerlessWordpressTestStack extends cdk.Stack {
    constructor(scope: cdk.Construct, id: string, props: StackProps) {
        super(scope, id, props);

        const staticContentBucket = new Bucket(this, 'StaticContentBucket', {
            encryption: BucketEncryption.S3_MANAGED,
            versioned: true,
            removalPolicy: props.removalPolicy
        });

        const vpc = new Vpc(this, 'Vpc', {
            natGateways: 1,
            maxAzs: 3,
            subnetConfiguration: [
                {
                    name: 'Public',
                    subnetType: SubnetType.PUBLIC
                },
                {
                    name: 'Private',
                    subnetType: SubnetType.PRIVATE

                },
                {
                    name: 'Isolated',
                    subnetType: SubnetType.ISOLATED
                }
            ],
            enableDnsHostnames: true,
            enableDnsSupport: true
        });

        const privateHostedZone = new PrivateHostedZone(this, 'PrivateHostedZone', {
            vpc,
            zoneName: `${props.hostname}.private`
        });

        const applicationLoadBalancerSecurityGroup = new SecurityGroup(this, 'ApplicationLoadBalancerSecurityGroup', { vpc });
        const elastiCacheMemcachedSecurityGroup = new SecurityGroup(this, 'ElastiCacheMemcachedSecurityGroup', { vpc });
        const rdsAuroraClusterSecurityGroup = new SecurityGroup(this, 'RdsAuroraClusterSecurityGroup', { vpc });
        const ecsFargateServiceSecurityGroup = new SecurityGroup(this, 'EcsFargateServiceSecurityGroup', { vpc });
        const efsFileSystemSecurityGroup = new SecurityGroup(this, 'EfsFileSystemSecurityGroup', { vpc });
        const bastionHostSecurityGroup = new SecurityGroup(this, 'BastionHostSecurityGroup', { vpc });

        applicationLoadBalancerSecurityGroup.addIngressRule(Peer.anyIpv4(), Port.tcp(80));
        ecsFargateServiceSecurityGroup.addIngressRule(applicationLoadBalancerSecurityGroup, Port.tcp(80));
        elastiCacheMemcachedSecurityGroup.addIngressRule(ecsFargateServiceSecurityGroup, Port.tcp(11211));
        rdsAuroraClusterSecurityGroup.addIngressRule(ecsFargateServiceSecurityGroup, Port.tcp(3306));
        efsFileSystemSecurityGroup.addIngressRule(ecsFargateServiceSecurityGroup, Port.tcp(2049));
        efsFileSystemSecurityGroup.addIngressRule(bastionHostSecurityGroup, Port.tcp(2049));

        const rdsAuroraClusterPasswordSecret = new Secret(this, 'RdsAuroraClusterPasswordSecret', {
            removalPolicy: props.removalPolicy,
            generateSecretString: { excludeCharacters: ` ;+%{}` + `@'"\`/\\#` }
        });

        const rdsAuroraCluster = new CfnDBCluster(this, 'RdsAuroraMySqlServerlessCluster', {
            engine: 'aurora-mysql',
            engineMode: 'serverless',
            enableHttpEndpoint: true,
            databaseName: 'wordpress',
            deletionProtection: props.resourceDeletionProtection,
            dbClusterParameterGroupName: new CfnDBClusterParameterGroup(this, 'RdsAuroraMySqlServerlessClusterParameterGroup', {
                family: 'aurora-mysql5.7',
                description: 'RDS Aurora MySQL Serverless Cluster Parameter Group',
                parameters: {
                    time_zone: 'Asia/Taipei'
                }
            }).ref,
            dbSubnetGroupName: new CfnDBSubnetGroup(this, 'RdsAuroraMySqlServerlessClusterSubnet', {
                dbSubnetGroupDescription: 'Aurora MySQL Serverless Database Subnet',
                subnetIds: vpc.isolatedSubnets.map(subnet => subnet.subnetId)
            }).ref,
            vpcSecurityGroupIds: [rdsAuroraClusterSecurityGroup.securityGroupId],
            masterUsername: props.databaseCredential.username,
            masterUserPassword: SecretValue.secretsManager(rdsAuroraClusterPasswordSecret.secretArn).toString(),
            storageEncrypted: true,
            scalingConfiguration: {
                autoPause: false,
                minCapacity: 1,
                maxCapacity: 16
            }
        });
        rdsAuroraCluster.applyRemovalPolicy(props.removalPolicy);

        const rdsAuroraClusterPrivateDnsRecord = new CnameRecord(this, 'RdsAuroraClusterPrivateDnsRecord', {
            zone: privateHostedZone,
            recordName: `database.${privateHostedZone.zoneName}`,
            domainName: rdsAuroraCluster.attrEndpointAddress,
            ttl: Duration.seconds(60)
        });

        const elastiCacheMemcachedCluster = new CfnCacheCluster(this, 'ElastiCacheMemcachedCluster', {
            cacheNodeType: 'cache.r5.large',
            engine: 'memcached',
            azMode: 'cross-az',
            numCacheNodes: 3,
            cacheSubnetGroupName: new CfnSubnetGroup(this, 'ElastiCacheMemcachedClusterSubnetGroup', {
                description: 'ElastiCacheMemcachedClusterSubnetGroup',
                subnetIds: vpc.isolatedSubnets.map(subnet => subnet.subnetId)
            }).ref,
            vpcSecurityGroupIds: [elastiCacheMemcachedSecurityGroup.securityGroupId]
        });

        const elastiCacheMemcachedClusterPrivateDnsRecord = new CnameRecord(this, 'ElastiCacheMemcachedClusterPrivateDnsRecord', {
            zone: privateHostedZone,
            recordName: `cache.${privateHostedZone.zoneName}`,
            domainName: elastiCacheMemcachedCluster.attrConfigurationEndpointAddress,
            ttl: Duration.seconds(60)
        });

        const fileSystem = new FileSystem(this, 'FileSystem', {
            vpc,
            vpcSubnets: {
                subnetType: SubnetType.ISOLATED
            },
            securityGroup: efsFileSystemSecurityGroup,
            performanceMode: PerformanceMode.GENERAL_PURPOSE,
            lifecyclePolicy: LifecyclePolicy.AFTER_30_DAYS,
            throughputMode: ThroughputMode.BURSTING,
            encrypted: true,
            removalPolicy: props.removalPolicy
        });

        const fileSystemAccessPoint = fileSystem.addAccessPoint('AccessPoint');

        const bastionHost = new BastionHostLinux(this, 'BastionHost', {
            vpc,
            securityGroup: bastionHostSecurityGroup
        });
        bastionHost.instance.addUserData(`mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport ${fileSystem.fileSystemId}.efs.${this.region}.amazonaws.com:/ /efs `)

        const _ecsCluster = new CfnCluster(this, 'EcsCluster', {
            capacityProviders: ['FARGATE', 'FARGATE_SPOT'],
            defaultCapacityProviderStrategy: [
                {
                    capacityProvider: 'FARGATE',
                    weight: 2,
                    base: 3
                },
                {
                    capacityProvider: 'FARGATE_SPOT',
                    weight: 1
                }
            ],
            clusterSettings: [{
                name: 'containerInsights',
                value: 'enabled'
            }]
        });

        const ecsCluster = Cluster.fromClusterAttributes(this, 'CdkEcsCluster', {
            clusterName: _ecsCluster.ref,
            vpc,
            securityGroups: [],
            hasEc2Capacity: false
        });

        const applicationLoadBalancer = new ApplicationLoadBalancer(this, 'ApplicationLoadBalancer', {
            vpc,
            deletionProtection: props.resourceDeletionProtection,
            http2Enabled: true,
            internetFacing: true,
            securityGroup: applicationLoadBalancerSecurityGroup
        });
        applicationLoadBalancer.setAttribute('routing.http.drop_invalid_header_fields.enabled', 'true')

        const httpListener = applicationLoadBalancer.addListener('HttpListener', {
            port: 80,
            protocol: ApplicationProtocol.HTTP
        });

        const wordPressFargateTaskExecutionRole = new Role(this, 'WordpressFargateTaskExecutionRole', {
            assumedBy: new ServicePrincipal('ecs-tasks.amazonaws.com'),
            managedPolicies: [ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonECSTaskExecutionRolePolicy')]
        });
        const wordPressFargateTaskRole = new Role(this, 'WordpressFargateTaskRole', {
            assumedBy: new ServicePrincipal('ecs-tasks.amazonaws.com'),
            inlinePolicies: {
                _: new PolicyDocument({
                    statements: [
                        new PolicyStatement({
                            actions: ['s3:GetBucketLocation'],
                            resources: [staticContentBucket.bucketArn]
                        })
                    ]
                })
            }
        });
        staticContentBucket.grantReadWrite(wordPressFargateTaskRole);

        const wordPressFargateTaskDefinition = new FargateTaskDefinition(this, 'WordpressFargateTaskDefinition', {
            memoryLimitMiB: 512,
            cpu: 256,
            executionRole: wordPressFargateTaskExecutionRole,
            taskRole: wordPressFargateTaskRole,
        });
        wordPressFargateTaskDefinition.addVolume({
            name: 'WordPressEfsVolume',
            efsVolumeConfiguration: {
                fileSystemId: fileSystem.fileSystemId,
                transitEncryption: 'ENABLED',
                authorizationConfig: {
                    accessPointId: fileSystemAccessPoint.accessPointId
                }
            }
        });

        const wordPressDockerImageAsset = new DockerImageAsset(this, 'WordPressDockerImageAsset', { directory: path.join(__dirname, 'images/wordpress') });
        const nginxDockerImageAsset = new DockerImageAsset(this, 'NginxDockerImageAsset', { directory: path.join(__dirname, 'images/nginx') });

        const wordPressContainer = wordPressFargateTaskDefinition.addContainer('WordPress', {
            image: ContainerImage.fromDockerImageAsset(wordPressDockerImageAsset),
            environment: {
                WORDPRESS_DB_HOST: rdsAuroraClusterPrivateDnsRecord.domainName,
                WORDPRESS_DB_USER: props.databaseCredential.username,
                WORDPRESS_DB_NAME: props.databaseCredential.defaultDatabaseName,
            },
            secrets: {
                WORDPRESS_DB_PASSWORD: EcsSecret.fromSecretsManager(rdsAuroraClusterPasswordSecret)
            },
            logging: LogDriver.awsLogs({
                streamPrefix: `${this.stackName}WordPressContainerLog`,
                logRetention: RetentionDays.ONE_DAY
            })
        });
        wordPressContainer.addMountPoints({
            readOnly: false,
            containerPath: '/var/www/html',
            sourceVolume: 'WordPressEfsVolume'
        });

        const nginxContainer = wordPressFargateTaskDefinition.addContainer('Nginx', {
            image: ContainerImage.fromDockerImageAsset(nginxDockerImageAsset),
            logging: LogDriver.awsLogs({
                streamPrefix: `${this.stackName}NginxContainerLog`,
                logRetention: RetentionDays.ONE_DAY
            }),
            environment: {
                SERVER_NAME: props.hostname,
                MEMCACHED_HOST: elastiCacheMemcachedClusterPrivateDnsRecord.domainName,
                NGINX_ENTRYPOINT_QUIET_LOGS: '1'
            }
        });
        nginxContainer.addPortMappings({
            hostPort: 80,
            containerPort: 80,
            protocol: Protocol.TCP
        });
        nginxContainer.addMountPoints({
            readOnly: false,
            containerPath: '/var/www/html',
            sourceVolume: 'WordPressEfsVolume'
        });

        const _wordPressFargateServiceTargetGroup = new CfnTargetGroup(this, 'CfnWordPressFargateServiceTargetGroup', {
            matcher: {
                httpCode: '200,301,302'
            },
            port: 80,
            protocol: 'HTTP',
            targetGroupAttributes: [
                {
                    key: 'stickiness.enabled',
                    value: 'true'
                },
                {
                    key: 'stickiness.type',
                    value: 'lb_cookie'
                },
                {
                    key: 'stickiness.lb_cookie.duration_seconds',
                    value: '604800'
                }
            ],
            targetType: 'ip',
            vpcId: vpc.vpcId,
            unhealthyThresholdCount: 5,
            healthCheckTimeoutSeconds: 45,
            healthCheckIntervalSeconds: 60,
        });

        const wordPressFargateServiceTargetGroup = ApplicationTargetGroup.fromTargetGroupAttributes(this, 'WordPressFargateServiceTargetGroup', {
            loadBalancerArns: applicationLoadBalancer.loadBalancerArn,
            targetGroupArn: _wordPressFargateServiceTargetGroup.ref
        });
        httpListener.addTargetGroups('WordPress', { targetGroups: [wordPressFargateServiceTargetGroup] });

        const _wordPressFargateService = new CfnService(this, 'CfnWordPressFargateService', {
            cluster: ecsCluster.clusterArn,
            desiredCount: 3,
            deploymentConfiguration: {
                maximumPercent: 200,
                minimumHealthyPercent: 50
            },
            deploymentController: {
                type: 'ECS'
            },
            healthCheckGracePeriodSeconds: 60,
            loadBalancers: [
                {
                    containerName: nginxContainer.containerName,
                    containerPort: 80,
                    targetGroupArn: wordPressFargateServiceTargetGroup.targetGroupArn
                }
            ],
            networkConfiguration: {
                awsvpcConfiguration: {
                    assignPublicIp: 'DISABLED',
                    securityGroups: [ecsFargateServiceSecurityGroup.securityGroupId],
                    subnets: vpc.privateSubnets.map(subnet => subnet.subnetId)
                }
            },
            platformVersion: '1.4.0',
            taskDefinition: wordPressFargateTaskDefinition.taskDefinitionArn
        });
        _wordPressFargateService.addOverride('DependsOn', this.getLogicalId(httpListener.node.defaultChild as CfnListener));
    }
}
