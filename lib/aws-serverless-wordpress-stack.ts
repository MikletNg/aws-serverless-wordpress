import * as cdk from '@aws-cdk/core';
import {CfnOutput, Duration, RemovalPolicy, SecretValue} from '@aws-cdk/core';
import {ARecord, CnameRecord, PrivateHostedZone, PublicHostedZone, RecordTarget} from '@aws-cdk/aws-route53';
import {Certificate, CertificateValidation} from '@aws-cdk/aws-certificatemanager';
import {Bucket, BucketEncryption, StorageClass} from '@aws-cdk/aws-s3';
import {
    AclCidr,
    AclTraffic,
    Action,
    BastionHostLinux,
    CfnFlowLog,
    NetworkAcl,
    Peer,
    Port,
    SecurityGroup,
    SubnetType,
    TrafficDirection,
    Vpc
} from '@aws-cdk/aws-ec2';
import {CfnDBCluster, CfnDBClusterParameterGroup, CfnDBSubnetGroup} from '@aws-cdk/aws-rds';
import {Secret} from '@aws-cdk/aws-secretsmanager';
import {CfnCacheCluster, CfnSubnetGroup} from '@aws-cdk/aws-elasticache';
import {FileSystem, LifecyclePolicy, PerformanceMode, ThroughputMode} from '@aws-cdk/aws-efs';
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
import {
    AccountRootPrincipal,
    ArnPrincipal,
    ManagedPolicy,
    PolicyDocument,
    PolicyStatement,
    Role,
    ServicePrincipal
} from '@aws-cdk/aws-iam';
import {RetentionDays} from '@aws-cdk/aws-logs';
import {PredefinedMetric, ScalableTarget, ServiceNamespace} from '@aws-cdk/aws-applicationautoscaling';
import {Alias} from '@aws-cdk/aws-kms';
import {DockerImageAsset} from "@aws-cdk/aws-ecr-assets";
import path = require('path');
import {
    CfnDistribution,
    CloudFrontAllowedCachedMethods,
    CloudFrontAllowedMethods, CloudFrontWebDistribution,
    HttpVersion, OriginAccessIdentity, OriginProtocolPolicy,
    PriceClass,
    ViewerCertificate,
    ViewerProtocolPolicy
} from "@aws-cdk/aws-cloudfront";
import {CfnWebACL, CfnWebACLAssociation} from "@aws-cdk/aws-wafv2";
import {BackupPlan, BackupResource, BackupVault} from "@aws-cdk/aws-backup";
import {CloudFrontTarget} from "@aws-cdk/aws-route53-targets";
import {Domain, ElasticsearchVersion} from "@aws-cdk/aws-elasticsearch";
import {SnsTopic} from "@aws-cdk/aws-events-targets";
import {CloudFormationStackDriftDetectionCheck, ManagedRule} from "@aws-cdk/aws-config";
import {EmailSubscription} from "@aws-cdk/aws-sns-subscriptions";
import {Topic} from "@aws-cdk/aws-sns";

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
    loadBalancerAccountId: string
}

export class AwsServerlessWordpressStack extends cdk.Stack {
    constructor(scope: cdk.Construct, id: string, props: StackProps) {
        super(scope, id, props);

        const awsManagedSnsKmsKey = Alias.fromAliasName(this, 'AwsManagedSnsKmsKey', 'alias/aws/sns');

        const publicHostedZone = PublicHostedZone.fromLookup(this, 'ExistingPublicHostedZone', {domainName: props.domainName});

        const acmCertificate = new Certificate(this, 'Certificate', {
            domainName: props.hostname,
            subjectAlternativeNames: props.alternativeHostname,
            validation: CertificateValidation.fromDns(publicHostedZone)
        });

        const staticContentBucket = new Bucket(this, 'StaticContentBucket', {
            encryption: BucketEncryption.S3_MANAGED,
            versioned: true,
            removalPolicy: props.removalPolicy
        });

        const loggingBucket = new Bucket(this, 'LoggingBucket', {
            encryption: BucketEncryption.S3_MANAGED,
            removalPolicy: props.removalPolicy,
            lifecycleRules: [
                {
                    enabled: true,
                    transitions: [
                        {
                            storageClass: StorageClass.INFREQUENT_ACCESS,
                            transitionAfter: Duration.days(30)
                        },
                        {
                            storageClass: StorageClass.DEEP_ARCHIVE,
                            transitionAfter: Duration.days(90)
                        }
                    ]
                }
            ]
        });
        loggingBucket.addToResourcePolicy(new PolicyStatement({
            principals: [new ServicePrincipal('delivery.logs.amazonaws.com'),],
            actions: ['s3:PutObject'],
            resources: [
                `${loggingBucket.bucketArn}/vpc-flow-log/AWSLogs/${this.account}/*`,
                `${loggingBucket.bucketArn}/application-load-balancer/AWSLogs/${this.account}/*`
            ],
            conditions: {
                StringEquals: {
                    's3:x-amz-acl': 'bucket-owner-full-control'
                }
            }
        }));
        loggingBucket.addToResourcePolicy(new PolicyStatement({
            principals: [new ServicePrincipal('delivery.logs.amazonaws.com'),],
            actions: ['s3:GetBucketAcl'],
            resources: [loggingBucket.bucketArn],
        }));

        loggingBucket.addToResourcePolicy(new PolicyStatement({
            principals: [new ArnPrincipal(`arn:aws:iam::${props.loadBalancerAccountId}:root`)],
            actions: ['s3:PutObject'],
            resources: [`${loggingBucket.bucketArn}/application-load-balancer/AWSLogs/${this.account}/*`]
        }));
        loggingBucket.addToResourcePolicy(new PolicyStatement({
            principals: [new AccountRootPrincipal()],
            actions: ['s3:GetBucketAcl', 's3:PutBucketAcl'],
            resources: [loggingBucket.bucketArn]
        }));

        const vpc = new Vpc(this, 'Vpc', {
            natGateways: 3,
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

        const nacl = new NetworkAcl(this, 'NetworkAcl', {vpc});
        nacl.addEntry('AllowAllHttpsFromIpv4', {
            ruleNumber: 100,
            cidr: AclCidr.anyIpv4(),
            traffic: AclTraffic.tcpPort(443),
            direction: TrafficDirection.INGRESS,
            ruleAction: Action.ALLOW
        });
        nacl.addEntry('AllowAllHttpsFromIpv6', {
            ruleNumber: 101,
            cidr: AclCidr.anyIpv6(),
            traffic: AclTraffic.tcpPort(443),
            direction: TrafficDirection.INGRESS,
            ruleAction: Action.ALLOW
        });
        nacl.addEntry('AllowResponseToHttpsRequestToIpv4', {
            ruleNumber: 100,
            cidr: AclCidr.anyIpv4(),
            traffic: AclTraffic.tcpPortRange(1024, 65535),
            direction: TrafficDirection.EGRESS,
            ruleAction: Action.ALLOW
        });
        nacl.addEntry('AllowResponseToHttpsRequestToIpv6', {
            ruleNumber: 101,
            cidr: AclCidr.anyIpv6(),
            traffic: AclTraffic.tcpPortRange(1024, 65535),
            direction: TrafficDirection.EGRESS,
            ruleAction: Action.ALLOW
        });

        new CfnFlowLog(this, 'CfnVpcFlowLog', {
            resourceId: vpc.vpcId,
            resourceType: 'VPC',
            trafficType: 'ALL',
            logDestinationType: 's3',
            logDestination: `${loggingBucket.bucketArn}/vpc-flow-log`
        });

        const privateHostedZone = new PrivateHostedZone(this, 'PrivateHostedZone', {
            vpc,
            zoneName: `${props.hostname}.private`
        });

        const applicationLoadBalancerSecurityGroup = new SecurityGroup(this, 'ApplicationLoadBalancerSecurityGroup', {vpc});
        const elastiCacheMemcachedSecurityGroup = new SecurityGroup(this, 'ElastiCacheMemcachedSecurityGroup', {vpc});
        const rdsAuroraClusterSecurityGroup = new SecurityGroup(this, 'RdsAuroraClusterSecurityGroup', {vpc});
        const ecsFargateServiceSecurityGroup = new SecurityGroup(this, 'EcsFargateServiceSecurityGroup', {vpc});
        const efsFileSystemSecurityGroup = new SecurityGroup(this, 'EfsFileSystemSecurityGroup', {vpc});
        const elasticsearchDomainSecurityGroup = new SecurityGroup(this, 'ElasticsearchDomainSecurityGroup', {vpc});
        const bastionHostSecurityGroup = new SecurityGroup(this, 'BastionHostSecurityGroup', {vpc});

        applicationLoadBalancerSecurityGroup.addIngressRule(Peer.anyIpv4(), Port.tcp(443));
        ecsFargateServiceSecurityGroup.addIngressRule(applicationLoadBalancerSecurityGroup, Port.tcp(80));
        elastiCacheMemcachedSecurityGroup.addIngressRule(ecsFargateServiceSecurityGroup, Port.tcp(11211));
        rdsAuroraClusterSecurityGroup.addIngressRule(ecsFargateServiceSecurityGroup, Port.tcp(3306));
        efsFileSystemSecurityGroup.addIngressRule(ecsFargateServiceSecurityGroup, Port.tcp(2049));
        elasticsearchDomainSecurityGroup.addIngressRule(ecsFargateServiceSecurityGroup, Port.tcp(443));

        efsFileSystemSecurityGroup.addIngressRule(bastionHostSecurityGroup, Port.tcp(2049));
        elastiCacheMemcachedSecurityGroup.addIngressRule(bastionHostSecurityGroup, Port.tcp(11211));
        rdsAuroraClusterSecurityGroup.addIngressRule(bastionHostSecurityGroup, Port.tcp(3306));
        elasticsearchDomainSecurityGroup.addIngressRule(bastionHostSecurityGroup, Port.tcp(443));

        const rdsAuroraClusterPasswordSecret = new Secret(this, 'RdsAuroraClusterPasswordSecret', {
            removalPolicy: props.removalPolicy,
            generateSecretString: {excludeCharacters: ` ;+%{}` + `@'"\`/\\#`}
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
            ttl: Duration.hours(1)
        });

        const elastiCacheMemcachedCluster = new CfnCacheCluster(this, 'ElastiCacheMemcachedCluster', {
            cacheNodeType: 'cache.t3.medium',
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
            ttl: Duration.hours(1)
        });

        const elasticsearchDomain = new Domain(this, 'ElasticsearchDomain', {
            version: ElasticsearchVersion.V7_7,
            capacity: {dataNodes: 3, dataNodeInstanceType: 't3.medium.elasticsearch'},
            zoneAwareness: {enabled: true, availabilityZoneCount: 3},
            encryptionAtRest: {enabled: true},
            nodeToNodeEncryption: true,
            ebs: {volumeSize: 10},
            enforceHttps: true,
            vpcOptions: {
                subnets: vpc.isolatedSubnets,
                securityGroups: [elasticsearchDomainSecurityGroup]
            }
        });
        const elasticsearchDomainPrivateDnsRecord = new CnameRecord(this, 'ElasticsearchDomainPrivateDnsRecord', {
            zone: privateHostedZone,
            recordName: `search.${privateHostedZone.zoneName}`,
            domainName: elasticsearchDomain.domainEndpoint,
            ttl: Duration.hours(1)
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

        const fileSystemEndpointPrivateDnsRecord = new CnameRecord(this, 'FileSystemEndpointPrivateDnsRecord', {
            zone: privateHostedZone,
            recordName: `nfs.${privateHostedZone.zoneName}`,
            domainName: `${fileSystem.fileSystemId}.efs.${this.region}.amazonaws.com`,
            ttl: Duration.hours(1)
        });

        const bastionHost = new BastionHostLinux(this, 'BastionHost', {
            vpc,
            securityGroup: bastionHostSecurityGroup
        });
        bastionHost.instance.addUserData('mkdir -p /mnt/efs');
        bastionHost.instance.addUserData(`mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport ${fileSystemEndpointPrivateDnsRecord.domainName}:/ /mnt/efs `);

        const ecsCluster = new Cluster(this, 'EcsCluster', {
            containerInsights: true,
            vpc
        });
        const _ecsCluster = ecsCluster.node.defaultChild as CfnCluster;
        _ecsCluster.capacityProviders = ['FARGATE', 'FARGATE_SPOT'];
        _ecsCluster.defaultCapacityProviderStrategy = [
            {
                capacityProvider: 'FARGATE',
                weight: 2,
                base: 3
            },
            {
                capacityProvider: 'FARGATE_SPOT',
                weight: 1
            }
        ];

        const applicationLoadBalancer = new ApplicationLoadBalancer(this, 'ApplicationLoadBalancer', {
            vpc,
            deletionProtection: props.resourceDeletionProtection,
            http2Enabled: true,
            internetFacing: true,
            securityGroup: applicationLoadBalancerSecurityGroup,
        });
        applicationLoadBalancer.setAttribute('routing.http.drop_invalid_header_fields.enabled', 'true');
        applicationLoadBalancer.setAttribute('access_logs.s3.enabled', 'true');
        applicationLoadBalancer.setAttribute('access_logs.s3.bucket', loggingBucket.bucketName);
        applicationLoadBalancer.setAttribute('access_logs.s3.prefix', 'application-load-balancer');
        applicationLoadBalancer.addListener('HttpListener', {
            port: 80,
            protocol: ApplicationProtocol.HTTP,
            defaultAction: ListenerAction.redirect({protocol: 'HTTPS', port: '443'})
        });

        const httpsListener = applicationLoadBalancer.addListener('HttpsListener', {
            port: 443,
            protocol: ApplicationProtocol.HTTPS,
            certificates: [acmCertificate]
        });

        const wordPressFargateTaskExecutionRole = new Role(this, 'WordpressFargateTaskExecutionRole', {
            assumedBy: new ServicePrincipal('ecs-tasks.amazonaws.com'),
            managedPolicies: [ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonECSTaskExecutionRolePolicy')]
        });
        const wordPressFargateTaskRole = new Role(this, 'WordpressFargateTaskRole', {
            assumedBy: new ServicePrincipal('ecs-tasks.amazonaws.com'),
            managedPolicies: [ManagedPolicy.fromManagedPolicyArn(this, 'XRayDaemonWriteAccess', 'arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess')],
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

        const wordPressDockerImageAsset = new DockerImageAsset(this, 'WordPressDockerImageAsset', {directory: path.join(__dirname, 'images/wordpress')});
        const nginxDockerImageAsset = new DockerImageAsset(this, 'NginxDockerImageAsset', {directory: path.join(__dirname, 'images/nginx')});

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
                logRetention: RetentionDays.ONE_MONTH
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
                logRetention: RetentionDays.ONE_MONTH
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

        const xrayContainer = wordPressFargateTaskDefinition.addContainer('XRay', {
            image: ContainerImage.fromRegistry('amazon/aws-xray-daemon'),
            logging: LogDriver.awsLogs({
                streamPrefix: `${this.stackName}XRayContainerLog`,
                logRetention: RetentionDays.ONE_MONTH
            }),
            user: '1337'
        });
        xrayContainer.addPortMappings({
            containerPort: 2000,
            protocol: Protocol.UDP
        })

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
        httpsListener.addTargetGroups('WordPress', {targetGroups: [wordPressFargateServiceTargetGroup]});

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
        _wordPressFargateService.addOverride('DependsOn', this.getLogicalId(httpsListener.node.defaultChild as CfnListener));

        const wordPressFargateService = FargateService.fromFargateServiceArn(this, 'WordPressFargateService', _wordPressFargateService.ref);

        const wordPressServiceScaling = new ScalableTarget(this, 'WordPressFargateServiceScaling', {
            scalableDimension: 'ecs:service:DesiredCount',
            minCapacity: 3,
            maxCapacity: 300,
            serviceNamespace: ServiceNamespace.ECS,
            resourceId: `service/${ecsCluster.clusterName}/${wordPressFargateService.serviceName}`
        });

        wordPressServiceScaling.scaleToTrackMetric('TargetResponseTime', {
            predefinedMetric: PredefinedMetric.ALB_REQUEST_COUNT_PER_TARGET,
            resourceLabel: `${applicationLoadBalancer.loadBalancerFullName}/${_wordPressFargateServiceTargetGroup.attrTargetGroupFullName}`,
            targetValue: 4096,
            scaleInCooldown: Duration.minutes(3),
            scaleOutCooldown: Duration.minutes(3)
        });

        const wordPressDistributionWafWebAcl = new CfnWebACL(this, 'WordPressCloudFrontDistributionWafWebAcl', {
            defaultAction: {allow: {}},
            scope: 'CLOUDFRONT',
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: 'WebAclMetric'
            },
            rules: [
                {
                    name: 'RuleWithAWSManagedRulesCommonRuleSet',
                    priority: 0,
                    overrideAction: {none: {}},
                    visibilityConfig: {
                        sampledRequestsEnabled: true,
                        cloudWatchMetricsEnabled: true,
                        metricName: 'CommonRuleSetMetric'
                    },
                    statement: {
                        managedRuleGroupStatement: {
                            vendorName: 'AWS',
                            name: 'AWSManagedRulesCommonRuleSet',
                            excludedRules: [{name: 'SizeRestrictions_BODY'}, {name: 'GenericRFI_BODY'}, {name: 'GenericRFI_URIPATH'}, {name: 'GenericRFI_QUERYARGUMENTS'}]
                        }
                    }
                },
                {
                    name: 'RuleWithAWSManagedRulesKnownBadInputsRuleSet',
                    priority: 1,
                    overrideAction: {none: {}},
                    visibilityConfig: {
                        sampledRequestsEnabled: true,
                        cloudWatchMetricsEnabled: true,
                        metricName: 'KnownBadInputsRuleSetMetric'
                    },
                    statement: {
                        managedRuleGroupStatement: {
                            vendorName: 'AWS',
                            name: 'AWSManagedRulesKnownBadInputsRuleSet',
                            excludedRules: []
                        }
                    }
                },
                {
                    name: 'RuleWithAWSManagedRulesWordPressRuleSet',
                    priority: 2,
                    overrideAction: {none: {}},
                    visibilityConfig: {
                        sampledRequestsEnabled: true,
                        cloudWatchMetricsEnabled: true,
                        metricName: 'WordPressRuleSetMetric'
                    },
                    statement: {
                        managedRuleGroupStatement: {
                            vendorName: 'AWS',
                            name: 'AWSManagedRulesWordPressRuleSet',
                            excludedRules: []
                        }
                    }
                },
                {
                    name: 'RuleWithAWSManagedRulesPHPRuleSet',
                    priority: 3,
                    overrideAction: {none: {}},
                    visibilityConfig: {
                        sampledRequestsEnabled: true,
                        cloudWatchMetricsEnabled: true,
                        metricName: 'PHPRuleSetMetric'
                    },
                    statement: {
                        managedRuleGroupStatement: {
                            vendorName: 'AWS',
                            name: 'AWSManagedRulesPHPRuleSet',
                            excludedRules: []
                        }
                    }
                },
                {
                    name: 'RuleWithAWSManagedRulesSQLiRuleSet',
                    priority: 4,
                    overrideAction: {none: {}},
                    visibilityConfig: {
                        sampledRequestsEnabled: true,
                        cloudWatchMetricsEnabled: true,
                        metricName: 'AWSManagedRulesSQLiRuleSetMetric'
                    },
                    statement: {
                        managedRuleGroupStatement: {
                            vendorName: 'AWS',
                            name: 'AWSManagedRulesSQLiRuleSet',
                            excludedRules: []
                        }
                    }
                },
                {
                    name: 'RuleWithAWSManagedRulesAmazonIpReputationList',
                    priority: 5,
                    overrideAction: {none: {}},
                    visibilityConfig: {
                        sampledRequestsEnabled: true,
                        cloudWatchMetricsEnabled: true,
                        metricName: 'AmazonIpReputationListMetric'
                    },
                    statement: {
                        managedRuleGroupStatement: {
                            vendorName: 'AWS',
                            name: 'AWSManagedRulesAmazonIpReputationList',
                            excludedRules: []
                        }
                    }
                },
            ]
        });

        const applicationLoadBalancerWebAcl = new CfnWebACL(this, 'ApplicationLoadBalancerWafWebAcl', {
            defaultAction: {block: {}},
            scope: 'REGIONAL',
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: 'WebAclMetric'
            },
            rules: [
                {
                    name: 'RuleWithOnlyAllowRequestFromCloudFront',
                    priority: 0,
                    action: {allow: {}},
                    visibilityConfig: {
                        sampledRequestsEnabled: true,
                        cloudWatchMetricsEnabled: true,
                        metricName: 'OnlyAllowRequestFromCloudFrontMetric'
                    },
                    statement: {
                        byteMatchStatement: {
                            fieldToMatch: {
                                singleHeader: {
                                    Name: 'X-Request-From-CloudFront'
                                }
                            },
                            positionalConstraint: 'EXACTLY',
                            searchString: props.cloudFrontHashHeader || Buffer.from(props.domainName).toString('base64'),
                            textTransformations: [
                                {
                                    type: 'NONE',
                                    priority: 0
                                }
                            ]
                        }
                    }
                }
            ]
        });

        new CfnWebACLAssociation(this, 'ApplicationLoadBalancerWafWebAclAssociation', {
            resourceArn: applicationLoadBalancer.loadBalancerArn,
            webAclArn: applicationLoadBalancerWebAcl.attrArn
        });

        const wordPressDistribution = new CloudFrontWebDistribution(this, 'WordPressDistribution', {
            originConfigs: [
                {
                    customOriginSource: {
                        domainName: applicationLoadBalancer.loadBalancerDnsName,
                        originProtocolPolicy: OriginProtocolPolicy.HTTPS_ONLY,
                        originReadTimeout: Duration.minutes(1),
                        originHeaders: {
                            'X-Request-From-CloudFront': props.cloudFrontHashHeader || Buffer.from(props.domainName).toString('base64')
                        }
                    },
                    behaviors: [
                        {
                            isDefaultBehavior: true,
                            forwardedValues: {
                                queryString: true,
                                cookies: {
                                    forward: 'whitelist',
                                    whitelistedNames: [
                                        'comment_*',
                                        'wordpress_*',
                                        'wp-settings-*'
                                    ]
                                },
                                headers: [
                                    'Host',
                                    'CloudFront-Forwarded-Proto',
                                    'CloudFront-Is-Mobile-Viewer',
                                    'CloudFront-Is-Tablet-Viewer',
                                    'CloudFront-Is-Desktop-Viewer'
                                ]
                            },
                            cachedMethods: CloudFrontAllowedCachedMethods.GET_HEAD_OPTIONS,
                            allowedMethods: CloudFrontAllowedMethods.ALL
                        },
                        {
                            pathPattern: 'wp-admin/*',
                            forwardedValues: {
                                queryString: true,
                                cookies: {
                                    forward: 'all'
                                },
                                headers: ['*']
                            },
                            cachedMethods: CloudFrontAllowedCachedMethods.GET_HEAD_OPTIONS,
                            allowedMethods: CloudFrontAllowedMethods.ALL
                        },
                        {
                            pathPattern: 'wp-login.php',
                            forwardedValues: {
                                queryString: true,
                                cookies: {
                                    forward: 'all'
                                },
                                headers: ['*']
                            },
                            cachedMethods: CloudFrontAllowedCachedMethods.GET_HEAD_OPTIONS,
                            allowedMethods: CloudFrontAllowedMethods.ALL
                        }
                    ]
                }
            ],
            priceClass: PriceClass.PRICE_CLASS_ALL,
            viewerProtocolPolicy: ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            httpVersion: HttpVersion.HTTP2,
            defaultRootObject: '',
            viewerCertificate: ViewerCertificate.fromAcmCertificate(acmCertificate, {aliases: [props.hostname]}),
            webACLId: wordPressDistributionWafWebAcl.attrArn,
            loggingConfig: {
                bucket: loggingBucket,
                prefix: 'wordpress-distribution'
            }
        });
        (wordPressDistribution.node.defaultChild as CfnDistribution).addDependsOn(wordPressDistributionWafWebAcl);

        const staticContentBucketOriginAccessIdentity = new OriginAccessIdentity(this, 'StaticContentBucketOriginAccessIdentity');
        staticContentBucket.grantRead(staticContentBucketOriginAccessIdentity);

        const staticContentDistribution = new CloudFrontWebDistribution(this, 'StaticContentDistribution', {
            originConfigs: [
                {
                    s3OriginSource: {
                        s3BucketSource: staticContentBucket,
                        originAccessIdentity: staticContentBucketOriginAccessIdentity
                    },
                    behaviors: [
                        {
                            isDefaultBehavior: true,
                            forwardedValues: {
                                queryString: true,
                                cookies: {
                                    forward: 'none'
                                }
                            },
                            cachedMethods: CloudFrontAllowedCachedMethods.GET_HEAD,
                            allowedMethods: CloudFrontAllowedMethods.GET_HEAD
                        }
                    ]
                },
            ],
            priceClass: PriceClass.PRICE_CLASS_ALL,
            viewerProtocolPolicy: ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            httpVersion: HttpVersion.HTTP2,
            defaultRootObject: '',
            viewerCertificate: ViewerCertificate.fromAcmCertificate(acmCertificate, {aliases: [`static.${props.hostname}`]}),
            loggingConfig: {
                bucket: loggingBucket,
                prefix: 'static-content-distribution'
            }
        });

        const backupVault = new BackupVault(this, 'BackupVault', {removalPolicy: props.removalPolicy});

        const backupPlan = BackupPlan.dailyMonthly1YearRetention(this, 'BackupPlan', backupVault);

        backupPlan.addSelection('BackupPlanSelection', {
            resources: [
                BackupResource.fromEfsFileSystem(fileSystem),
                BackupResource.fromArn(this.formatArn({
                    resource: 'cluster',
                    service: 'rds',
                    sep: ':',
                    resourceName: rdsAuroraCluster.ref
                }))
            ]
        });

        const awsConfigOnComplianceSnsTopic = new Topic(this, 'AwsConfigOnComplianceSnsTopic', {masterKey: awsManagedSnsKmsKey});
        props.snsEmailSubscription.forEach(email => awsConfigOnComplianceSnsTopic.addSubscription(new EmailSubscription(email)));

        const awsConfigManagesRules = [
            new ManagedRule(this, 'AwsConfigManagedRuleVpcFlowLogsEnabled', {
                identifier: 'VPC_FLOW_LOGS_ENABLED',
                inputParameters: {trafficType: 'ALL'}
            }),
            new ManagedRule(this, 'AwsConfigManagedRuleVpcSgOpenOnlyToAuthorizedPorts', {
                identifier: 'VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS',
                inputParameters: {authorizedTcpPorts: '443'}
            }),
            new ManagedRule(this, 'AwsConfigManagedRuleInternetGatewayAuthorizedVpcOnly', {
                identifier: 'INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY',
                inputParameters: {AuthorizedVpcIds: vpc.vpcId}
            }),
            new ManagedRule(this, 'AwsConfigManagedRuleAcmCertificateExpirationCheck', {
                identifier: 'ACM_CERTIFICATE_EXPIRATION_CHECK',
                inputParameters: {daysToExpiration: 90}
            }),
            new ManagedRule(this, 'AwsConfigManagedRuleAutoScalingGroupElbHealthcheckRequired', {identifier: 'AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED'}),
            new ManagedRule(this, 'AwsConfigManagedRuleIncomingSshDisabled', {identifier: 'INCOMING_SSH_DISABLED'}),
            new ManagedRule(this, 'AwsConfigManagedRuleSnsEncryptedKms', {identifier: 'SNS_ENCRYPTED_KMS'}),
            new ManagedRule(this, 'AwsConfigManagedRuleElbDeletionProtection', {identifier: 'ELB_DELETION_PROTECTION_ENABLED'}),
            new ManagedRule(this, 'AwsConfigManagedRuleElbLoggingEnabled', {
                identifier: 'ELB_LOGGING_ENABLED',
                inputParameters: {s3BucketNames: loggingBucket.bucketName}
            }),
            new ManagedRule(this, 'AwsConfigManagedRuleAlbHttpDropInvalidHeaderEnabled', {identifier: 'ALB_HTTP_DROP_INVALID_HEADER_ENABLED'}),
            new ManagedRule(this, 'AwsConfigManagedRuleAlbHttpToHttpsRedirectionCheck', {identifier: 'ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK'}),
            new ManagedRule(this, 'AwsConfigManagedRuleAlbWafEnabled', {
                identifier: 'ALB_WAF_ENABLED',
                inputParameters: {wafWebAclIds: applicationLoadBalancerWebAcl.attrArn}
            }),
            new ManagedRule(this, 'AwsConfigManagedRuleCloudFrontOriginAccessIdentityEnabled', {identifier: 'CLOUDFRONT_ORIGIN_ACCESS_IDENTITY_ENABLED'}),
            new ManagedRule(this, 'AwsConfigManagedRuleCloudFrontViewerPolicyHttps', {identifier: 'CLOUDFRONT_VIEWER_POLICY_HTTPS'}),
            new ManagedRule(this, 'AwsConfigManagedRuleEfsInBackupPlan', {identifier: 'EFS_IN_BACKUP_PLAN'}),
            new ManagedRule(this, 'AwsConfigManagedRuleEfsEncryptedCheck', {identifier: 'EFS_ENCRYPTED_CHECK'}),
            new ManagedRule(this, 'AwsConfigManagedRuleRdsClusterDeletionProtectionEnabled', {identifier: 'RDS_CLUSTER_DELETION_PROTECTION_ENABLED'}),
            new ManagedRule(this, 'AwsConfigManagedRuleEdsInBackupPlan', {identifier: 'RDS_IN_BACKUP_PLAN'}),
            new ManagedRule(this, 'AwsConfigManagedRuleS3BucketPublicReadProhibited', {identifier: 'S3_BUCKET_PUBLIC_READ_PROHIBITED'}),
            new ManagedRule(this, 'AwsConfigManagedRuleS3BucketPublicWriteProhibited', {identifier: 'S3_BUCKET_PUBLIC_WRITE_PROHIBITED'}),
        ]
        awsConfigManagesRules.forEach(rule => {
            rule.scopeToTag('aws-config:cloudformation:stack-name', this.stackName);
            rule.onComplianceChange('TopicEvent', {target: new SnsTopic(awsConfigOnComplianceSnsTopic)});
        });

        const awsConfigCloudFormationStackDriftDetectionCheckRule = new CloudFormationStackDriftDetectionCheck(this, 'AwsConfigCloudFormationStackDriftDetectionCheck', {ownStackOnly: true});
        awsConfigCloudFormationStackDriftDetectionCheckRule.onComplianceChange('TopicEvent', {target: new SnsTopic(awsConfigOnComplianceSnsTopic)})

        const rootDnsRecord = new ARecord(this, 'RootDnsRecord', {
            zone: publicHostedZone,
            recordName: props.hostname,
            target: RecordTarget.fromAlias(new CloudFrontTarget(wordPressDistribution))
        });

        const staticContentDnsRecord = new ARecord(this, 'StaticContentDnsRecord', {
            zone: publicHostedZone,
            recordName: `static.${props.hostname}`,
            target: RecordTarget.fromAlias(new CloudFrontTarget(staticContentDistribution))
        });

        new CfnOutput(this, 'RootHostname', {
            value: rootDnsRecord.domainName
        });

        new CfnOutput(this, 'StaticContentHostname', {
            value: staticContentDnsRecord.domainName
        });

        new CfnOutput(this, 'RdsAuroraServerlessClusterPrivateHostname', {
            value: rdsAuroraClusterPrivateDnsRecord.domainName
        });

        new CfnOutput(this, 'ElastiCacheMemcachedClusterPrivateHostname', {
            value: elastiCacheMemcachedClusterPrivateDnsRecord.domainName
        });

        new CfnOutput(this, 'ElasticsearchDomainPrivateHostname', {
            value: elasticsearchDomainPrivateDnsRecord.domainName
        });

        new CfnOutput(this, 'EfsFileSystemPrivateHostname', {
            value: fileSystemEndpointPrivateDnsRecord.domainName
        });
    }
}
