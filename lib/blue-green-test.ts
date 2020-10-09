import * as cdk from '@aws-cdk/core';
import {ServicePrincipal, Role, PolicyStatement, CfnRole} from "@aws-cdk/aws-iam";
import {CfnCodeDeployBlueGreenHook, CfnTrafficRoutingType, CfnHook} from '@aws-cdk/core';
import {Vpc, SecurityGroup, Port, Peer, SubnetType} from '@aws-cdk/aws-ec2';
import {
    Cluster,
    CfnCluster,
    FargateTaskDefinition,
    ContainerImage,
    Protocol,
    FargateService,
    CfnService,
    CfnTaskDefinition,
    DeploymentControllerType,
    CfnTaskSet,
    CfnPrimaryTaskSet
} from '@aws-cdk/aws-ecs';
import {
    ApplicationTargetGroup,
    ApplicationLoadBalancer,
    ApplicationProtocol,
    CfnListener,
    CfnTargetGroup,
    TargetType
} from '@aws-cdk/aws-elasticloadbalancingv2';

export class BlueGreenTestStack extends cdk.Stack {
    constructor(scope: cdk.Construct, id: string, props: cdk.StackProps) {
        super(scope, id, props)

        const vpc = new Vpc(this, 'Vpc', {maxAzs: 2, natGateways: 1});

        const albSg = new SecurityGroup(this, 'AlbSg', {vpc})
        const ecsSg = new SecurityGroup(this, 'EcsSg', {vpc})
        albSg.addIngressRule(Peer.anyIpv4(), Port.tcp(80));
        ecsSg.addIngressRule(albSg, Port.tcp(80));

        const alb = new ApplicationLoadBalancer(this, 'Alb', {
            vpc,
            vpcSubnets: {subnetType: SubnetType.PUBLIC},
            securityGroup: albSg
        });

        const prodListener = alb.addListener('ProdListener', {
            port: 80,
            protocol: ApplicationProtocol.HTTP
        });

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

        const blueTargetGroup = new ApplicationTargetGroup(this, ' BlueTargetGroup', {
            vpc,
            port: 80,
            protocol: ApplicationProtocol.HTTP,
            targetType: TargetType.IP
        });

        const blueTaskDefinition = new FargateTaskDefinition(this, 'BlueTaskDefinition', {
            cpu: 256,
            memoryLimitMiB: 512
        });
        const nginxContainer = blueTaskDefinition.addContainer('Nginx', {
            image: ContainerImage.fromRegistry('nginxdemos/hello:latest'),
            environment: {
                TEST_ENV: '123'
            }
        });
        nginxContainer.addPortMappings({
            containerPort: 80,
            protocol: Protocol.TCP
        });

        const service = new CfnService(this, 'Service', {
            desiredCount: 1,
            deploymentController: {
                type: 'EXTERNAL'
            },
            cluster: ecsCluster.clusterArn
        })

        prodListener.addTargetGroups('nginx', {targetGroups: [blueTargetGroup]});

        const blueTaskSet = new CfnTaskSet(this, 'BlueTaskSet', {
            cluster: ecsCluster.clusterArn,
            service: service.ref,
            taskDefinition: blueTaskDefinition.taskDefinitionArn,
            loadBalancers: [
                {
                    containerName: nginxContainer.containerName,
                    containerPort: nginxContainer.containerPort,
                    targetGroupArn: blueTargetGroup.targetGroupArn
                }
            ],
            networkConfiguration: {
                awsVpcConfiguration: {
                    securityGroups: [ecsSg.securityGroupId],
                    assignPublicIp: 'DISABLED',
                    subnets: vpc.privateSubnets.map(s => s.subnetId)
                }
            }
        });

        const primaryTaskSet = new CfnPrimaryTaskSet(this, 'PrimaryTaskSet', {
            cluster: ecsCluster.clusterArn,
            service: service.ref,
            taskSetId: blueTaskSet.attrId
        })

        const ecsServiceBlueGreenDeploymentHookServiceRole = new Role(this, 'EcsServiceBlueGreenDeploymentHookServiceRole', {
            assumedBy: new ServicePrincipal('codedeploy.amazonaws.com'),
        });
        ecsServiceBlueGreenDeploymentHookServiceRole.addToPolicy(new PolicyStatement({
            actions: ['codedeploy:Get*', 'codedeploy:CreateCloudFormationDeployment'],
            resources: ['*']
        }));

        const ecsServiceBlueGreenDeploymentHook = new CfnHook(this, 'EcsServiceBlueGreenDeploymentHook', {
            type: 'AWS::CodeDeploy::BlueGreen',
            properties: {
                ServiceRole: this.getLogicalId(ecsServiceBlueGreenDeploymentHookServiceRole.node.defaultChild as CfnRole),
                TrafficRoutingConfig: {
                    Type: CfnTrafficRoutingType.TIME_BASED_CANARY,
                    TimeBasedCanary: {
                        StepPercentage: 15,
                        BakeTimeMins: 5
                    }
                },
                Applications: [
                    {
                        Target: {
                            Type: 'AWS::ECS::Service',
                            LogicalID: service.logicalId
                        },
                        ECSAttributes: {
                            TaskDefinitions: [
                                this.getLogicalId(blueTaskDefinition.node.defaultChild as CfnTaskDefinition),
                                'GreenTaskDefinition'
                            ],
                            TaskSets: [
                                blueTaskSet.logicalId,
                                'GreenTaskSet'
                            ],
                            TrafficRouting: {
                                ProdTrafficRoute: {
                                    Type: 'AWS::ElasticLoadBalancingV2::Listener',
                                    LogicalID: this.getLogicalId(prodListener.node.defaultChild as CfnListener)
                                },
                                TestTrafficRoute: {
                                    Type: 'AWS::ElasticLoadBalancingV2::Listener',
                                    LogicalID: 'TestListener'
                                },
                                TargetGroups: [
                                    this.getLogicalId(blueTargetGroup.node.defaultChild as CfnTargetGroup),
                                    'GreenTargetGroup'
                                ]
                            }
                        }
                    }
                ]
            }
        })
    }
}