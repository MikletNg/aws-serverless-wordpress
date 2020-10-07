import * as cdk from '@aws-cdk/core';
import {ServicePrincipal, Role, PolicyStatement} from "@aws-cdk/aws-iam";
import {CfnCodeDeployBlueGreenHook, CfnTrafficRoutingType} from '@aws-cdk/core';
import {Vpc, SecurityGroup, Port, Peer, SubnetType} from '@aws-cdk/aws-ec2';
import {Cluster, CfnCluster} from '@aws-cdk/aws-ecs';
import {ApplicationTargetGroup, ApplicationLoadBalancer, ApplicationProtocol} from '@aws-cdk/aws-elasticloadbalancingv2';

export class BlueGreenTest extends cdk.Stack {
    constructor(scope: cdk.Construct, id: string, props: cdk.StackProps) {
        super(scope, id, props)

        const vpc = new Vpc(this, 'Vpc', {maxAzs: 2, natGateways: 1});

        const albSg = new SecurityGroup(this, 'AlbSg', {vpc})
        const ecsSg = new SecurityGroup(this, 'EcsSg', {vpc})
        albSg.addIngressRule(Peer.anyIpv4(), Port.tcp(80));
        ecsSg.addIngressRule(albSg, Port.tcp(80));

        const blueAlbTg = new ApplicationTargetGroup(this, 'BlueAlbTg', {vpc});
        const greenAlbTg = new ApplicationTargetGroup(this, 'GreenAlbTg', {vpc});

        const alb = new ApplicationLoadBalancer(this, 'Alb', {
            vpc,
            vpcSubnets: {subnetType: SubnetType.PUBLIC},
            securityGroup: albSg
        });

        const prodListener = alb.addListener('Prod', {
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

        const ecsServiceBlugGreenDeplotmentHookServiceRole = new Role(this, 'EcsServiceBlugGreenDeplotmentHookServiceRole', {
            assumedBy: new ServicePrincipal('codedeploy.amazonaws.com'),
        });
        ecsServiceBlugGreenDeplotmentHookServiceRole.addToPolicy(new PolicyStatement({
            actions: ['codedeploy:Get*', 'codedeploy:CreateCloudFormationDeployment']
        }));

        const ecsServiceBlueGreenDeploymentHook = new CfnCodeDeployBlueGreenHook(this, 'EcsServiceBlueGreenDeploymentHook', {
            serviceRole: '',
            trafficRoutingConfig: {
                type: CfnTrafficRoutingType.TIME_BASED_CANARY,
                timeBasedCanary: {
                    stepPercentage: 15,
                    bakeTimeMins: 5
                }
            },
            applications: [
                {
                    target: {
                        type: 'AWS::ECS::Service',
                        logicalId: ''
                    },
                    ecsAttributes: {
                        taskDefinitions: [],
                        taskSets: [],
                        trafficRouting: {
                            prodTrafficRoute: {
                                type: 'AWS::ElasticLoadBalancingV2::Listener',
                                logicalId: ''
                            },
                            targetGroups: [''],
                            testTrafficRoute: {
                                type: 'AWS::ElasticLoadBalancingV2::Listener',
                                logicalId: ''
                            }
                        }
                    }
                }
            ]
        })
    }
}