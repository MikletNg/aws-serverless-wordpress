#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import {RemovalPolicy, Tags} from '@aws-cdk/core';
import {AwsServerlessWordpressStack} from '../lib/aws-serverless-wordpress-stack';

const app = new cdk.App();
const stack = new AwsServerlessWordpressStack(app, 'AwsServerlessWordpressStack', {
    terminationProtection: false,
    resourceDeletionProtection: false,
    removalPolicy: RemovalPolicy.DESTROY,
    env: {
        region: 'us-east-1',
        account: 'YOUR_AWS_ACCOUNT_ID'
    },
    databaseCredential: {
        username: 'wordpress',
        defaultDatabaseName: 'wordpress'
    },
    domainName: 'blog.example.com',
    hostname: 'blog.example.com',
    alternativeHostname: ['*.blog.example.com'],
    snsEmailSubscription: [],
    // This load balancer account ID should not be change if you deploy in us-east-1
    // https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#access-logging-bucket-permissions
    loadBalancerAccountId: '127311923021'
});
Tags.of(stack).add('aws-config:cloudformation:stack-name', stack.stackName);
