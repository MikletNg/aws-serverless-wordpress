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
        account: '751225572132'
    },
    databaseCredential: {
        username: 'wordpress',
        defaultDatabaseName: 'wordpress'
    },
    domainName: 'blog.miklet.pro',
    hostname: 'blog.miklet.pro',
    alternativeHostname: ['*.blog.miklet.pro'],
    snsEmailSubscription: ['mike@miklet.pro'],
});
Tags.of(stack).add('aws-config:cloudformation:stack-name', stack.stackName);
