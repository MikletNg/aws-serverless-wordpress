#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import {RemovalPolicy, Tags} from '@aws-cdk/core';
import {AwsServerlessWordpressStack} from '../lib/aws-serverless-wordpress-stack';
import {AwsServerlessWordpressTestStack} from "../lib/aws-serverless-wordpress-test-stack";

const app = new cdk.App();
new AwsServerlessWordpressTestStack(app, 'AwsServerlessWordpressTestStack', {
    terminationProtection: false,
    resourceDeletionProtection: false,
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
    removalPolicy: RemovalPolicy.DESTROY,
    snsEmailSubscription: ['mike@miklet.pro'],
});

// const stack = new AwsServerlessWordpressStack(app, 'AwsServerlessWordpressStack', {
//     terminationProtection: true,
//     resourceDeletionProtection: true,
//     env: {
//         region: 'us-east-1',
//     },
//     databaseCredential: {
//         username: 'wordpress-user',
//         defaultDatabaseName: 'wordpress'
//     },
//     domainName: 'blog.miklet.pro',
//     hostname: 'blog.miklet.pro',
//     alternativeHostname: ['*.blog.miklet.pro'],
//     removalPolicy: RemovalPolicy.DESTROY,
//     snsEmailSubscription: ['mike@miklet.pro'],
// });
// Tags.of(stack).add('aws:cloudformation:stack-name', stack.stackName);
