#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import {RemovalPolicy, Tags} from '@aws-cdk/core';
import {AwsServerlessWordpressStack} from '../lib/aws-serverless-wordpress-stack';

const app = new cdk.App();
const stack = new AwsServerlessWordpressStack(app, 'AwsServerlessWordpressStack', {
    env: {
        region: 'ap-southeast-1'
    },
    databaseCredential: {
        username: 'wordpress-user',
        defaultDatabaseName: 'wordpress'
    },
    domainName: 'blog.miklet.pro',
    hostname: 'blog.miklet.pro',
    alternativeHostname: ['*.blog.miklet.pro'],
    enableDeletionProtection: true,
    removalPolicy: RemovalPolicy.DESTROY,
    snsEmailSubscription: ['empty@miklet.pro'],
});

Tags.of(stack).add('aws:cloudformation:stack-name', stack.stackName);
