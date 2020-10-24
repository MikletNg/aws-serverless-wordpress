#!/usr/bin/env node
import 'source-map-support/register';
import fs = require('fs');
import path = require('path');
import * as cdk from '@aws-cdk/core';
import {RemovalPolicy, Tags} from '@aws-cdk/core';
import {AwsServerlessWordpressStack} from '../lib/aws-serverless-wordpress-stack';
import * as toml from 'toml';

interface IConfigEnvironment {
    region: string
    account: string
}

interface IConfigAdmin {
    allowIpAddresses: string[]
    serverCertificateArn: string
    clientCertificateArn: string
}

interface IConfigDatabase {
    username: string
    defaultDatabaseName: string
}

interface IConfigDomain {
    domainName: string
    hostname: string
    alternativeHostname: string
}

interface IConfigContact {
    email: string[]
}

interface IConfig {
    environment: IConfigEnvironment
    admin: IConfigAdmin
    database: IConfigDatabase
    domain: IConfigDomain
    contact: IConfigContact
}

const config: IConfig = toml.parse(fs.readFileSync(path.join(__dirname, 'config.toml')).toString());

const app = new cdk.App();
const stack = new AwsServerlessWordpressStack(app, 'AwsServerlessWordpressStack', {
    terminationProtection: false,
    resourceDeletionProtection: false,
    removalPolicy: RemovalPolicy.DESTROY,
    env: {region: 'us-east-1', account: config.environment.account},
    databaseCredential: {username: config.database.username, defaultDatabaseName: config.database.defaultDatabaseName},
    domainName: config.domain.domainName,
    hostname: config.domain.hostname,
    alternativeHostname: [...config.domain.alternativeHostname],
    snsEmailSubscription: [...config.contact.email],
    whitelistIpAddress: [...config.admin.allowIpAddresses],
    certificate: {server: config.admin.serverCertificateArn, client: config.admin.clientCertificateArn},
    // This load balancer account ID should not be change if you deploy in us-east-1
    // https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#access-logging-bucket-permissions
    loadBalancerAccountId: '127311923021'
});
Tags.of(stack).add('aws-config:cloudformation:stack-name', stack.stackName, {excludeResourceTypes: ['AWS::ResourceGroups::Group']});