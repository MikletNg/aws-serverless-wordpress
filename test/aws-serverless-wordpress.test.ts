import {expect as expectCDK, matchTemplate, MatchStyle} from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import AwsServerlessWordpress = require('../lib/aws-serverless-wordpress-stack');
import {RemovalPolicy} from "@aws-cdk/core";

test('Empty Stack', () => {
    const app = new cdk.App();
    // WHEN
    const stack = new AwsServerlessWordpress.AwsServerlessWordpressStack(app, 'MyTestStack', {
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
        enableDeletionProtection: false,
        removalPolicy: RemovalPolicy.DESTROY
    });
    // THEN
    expectCDK(stack).to(matchTemplate({
        "Resources": {}
    }, MatchStyle.EXACT))
});
