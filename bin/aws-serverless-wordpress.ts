#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import { AwsServerlessWordpressStack } from '../lib/aws-serverless-wordpress-stack';

const app = new cdk.App();
new AwsServerlessWordpressStack(app, 'AwsServerlessWordpressStack');
