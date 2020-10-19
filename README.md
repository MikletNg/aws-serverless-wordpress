# AWS Serverless WordPress

## Introduction
This CDK project attempt to use serverless services on AWS to deploy a high ava
### WordPress Plugin Used
- W3 Total Cache
- WP Offload SES Lite
- WP Offload Media Lite
- ElasticPress
- HumanMade - AWS-XRay (Working on making it work...)
## Architecture Diagram
![Architecture Diagram](doc/architecture-diagram.png)

## Deployment
*Please be notice, this stack only can deploy into us-east-1*
0. Install Docker
1. Install AWS CLI
2. Configure AWS profile through AWS CLI
3. Install the latest version of AWS CDK CLI
4. Deploy the CDK Toolkit stack on to the target region.
5. Initialize the CDK project, run `make init`
6. Modify the configuration in `bin/aws-serverless-wordpress.ts`
7. Run `make deploy profile=YOUR_AWS_PROFILE_NAME`
8. After the CloudFormation stack deployed, open the Session Manager in System Manager, and open a session to the created bastion host. Then run the following command. (The version of WordPress plugin may NOT be latest)
    ```shell script
    sudo su -
    mkdir -p /mnt/efs &&\
    mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport nfs.blog.miklet.pro.private:/ /mnt/efs &&\
    cd /mnt/efs/wp-content/plugins &&\
    curl -O https://downloads.wordpress.org/plugin/w3-total-cache.0.15.1.zip &&\
    curl -O https://downloads.wordpress.org/plugin/wp-ses.1.4.3.zip &&\
    curl -O https://downloads.wordpress.org/plugin/amazon-s3-and-cloudfront.2.4.4.zip &&\
    curl -O https://downloads.wordpress.org/plugin/elasticpress.zip &&\
    curl https://codeload.github.com/humanmade/aws-xray/zip/1.2.12 -o humanmade-aws-xray-1.2.12.zip &&\
    unzip '*.zip' &&\
    rm -rf *.zip
    ```
9. After the installation, go to the webpage and setup the database connection and plugin configuration. For the hostname of Memcached or MySQL, please check the output in CloudFormation stack.

## References
https://aws.amazon.com/tw/blogs/devops/build-a-continuous-delivery-pipeline-for-your-container-images-with-amazon-ecr-as-source/
https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/blue-green.html

https://docs.aws.amazon.com/codepipeline/latest/userguide/tutorials-ecs-ecr-codedeploy.html#tutorials-ecs-ecr-codedeploy-cluster
https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-networking.html
https://stackoverflow.com/questions/56535632/how-do-i-link-2-containers-running-in-a-aws-ecs-task

https://github.com/Monogramm/docker-wordpress
https://github.com/fjudith/docker-wordpress
https://github.com/humanmade/aws-xray

https://pecl.php.net/package/memcached
https://pecl.php.net/package/APCu

https://stackoverflow.com/questions/54772120/docker-links-with-awsvpc-network-mode

https://www.mgt-commerce.com/blog/aws-varnish-auto-scaling-magento/

https://downloads.wordpress.org/plugin/w3-total-cache.0.15.1.zip
https://downloads.wordpress.org/plugin/wp-ses.1.4.3.zip
https://downloads.wordpress.org/plugin/amazon-s3-and-cloudfront.2.4.4.zip
https://downloads.wordpress.org/plugin/elasticpress.zip