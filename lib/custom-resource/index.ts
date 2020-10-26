import AWS = require('aws-sdk');

const s3 = new AWS.S3();
export const handler = async (evt: any) => {
    const requestType = evt.RequestType;
    if (requestType === 'Delete') {
        let objects;
        do {
            objects = await s3.listObjectsV2({Bucket: process.env.LOGGING_BUCKET_NAME!}).promise();
            if (objects.Contents) {
                await s3.deleteObjects({
                    Bucket: process.env.LOGGING_BUCKET_NAME!,
                    Delete: {Objects: [...objects.Contents.filter(_object => _object.Key).map(_object => ({Key: _object.Key!}))]}
                }).promise();
            }
        } while (objects.IsTruncated || objects.NextContinuationToken)
    }
}