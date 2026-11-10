-- Option B, step 1: storage integration only. Its IAM user + external id go into the AWS role trust
-- (CDK pass 2) before the stage can be created. Variables: &{role_arn} &{bucket}
USE ROLE ACCOUNTADMIN;
CREATE STORAGE INTEGRATION IF NOT EXISTS PK_LANDING_INT
  TYPE = EXTERNAL_STAGE STORAGE_PROVIDER = 'S3' ENABLED = TRUE
  STORAGE_AWS_ROLE_ARN = '&{role_arn}'
  STORAGE_ALLOWED_LOCATIONS = ('s3://&{bucket}/silver-in/');
