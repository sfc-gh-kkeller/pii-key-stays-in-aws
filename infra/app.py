"""CDK stack for the "key stays in AWS" options.

Option A: Lambda Function URL that decrypts batches for a Snowflake External Access UDF.
Option B: SQS (stands in for Kafka) -> upstream decrypt Lambda -> S3 (SSE-KMS) -> Snowpipe.

Deploy (setup.sh does this, twice):
  cdk deploy [-c sf_storage_iam_user_arn=<STORAGE_AWS_IAM_USER_ARN> -c sf_storage_external_id=<...>]
The second pass adds the trust from DESC STORAGE INTEGRATION.
"""
import os

from aws_cdk import (App, BundlingOptions, CfnOutput, Duration, RemovalPolicy, Stack,
                     aws_iam as iam, aws_kms as kms, aws_lambda as lambda_,
                     aws_lambda_event_sources as les, aws_logs as logs, aws_s3 as s3,
                     aws_secretsmanager as sm, aws_sqs as sqs)
from constructs import Construct

LAMBDA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lambda")
ROLE_NAME = "pii-key-demo-snowflake-storage"


class PiiKeyStaysInAwsStack(Stack):
    def __init__(self, scope: Construct, cid: str, **kw):
        super().__init__(scope, cid, **kw)
        sf_user = self.node.try_get_context("sf_storage_iam_user_arn")
        sf_ext_id = self.node.try_get_context("sf_storage_external_id")

        cmk = kms.Key(self, "DemoKey", alias="alias/pii-key-demo", enable_key_rotation=True,
                      removal_policy=RemovalPolicy.DESTROY, pending_window=Duration.days(7))

        # AES key ring (value written by setup.sh / rotate_key.py, playing a CI job)
        keyring = sm.Secret(self, "KeyRing", secret_name="pii-key-demo/pii-keyring", encryption_key=cmk,
                            removal_policy=RemovalPolicy.DESTROY)
        # Bearer token the Snowflake UDF presents to the decrypt API (allows decrypt calls, is not the key)
        caller_token = sm.Secret(self, "CallerToken", secret_name="pii-key-demo/decrypt-caller-token",
                                 encryption_key=cmk, removal_policy=RemovalPolicy.DESTROY,
                                 generate_secret_string=sm.SecretStringGenerator(
                                     secret_string_template="{}", generate_string_key="token",
                                     password_length=48, exclude_punctuation=True))

        code = lambda_.Code.from_asset(LAMBDA_DIR, bundling=BundlingOptions(
            image=lambda_.Runtime.PYTHON_3_12.bundling_image, platform="linux/arm64",
            command=["bash", "-c", "pip install -q -r requirements.txt -t /asset-output && cp -au *.py /asset-output"]))

        def fn(cid, handler, env, timeout=30, memory=512):
            return lambda_.Function(self, cid, runtime=lambda_.Runtime.PYTHON_3_12,
                                    architecture=lambda_.Architecture.ARM_64, handler=handler, code=code,
                                    timeout=Duration.seconds(timeout), memory_size=memory, environment=env,
                                    log_retention=logs.RetentionDays.ONE_MONTH)

        # ---------------- Option A: decrypt API for the Snowflake External Access UDF
        decrypt_fn = fn("DecryptApi", "decrypt_api.handler",
                        {"KEYRING_SECRET_ARN": keyring.secret_arn, "CALLER_TOKEN_SECRET_ARN": caller_token.secret_arn})
        keyring.grant_read(decrypt_fn)
        caller_token.grant_read(decrypt_fn)
        decrypt_url = decrypt_fn.add_function_url(auth_type=lambda_.FunctionUrlAuthType.NONE)

        # ---------------- Option B: upstream decrypt before landing
        bucket = s3.Bucket(self, "Landing", encryption=s3.BucketEncryption.KMS, encryption_key=cmk,
                           bucket_key_enabled=True, enforce_ssl=True,
                           block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                           removal_policy=RemovalPolicy.DESTROY, auto_delete_objects=True)
        dlq = sqs.Queue(self, "IngestDlq", encryption=sqs.QueueEncryption.KMS, encryption_master_key=cmk,
                        retention_period=Duration.days(14))
        queue = sqs.Queue(self, "Ingest", encryption=sqs.QueueEncryption.KMS, encryption_master_key=cmk,
                          visibility_timeout=Duration.seconds(180),
                          dead_letter_queue=sqs.DeadLetterQueue(queue=dlq, max_receive_count=3))
        upstream_fn = fn("UpstreamDecrypt", "upstream.handler",
                         {"KEYRING_SECRET_ARN": keyring.secret_arn, "LANDING_BUCKET": bucket.bucket_name,
                          "LANDING_PREFIX": "silver-in/"}, timeout=60)
        keyring.grant_read(upstream_fn)
        bucket.grant_put(upstream_fn)
        upstream_fn.add_event_source(les.SqsEventSource(queue, batch_size=500,
                                                        max_batching_window=Duration.seconds(10),
                                                        report_batch_item_failures=True))

        # Role Snowflake's storage integration assumes to read the landing prefix
        trust = (iam.ArnPrincipal(sf_user).with_conditions({"StringEquals": {"sts:ExternalId": sf_ext_id}})
                 if sf_user and sf_ext_id else iam.AccountRootPrincipal())
        sf_role = iam.Role(self, "SnowflakeStorageRole", role_name=ROLE_NAME, assumed_by=trust)
        bucket.grant_read(sf_role, "silver-in/*")
        sf_role.add_to_policy(iam.PolicyStatement(actions=["s3:ListBucket", "s3:GetBucketLocation"],
                                                  resources=[bucket.bucket_arn]))

        for k, v in {"DecryptUrl": decrypt_url.url, "DecryptLogGroup": f"/aws/lambda/{decrypt_fn.function_name}",
                     "CallerTokenSecretArn": caller_token.secret_arn, "KeyRingSecretArn": keyring.secret_arn,
                     "QueueUrl": queue.queue_url, "DlqUrl": dlq.queue_url, "BucketName": bucket.bucket_name,
                     "UpstreamLogGroup": f"/aws/lambda/{upstream_fn.function_name}",
                     "SnowflakeRoleArn": sf_role.role_arn, "KmsKeyArn": cmk.key_arn}.items():
            CfnOutput(self, k, value=v)


app = App()
PiiKeyStaysInAwsStack(app, "PiiKeyStaysInAws",
                         env={"account": os.getenv("CDK_DEFAULT_ACCOUNT"), "region": "eu-central-1"})
app.synth()
