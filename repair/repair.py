import boto3
import json
import os

def handler(event, context):

    client = boto3.client('athena')

    response = client.start_query_execution(
        QueryString = "MSCK REPAIR TABLE forensicvpc.flowlogs",
        ResultConfiguration = {
            'OutputLocation': 's3://'+os.environ['BUCKET']+'/Temp/'
        }
    )

    return {
        'statusCode': 200,
        'body': json.dumps('Athena Table - Repair')
    }