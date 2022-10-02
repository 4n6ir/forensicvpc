import boto3
import json
import os

def handler(event, context):

    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    parse = key.split('/')

    if parse[0] == 'accept' or parse[0] == 'reject':

        separate = parse[2].split('%')
        chunk = separate[0].split('_')
        out = chunk[0].split('-')

        ssm_client = boto3.client('ssm')

        response = ssm_client.get_parameter(
            Name = os.environ['STEP_FUNCTION']
        )

        getobject = {}
        getobject['bucket'] = bucket
        getobject['key'] = key.replace('%3A',':')
        getobject['table'] = os.environ['DYNAMODB_TABLE']
        getobject['step'] = response['Parameter']['Value']
        getobject['state'] = parse[0].upper()
        getobject['source'] = parse[1].upper()
        getobject['year'] = str(out[0])
        getobject['month'] = str(out[1])
        getobject['day'] = str(out[2])
        getobject['hour'] = str(chunk[1])
        getobject['offset'] = 0
        getobject['transitions'] = 0

        sfn_client = boto3.client('stepfunctions')

        sfn_client.start_execution(
            stateMachineArn = response['Parameter']['Value'],
            input = json.dumps(getobject),
        )

    return {
        'statusCode': 200,
        'body': json.dumps('Step Function - Start')
    }