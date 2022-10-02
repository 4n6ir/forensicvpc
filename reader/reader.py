import boto3
import json
import os
from smart_open import open

def handler(event, context):

    bucket = event['event']['bucket']
    key = event['event']['key']
    table = event['event']['table']
    step = event['event']['step']
    state = event['event']['state']
    source = event['event']['source']
    year = event['event']['year']
    month = event['event']['month']
    day = event['event']['day']
    hour = event['event']['hour']
    offset = event['event']['offset']
    transitions = event['event']['transitions']

    dynamodb = boto3.resource('dynamodb')
    db = dynamodb.Table(table)
    
    limit = 'NO'
    
    with open('s3://'+bucket+'/'+key, 'rb') as f:

        f.seek(offset)

        with db.batch_writer(overwrite_by_pkeys = ['pk','sk']) as batch:

            for count, value in enumerate(f):
    
                if count == 25: 
                    status = 'CONTINUE'
                    break
                else:
                    status = 'SUCCEEDED'

                offset = offset + len(value)

                output = value[:-1].decode().split(',')

                batch.put_item(
                    Item = {
                        'pk': output[0],
                        'sk': '#'+state+'#'+source+'#'+year+'#'+month+'#'+day+'#'+hour,
                        'count': output[1]
                    }    
                )

    transitions += 1
    
    if transitions == 2500:
        
        limit = 'YES'
        transitions = 0

    getobject = {}
    getobject['bucket'] = bucket
    getobject['key'] = key
    getobject['table'] = table
    getobject['step'] = step
    getobject['state'] = state
    getobject['source'] = source
    getobject['year'] = year
    getobject['month'] = month
    getobject['day'] = day
    getobject['hour'] = hour
    getobject['offset'] = offset
    getobject['transitions'] = transitions

    if limit == 'YES':

        sfn_client = boto3.client('stepfunctions')

        sfn_client.start_execution(
            stateMachineArn = step,
            input = json.dumps(getobject),
        )
   
        status = 'SUCCEEDED'

    return {
        'event': getobject,
        'status': status,
    }