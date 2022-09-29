import boto3
import json
import os
from datetime import datetime, timedelta

def handler(event, context):
    
    now = datetime.now()
    fname = str(now).replace(' ','_')
    lasthour = datetime.now() - timedelta(hours = 1)
    previous = lasthour.strftime('%Y-%m-%d %H:%M:%S')
    parse = previous.split(' ')
    dated = parse[0].split('-')
    timed = parse[1].split(':')

    client = boto3.client('athena')

    ### ACCEPT ###

    response = client.start_query_execution(
        QueryString = "UNLOAD (SELECT DISTINCT(srcaddr), COUNT(*) AS addrCount FROM forensicvpc.flowlogs WHERE year = '"+dated[0]+"' AND month = '"+dated[1]+"' AND day = '"+dated[2]+"' AND hour = '"+timed[0]+"' AND action = 'ACCEPT' GROUP BY srcaddr) TO 's3://"+os.environ['BUCKET']+"/accept/srcaddr/"+fname+"/' WITH (format = 'TEXTFILE', field_delimiter = ',')",
        ResultConfiguration = {
            'OutputLocation': 's3://'+os.environ['BUCKET']+'/Temp/'
        }
    )

    response = client.start_query_execution(
        QueryString = "UNLOAD (SELECT DISTINCT(dstaddr), COUNT(*) AS addrCount FROM forensicvpc.flowlogs WHERE year = '"+dated[0]+"' AND month = '"+dated[1]+"' AND day = '"+dated[2]+"' AND hour = '"+timed[0]+"' AND action = 'ACCEPT' GROUP BY dstaddr) TO 's3://"+os.environ['BUCKET']+"/accept/dstaddr/"+fname+"/' WITH (format = 'TEXTFILE', field_delimiter = ',')",
        ResultConfiguration = {
            'OutputLocation': 's3://'+os.environ['BUCKET']+'/Temp/'
        }
    )

    response = client.start_query_execution(
        QueryString = "UNLOAD (SELECT DISTINCT(pkt_srcaddr), COUNT(*) AS addrCount FROM forensicvpc.flowlogs WHERE year = '"+dated[0]+"' AND month = '"+dated[1]+"' AND day = '"+dated[2]+"' AND hour = '"+timed[0]+"' AND action = 'ACCEPT' GROUP BY pkt_srcaddr) TO 's3://"+os.environ['BUCKET']+"/accept/pkt_srcaddr/"+fname+"/' WITH (format = 'TEXTFILE', field_delimiter = ',')",
        ResultConfiguration = {
            'OutputLocation': 's3://'+os.environ['BUCKET']+'/Temp/'
        }
    )

    response = client.start_query_execution(
        QueryString = "UNLOAD (SELECT DISTINCT(pkt_dstaddr), COUNT(*) AS addrCount FROM forensicvpc.flowlogs WHERE year = '"+dated[0]+"' AND month = '"+dated[1]+"' AND day = '"+dated[2]+"' AND hour = '"+timed[0]+"' AND action = 'ACCEPT' GROUP BY pkt_dstaddr) TO 's3://"+os.environ['BUCKET']+"/accept/pkt_dstaddr/"+fname+"/' WITH (format = 'TEXTFILE', field_delimiter = ',')",
        ResultConfiguration = {
            'OutputLocation': 's3://'+os.environ['BUCKET']+'/Temp/'
        }
    )
    
    ### REJECT ###

    response = client.start_query_execution(
        QueryString = "UNLOAD (SELECT DISTINCT(srcaddr), COUNT(*) AS addrCount FROM forensicvpc.flowlogs WHERE year = '"+dated[0]+"' AND month = '"+dated[1]+"' AND day = '"+dated[2]+"' AND hour = '"+timed[0]+"' AND action = 'REJECT' GROUP BY srcaddr) TO 's3://"+os.environ['BUCKET']+"/reject/srcaddr/"+fname+"/' WITH (format = 'TEXTFILE', field_delimiter = ',')",
        ResultConfiguration = {
            'OutputLocation': 's3://'+os.environ['BUCKET']+'/Temp/'
        }
    )

    response = client.start_query_execution(
        QueryString = "UNLOAD (SELECT DISTINCT(dstaddr), COUNT(*) AS addrCount FROM forensicvpc.flowlogs WHERE year = '"+dated[0]+"' AND month = '"+dated[1]+"' AND day = '"+dated[2]+"' AND hour = '"+timed[0]+"' AND action = 'REJECT' GROUP BY dstaddr) TO 's3://"+os.environ['BUCKET']+"/reject/dstaddr/"+fname+"/' WITH (format = 'TEXTFILE', field_delimiter = ',')",
        ResultConfiguration = {
            'OutputLocation': 's3://'+os.environ['BUCKET']+'/Temp/'
        }
    )

    response = client.start_query_execution(
        QueryString = "UNLOAD (SELECT DISTINCT(pkt_srcaddr), COUNT(*) AS addrCount FROM forensicvpc.flowlogs WHERE year = '"+dated[0]+"' AND month = '"+dated[1]+"' AND day = '"+dated[2]+"' AND hour = '"+timed[0]+"' AND action = 'REJECT' GROUP BY pkt_srcaddr) TO 's3://"+os.environ['BUCKET']+"/reject/pkt_srcaddr/"+fname+"/' WITH (format = 'TEXTFILE', field_delimiter = ',')",
        ResultConfiguration = {
            'OutputLocation': 's3://'+os.environ['BUCKET']+'/Temp/'
        }
    )

    response = client.start_query_execution(
        QueryString = "UNLOAD (SELECT DISTINCT(pkt_dstaddr), COUNT(*) AS addrCount FROM forensicvpc.flowlogs WHERE year = '"+dated[0]+"' AND month = '"+dated[1]+"' AND day = '"+dated[2]+"' AND hour = '"+timed[0]+"' AND action = 'REJECT' GROUP BY pkt_dstaddr) TO 's3://"+os.environ['BUCKET']+"/reject/pkt_dstaddr/"+fname+"/' WITH (format = 'TEXTFILE', field_delimiter = ',')",
        ResultConfiguration = {
            'OutputLocation': 's3://'+os.environ['BUCKET']+'/Temp/'
        }
    )

    return {
        'statusCode': 200,
        'body': json.dumps('VPC Flow Logs - Parse')
    }