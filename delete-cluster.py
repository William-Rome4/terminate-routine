import boto3
import json
import time
from datetime import datetime as dt

region = "us-east-1"
date_format = "%Y-%m-%d"
now = dt.now()

aws = boto3.client('sts', region_name = region)
logs = boto3.client('logs', region_name = region)
#cw = boto3.client('cloudwatch', region_name = region)
#sns = boto3.client('sns', region_name = region)
tags = boto3.client('resourcegroupstaggingapi', region_name=region)


def main():
    # Quantidade de dias até deleção 
    # [ Primeira notificação, Segunda notificação, Data do Terminate ]
    schedule = [7,3,0]

    tagged_resources = []
    
    response = tags.get_resources(
        TagFilters=[
            {
                'Key': 'Terminate'
            }
        ]
    )
    for item in response['ResourceTagMappingList']:
        tag = [tag['Value'] for tag in item['Tags'] if tag['Key'] == 'Terminate']
        tagged_resources.append({'ARN': item['ResourceARN'], 'TERMINATE': tag[0]})
    print(tagged_resources)

    for resource in tagged_resources:
        service = resource['ARN'].split(":")[2]
        name = resource['ARN'].split('/')[1]
        terminate = dt.strptime(resource['TERMINATE'],date_format)
        dif = terminate - now
        print(f"\n[INFO] Resource: {name}")
        print(f"[INFO] Terminate on {terminate.strftime('%d/%m/%Y')}")

        if dif.days+1 == schedule[0]:
            print("[INFO] Uma semana até o terminate")
            resource['MESSAGE'] = f"Recurso será terminado em {schedule[0]} dias"
            send_alert(service,resource,schedule[0])
        elif dif.days+1 == schedule[1]:
            print("[INFO] 3 dias até o terminate")
            resource['MESSAGE'] = f"Recurso será terminado em {schedule[0]} dias"
            send_alert(service,resource,schedule[1])
        elif dif.days+1 == schedule[2]:
            print("[INFO] Realizando o terminate do recurso")
            resource['MESSAGE'] = f"Realizando o terminate do recurso"
            send_alert(service,resource,schedule[2])
            delete_resource(service,resource)

def send_alert(service,resource,schedule):
    group_name = f"unbh-poc-routine-logs"
    stream_name = service.upper()
    try:
        # Utilizando o CloudWatch Logs
        logs.create_log_group(
            logGroupName=group_name,
            tags={
                "Name": group_name,
                "Repo": "unbh-dev-routine",
                "Process": "routine"
            }
        )

        logs.put_retention_policy(
            logGroupName=group_name,
            retentionInDays=90
        )
    except Exception as e:
        if e.response['Error']['Code'] == "ResourceAlreadyExistsException":
            print(f"[INFO] Log Group: {group_name} already created")
        else:
            print(f"[ERROR] {e}")

    try:
        logs.create_log_stream(
            logGroupName=group_name,
            logStreamName=stream_name
        )
    except Exception as e:
        if e.response['Error']['Code'] == "ResourceAlreadyExistsException":
            print(f"[INFO] Log Stream: {stream_name} already created")
        else:
            print(f"[ERROR] {e}")
    # Utilizando apenas SNS
    '''
    account = aws.get_caller_identity()['Account']
    message = {
        "AlarmName": f"[MI000018288] UNIMED_BH_LAKE_DEV_{service.upper()}_ROUTINE_{resource}_days = {schedule}",
        "AlarmDescription": "",
        "AWSAccountId": account,
        "NewStateValue": "OK",
        "NewStateReason": "Threshold Crossed",
        "StateChangeTime": now.strftime("%d/%m/%Y - %H:%M %Z"),
        "Region": region,
        "OldStateValue": "ALARM"
    }

    response = sns.publish(
        TopicArn='arn:aws:sns:us-east-1:207745726120:BRLinkMonitoring',
        Subject=f"[MI000018288] UNIMED_BH_LAKE_DEV_{service.upper()}_ROUTINE_{resource}_days = {schedule}",
        Message=json.dumps(message)
    )

    '''
    
    # Utilizando o CloudWatch Metrics
    '''
    response = cw.put_metric_data(
        Namespace='Routine',
        MetricData=[
            {
                'MetricName': 'Terminate',
                'Dimensions': [
                    {
                        'Name': service.upper(),
                        'Value': resource
                    }
                ],
                'Value': 1,
                'Unit': 'Count'
            }
        ]
    )
    '''
    response = logs.put_log_events(
        logGroupName=group_name,
        logStreamName=service.upper(),
        logEvents=[
            {
                'timestamp': round(time.time() * 1000),
                'message': json.dumps(resource)
            }
        ]
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        print("[DONE] Log Delivery Successful")

def delete_resource(service,resource):
    return 0

def lambda_handler(event, context):
    main()

if __name__ == "__main__":
    lambda_handler(0,0)
