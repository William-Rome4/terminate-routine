import boto3
import json
import time
from datetime import datetime as dt

region = "us-east-1"
date_format = "%Y-%m-%d"
now = dt.now()
group_name = f"unbh-poc-routine-logs"

aws = boto3.client('sts', region_name = region)
logs = boto3.client('logs', region_name = region)
tags = boto3.client('resourcegroupstaggingapi', region_name=region)

def create_log_group():
    try:
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
            print(f"[INFO] Log Group: '{group_name}' already created")
        else:
            print(f"[ERROR] {e}")

def search_resources():
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

    for resource in tagged_resources:
        service = resource['ARN'].split(":")[2]
        name = resource['ARN'].split('/')[1]
        terminate = dt.strptime(resource['TERMINATE'],date_format)
        dif = terminate - now
        
        if service not in ['ec2','ecs','rds']:
            print(f"[WARN] Service '{service.upper()}' not supported. Ignoring Terminate")
            return 0

        print(f"\n[INFO] Resource: {name}")
        print(f"[INFO] Terminate on {terminate.strftime('%d/%m/%Y')}")

        if dif.days+1 == schedule[0]:
            print("[INFO] Uma semana até o terminate")
            resource['MESSAGE'] = f"Recurso será terminado em {schedule[0]} dias"
            send_alert(service,resource,schedule[0])
        elif dif.days+1 == schedule[1]:
            print("[INFO] 3 dias até o terminate")
            resource['MESSAGE'] = f"Recurso será terminado em {schedule[1]} dias"
            send_alert(service,resource,schedule[1])
        elif dif.days+1 == schedule[2]:
            print("[INFO] Realizando o terminate do recurso")
            resource['MESSAGE'] = f"Realizando o terminate do recurso"
            send_alert(service,resource,schedule[2])
            delete_resource(service,resource)

def send_alert(service,resource,schedule):
    stream_name = service.upper()
    try:
        logs.create_log_stream(
            logGroupName=group_name,
            logStreamName=stream_name
        )
    except Exception as e:
        if e.response['Error']['Code'] == "ResourceAlreadyExistsException":
            print(f"[INFO] Log Stream: '{stream_name}' already created")
        else:
            print(f"[ERROR] {e}")
    
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
    try:
        client = boto3.client(service,region_name=region)
        if service == "ecs":
            print(f"[DELETE] Realizando delete do cluster {resource['ARN'].split('/')[1]}")
            response = client.delete_cluster(
                cluster=resource['ARN']
            )
            print(response)
    except Exception as e:
        print(e)

def lambda_handler(event, context):
    create_log_group() 
    search_resources()

if __name__ == "__main__":
    lambda_handler(0,0)
