import boto3
from datetime import datetime as dt

region = "us-east-1"
cw = boto3.client('cloudwatch', region_name = region)
tags = boto3.client('resourcegroupstaggingapi', region_name=region)
date_format = "%Y-%m-%d"
now = dt.now()

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
        print(f"\nResource: {name}")
        print(f"Terminate on {terminate.strftime('%d/%m/%Y')}")

        if dif.days+1 == schedule[0]:
            print("Uma semana até o terminate")
            send_alert(service,name,schedule[0])
        elif dif.days+1 == schedule[1]:
            print("3 dias até o terminate")
            send_alert(service,name,schedule[1])
        elif dif.days+1 == schedule[2]:
            print("Realizando o terminate do recurso")
            send_alert(service,name,schedule[2])

def send_alert(service,resource,schedule):
    try:
        # TODO método de envio de alertas (Provável uso do SNS diretamente)
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
    except Exception as e:
        print(e)

def lambda_handler(event, context):
    main()

if __name__ == "__main__":
    lambda_handler(0,0)
