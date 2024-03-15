import boto3
from datetime import datetime

region = "us-east-1"
client = boto3.client('ecs', region_name = region)

date_format = "%Y-%m-%d"
now = datetime.now()
Terminate = datetime.strptime("2024-03-15", date_format)

if Terminate - now == 7:
    print("Uma semana até o terminate")
    #Alerta no ITSM
elif Terminate - now == 3:
    print("3 dias até o terminate")
    #Alerta no ITSM
elif Terminate.strftime(date_format) == now.strftime(date_format):
    print("Realizando o terminate do recurso")
    response = client.describe_clusters()
    print(response)
