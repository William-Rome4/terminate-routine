import boto3
import json
import time
import os
from datetime import datetime as dt

region = os.environ.get('region')
date_format = os.environ.get('date_format')
now = dt.now()
control_tag = os.environ.get('control_tag')
group_name = os.environ.get('group_name')
types_list=['AWS::EC2::CustomerGateway','AWS::EC2::EIP','AWS::EC2::Host','AWS::EC2::Instance','AWS::EC2::InternetGateway','AWS::EC2::NetworkAcl','AWS::EC2::NetworkInterface','AWS::EC2::RouteTable','AWS::EC2::SecurityGroup','AWS::EC2::Subnet','AWS::CloudTrail::Trail','AWS::EC2::Volume','AWS::EC2::VPC','AWS::EC2::VPNConnection','AWS::EC2::VPNGateway','AWS::EC2::RegisteredHAInstance','AWS::EC2::NatGateway','AWS::EC2::EgressOnlyInternetGateway','AWS::EC2::VPCEndpoint','AWS::EC2::VPCEndpointService','AWS::EC2::FlowLog','AWS::EC2::VPCPeeringConnection','AWS::Elasticsearch::Domain','AWS::IAM::Group','AWS::IAM::Policy','AWS::IAM::Role','AWS::IAM::User','AWS::ElasticLoadBalancingV2::LoadBalancer','AWS::ACM::Certificate','AWS::RDS::DBInstance','AWS::RDS::DBSubnetGroup','AWS::RDS::DBSecurityGroup','AWS::RDS::DBSnapshot','AWS::RDS::DBCluster','AWS::RDS::DBClusterSnapshot','AWS::RDS::EventSubscription','AWS::S3::Bucket','AWS::S3::AccountPublicAccessBlock','AWS::Redshift::Cluster','AWS::Redshift::ClusterSnapshot','AWS::Redshift::ClusterParameterGroup','AWS::Redshift::ClusterSecurityGroup','AWS::Redshift::ClusterSubnetGroup','AWS::Redshift::EventSubscription','AWS::SSM::ManagedInstanceInventory','AWS::CloudWatch::Alarm','AWS::CloudFormation::Stack','AWS::ElasticLoadBalancing::LoadBalancer','AWS::AutoScaling::AutoScalingGroup','AWS::AutoScaling::LaunchConfiguration','AWS::AutoScaling::ScalingPolicy','AWS::AutoScaling::ScheduledAction','AWS::DynamoDB::Table','AWS::CodeBuild::Project','AWS::WAF::RateBasedRule','AWS::WAF::Rule','AWS::WAF::RuleGroup','AWS::WAF::WebACL','AWS::WAFRegional::RateBasedRule','AWS::WAFRegional::Rule','AWS::WAFRegional::RuleGroup','AWS::WAFRegional::WebACL','AWS::CloudFront::Distribution','AWS::CloudFront::StreamingDistribution','AWS::Lambda::Function','AWS::NetworkFirewall::Firewall','AWS::NetworkFirewall::FirewallPolicy','AWS::NetworkFirewall::RuleGroup','AWS::ElasticBeanstalk::Application','AWS::ElasticBeanstalk::ApplicationVersion','AWS::ElasticBeanstalk::Environment','AWS::WAFv2::WebACL','AWS::WAFv2::RuleGroup','AWS::WAFv2::IPSet','AWS::WAFv2::RegexPatternSet','AWS::WAFv2::ManagedRuleSet','AWS::XRay::EncryptionConfig','AWS::SSM::AssociationCompliance','AWS::SSM::PatchCompliance','AWS::Shield::Protection','AWS::ShieldRegional::Protection','AWS::Config::ConformancePackCompliance','AWS::Config::ResourceCompliance','AWS::ApiGateway::Stage','AWS::ApiGateway::RestApi','AWS::ApiGatewayV2::Stage','AWS::ApiGatewayV2::Api','AWS::CodePipeline::Pipeline','AWS::ServiceCatalog::CloudFormationProvisionedProduct','AWS::ServiceCatalog::CloudFormationProduct','AWS::ServiceCatalog::Portfolio','AWS::SQS::Queue','AWS::KMS::Key','AWS::QLDB::Ledger','AWS::SecretsManager::Secret','AWS::SNS::Topic','AWS::SSM::FileData','AWS::Backup::BackupPlan','AWS::Backup::BackupSelection','AWS::Backup::BackupVault','AWS::Backup::RecoveryPoint','AWS::ECR::Repository','AWS::ECS::Cluster','AWS::ECS::Service','AWS::ECS::TaskDefinition','AWS::EFS::AccessPoint','AWS::EFS::FileSystem','AWS::EKS::Cluster','AWS::OpenSearch::Domain','AWS::EC2::TransitGateway','AWS::Kinesis::Stream','AWS::Kinesis::StreamConsumer','AWS::CodeDeploy::Application','AWS::CodeDeploy::DeploymentConfig','AWS::CodeDeploy::DeploymentGroup','AWS::EC2::LaunchTemplate','AWS::ECR::PublicRepository','AWS::GuardDuty::Detector','AWS::EMR::SecurityConfiguration','AWS::SageMaker::CodeRepository','AWS::Route53Resolver::ResolverEndpoint','AWS::Route53Resolver::ResolverRule','AWS::Route53Resolver::ResolverRuleAssociation','AWS::DMS::ReplicationSubnetGroup','AWS::DMS::EventSubscription','AWS::MSK::Cluster','AWS::StepFunctions::Activity','AWS::WorkSpaces::Workspace','AWS::WorkSpaces::ConnectionAlias','AWS::SageMaker::Model','AWS::ElasticLoadBalancingV2::Listener','AWS::StepFunctions::StateMachine','AWS::Batch::JobQueue','AWS::Batch::ComputeEnvironment','AWS::AccessAnalyzer::Analyzer','AWS::Athena::WorkGroup','AWS::Athena::DataCatalog','AWS::Detective::Graph','AWS::GlobalAccelerator::Accelerator','AWS::GlobalAccelerator::EndpointGroup','AWS::GlobalAccelerator::Listener','AWS::EC2::TransitGatewayAttachment','AWS::EC2::TransitGatewayRouteTable','AWS::DMS::Certificate','AWS::AppConfig::Application','AWS::AppSync::GraphQLApi','AWS::DataSync::LocationSMB','AWS::DataSync::LocationFSxLustre','AWS::DataSync::LocationS3','AWS::DataSync::LocationEFS','AWS::DataSync::Task','AWS::DataSync::LocationNFS','AWS::EC2::NetworkInsightsAccessScopeAnalysis','AWS::EKS::FargateProfile','AWS::Glue::Job','AWS::GuardDuty::ThreatIntelSet','AWS::GuardDuty::IPSet','AWS::SageMaker::Workteam','AWS::SageMaker::NotebookInstanceLifecycleConfig','AWS::ServiceDiscovery::Service','AWS::ServiceDiscovery::PublicDnsNamespace','AWS::SES::ContactList','AWS::SES::ConfigurationSet','AWS::Route53::HostedZone','AWS::IoTEvents::Input','AWS::IoTEvents::DetectorModel','AWS::IoTEvents::AlarmModel','AWS::ServiceDiscovery::HttpNamespace','AWS::Events::EventBus','AWS::ImageBuilder::ContainerRecipe','AWS::ImageBuilder::DistributionConfiguration','AWS::ImageBuilder::InfrastructureConfiguration','AWS::DataSync::LocationObjectStorage','AWS::DataSync::LocationHDFS','AWS::Glue::Classifier','AWS::Route53RecoveryReadiness::Cell','AWS::Route53RecoveryReadiness::ReadinessCheck','AWS::ECR::RegistryPolicy','AWS::Backup::ReportPlan','AWS::Lightsail::Certificate','AWS::RUM::AppMonitor','AWS::Events::Endpoint','AWS::SES::ReceiptRuleSet','AWS::Events::Archive','AWS::Events::ApiDestination','AWS::Lightsail::Disk','AWS::FIS::ExperimentTemplate','AWS::DataSync::LocationFSxWindows','AWS::SES::ReceiptFilter','AWS::GuardDuty::Filter','AWS::SES::Template','AWS::AmazonMQ::Broker','AWS::AppConfig::Environment','AWS::AppConfig::ConfigurationProfile','AWS::Cloud9::EnvironmentEC2','AWS::EventSchemas::Registry','AWS::EventSchemas::RegistryPolicy','AWS::EventSchemas::Discoverer','AWS::FraudDetector::Label','AWS::FraudDetector::EntityType','AWS::FraudDetector::Variable','AWS::FraudDetector::Outcome','AWS::IoT::Authorizer','AWS::IoT::SecurityProfile','AWS::IoT::RoleAlias','AWS::IoT::Dimension','AWS::IoTAnalytics::Datastore','AWS::Lightsail::Bucket','AWS::Lightsail::StaticIp','AWS::MediaPackage::PackagingGroup','AWS::Route53RecoveryReadiness::RecoveryGroup','AWS::ResilienceHub::ResiliencyPolicy','AWS::Transfer::Workflow','AWS::EKS::IdentityProviderConfig','AWS::EKS::Addon','AWS::Glue::MLTransform','AWS::IoT::Policy','AWS::IoT::MitigationAction','AWS::IoTTwinMaker::Workspace','AWS::IoTTwinMaker::Entity','AWS::IoTAnalytics::Dataset','AWS::IoTAnalytics::Pipeline','AWS::IoTAnalytics::Channel','AWS::IoTSiteWise::Dashboard','AWS::IoTSiteWise::Project','AWS::IoTSiteWise::Portal','AWS::IoTSiteWise::AssetModel','AWS::IVS::Channel','AWS::IVS::RecordingConfiguration','AWS::IVS::PlaybackKeyPair','AWS::KinesisAnalyticsV2::Application','AWS::RDS::GlobalCluster','AWS::S3::MultiRegionAccessPoint','AWS::DeviceFarm::TestGridProject','AWS::Budgets::BudgetsAction','AWS::Lex::Bot','AWS::CodeGuruReviewer::RepositoryAssociation','AWS::IoT::CustomMetric','AWS::Route53Resolver::FirewallDomainList','AWS::RoboMaker::RobotApplicationVersion','AWS::EC2::TrafficMirrorSession','AWS::IoTSiteWise::Gateway','AWS::Lex::BotAlias','AWS::LookoutMetrics::Alert','AWS::IoT::AccountAuditConfiguration','AWS::EC2::TrafficMirrorTarget','AWS::S3::StorageLens','AWS::IoT::ScheduledAudit','AWS::Events::Connection','AWS::EventSchemas::Schema','AWS::MediaPackage::PackagingConfiguration','AWS::KinesisVideo::SignalingChannel','AWS::AppStream::DirectoryConfig','AWS::LookoutVision::Project','AWS::Route53RecoveryControl::Cluster','AWS::Route53RecoveryControl::SafetyRule','AWS::Route53RecoveryControl::ControlPanel','AWS::Route53RecoveryControl::RoutingControl','AWS::Route53RecoveryReadiness::ResourceSet','AWS::RoboMaker::SimulationApplication','AWS::RoboMaker::RobotApplication','AWS::HealthLake::FHIRDatastore','AWS::Pinpoint::Segment','AWS::Pinpoint::ApplicationSettings','AWS::Events::Rule','AWS::EC2::DHCPOptions','AWS::EC2::NetworkInsightsPath','AWS::EC2::TrafficMirrorFilter','AWS::EC2::IPAM','AWS::IoTTwinMaker::Scene','AWS::NetworkManager::TransitGatewayRegistration','AWS::CustomerProfiles::Domain','AWS::AutoScaling::WarmPool','AWS::Connect::PhoneNumber','AWS::AppConfig::DeploymentStrategy','AWS::AppFlow::Flow','AWS::AuditManager::Assessment','AWS::CloudWatch::MetricStream','AWS::DeviceFarm::InstanceProfile','AWS::DeviceFarm::Project','AWS::EC2::EC2Fleet','AWS::EC2::SubnetRouteTableAssociation','AWS::ECR::PullThroughCacheRule','AWS::GroundStation::Config','AWS::ImageBuilder::ImagePipeline','AWS::IoT::FleetMetric','AWS::IoTWireless::ServiceProfile','AWS::NetworkManager::Device','AWS::NetworkManager::GlobalNetwork','AWS::NetworkManager::Link','AWS::NetworkManager::Site','AWS::Panorama::Package','AWS::Pinpoint::App','AWS::Redshift::ScheduledAction','AWS::Route53Resolver::FirewallRuleGroupAssociation','AWS::SageMaker::AppImageConfig','AWS::SageMaker::Image','AWS::ECS::TaskSet','AWS::Cassandra::Keyspace','AWS::Signer::SigningProfile','AWS::Amplify::App','AWS::AppMesh::VirtualNode','AWS::AppMesh::VirtualService','AWS::AppRunner::VpcConnector','AWS::AppStream::Application','AWS::CodeArtifact::Repository','AWS::EC2::PrefixList','AWS::EC2::SpotFleet','AWS::Evidently::Project','AWS::Forecast::Dataset','AWS::IAM::SAMLProvider','AWS::IAM::ServerCertificate','AWS::Pinpoint::Campaign','AWS::Pinpoint::InAppTemplate','AWS::SageMaker::Domain','AWS::Transfer::Agreement','AWS::Transfer::Connector','AWS::KinesisFirehose::DeliveryStream','AWS::Amplify::Branch','AWS::AppIntegrations::EventIntegration','AWS::AppMesh::Route','AWS::Athena::PreparedStatement','AWS::EC2::IPAMScope','AWS::Evidently::Launch','AWS::Forecast::DatasetGroup','AWS::GreengrassV2::ComponentVersion','AWS::GroundStation::MissionProfile','AWS::MediaConnect::FlowEntitlement','AWS::MediaConnect::FlowVpcInterface','AWS::MediaTailor::PlaybackConfiguration','AWS::MSK::Configuration','AWS::Personalize::Dataset','AWS::Personalize::Schema','AWS::Personalize::Solution','AWS::Pinpoint::EmailTemplate','AWS::Pinpoint::EventStream','AWS::ResilienceHub::App','AWS::ACMPCA::CertificateAuthority','AWS::AppConfig::HostedConfigurationVersion','AWS::AppMesh::VirtualGateway','AWS::AppMesh::VirtualRouter','AWS::AppRunner::Service','AWS::CustomerProfiles::ObjectType','AWS::DMS::Endpoint','AWS::EC2::CapacityReservation','AWS::EC2::ClientVpnEndpoint','AWS::Kendra::Index','AWS::KinesisVideo::Stream','AWS::Logs::Destination','AWS::Pinpoint::EmailChannel','AWS::S3::AccessPoint','AWS::NetworkManager::CustomerGatewayAssociation','AWS::NetworkManager::LinkAssociation','AWS::IoTWireless::MulticastGroup','AWS::Personalize::DatasetGroup','AWS::IoTTwinMaker::ComponentType','AWS::CodeBuild::ReportGroup','AWS::SageMaker::FeatureGroup','AWS::MSK::BatchScramSecret','AWS::AppStream::Stack','AWS::IoT::JobTemplate','AWS::IoTWireless::FuotaTask','AWS::IoT::ProvisioningTemplate','AWS::InspectorV2::Filter','AWS::Route53Resolver::ResolverQueryLoggingConfigAssociation','AWS::ServiceDiscovery::Instance','AWS::Transfer::Certificate','AWS::MediaConnect::FlowSource','AWS::APS::RuleGroupsNamespace','AWS::CodeGuruProfiler::ProfilingGroup','AWS::Route53Resolver::ResolverQueryLoggingConfig','AWS::Batch::SchedulingPolicy','AWS::ACMPCA::CertificateAuthorityActivation','AWS::AppMesh::GatewayRoute','AWS::AppMesh::Mesh','AWS::Connect::Instance','AWS::Connect::QuickConnect','AWS::EC2::CarrierGateway','AWS::EC2::IPAMPool','AWS::EC2::TransitGatewayConnect','AWS::EC2::TransitGatewayMulticastDomain','AWS::ECS::CapacityProvider','AWS::IAM::InstanceProfile','AWS::IoT::CACertificate','AWS::IoTTwinMaker::SyncJob','AWS::KafkaConnect::Connector','AWS::Lambda::CodeSigningConfig','AWS::NetworkManager::ConnectPeer','AWS::ResourceExplorer2::Index','AWS::AppStream::Fleet','AWS::Cognito::UserPool','AWS::Cognito::UserPoolClient','AWS::Cognito::UserPoolGroup','AWS::EC2::NetworkInsightsAccessScope','AWS::EC2::NetworkInsightsAnalysis','AWS::Grafana::Workspace','AWS::GroundStation::DataflowEndpointGroup','AWS::ImageBuilder::ImageRecipe','AWS::KMS::Alias','AWS::M2::Environment','AWS::QuickSight::DataSource','AWS::QuickSight::Template','AWS::QuickSight::Theme','AWS::RDS::OptionGroup','AWS::Redshift::EndpointAccess','AWS::Route53Resolver::FirewallRuleGroup','AWS::SSM::Document']

aws = boto3.client('sts', region_name = region)
config = boto3.client('config', region_name = region)
cf = boto3.client('cloudformation', region_name = region)
logs = boto3.client('logs', region_name = region)
tags = boto3.client('resourcegroupstaggingapi', region_name=region)

def create_log_group():
    try:
        logs.create_log_group(
            logGroupName=group_name,
            tags={
                "Name": group_name,
                "REPO": "unbh-dev-terminate-routine",
                "APLICACAO": "terminate-routine"
            }
        )

        logs.put_retention_policy(
            logGroupName=group_name,
            retentionInDays=90
        )
    except Exception as e:
        if e.response['Error']['Code'] != "ResourceAlreadyExistsException":
            print(f"[ERROR] {e}")

def search_resources(event):
    # Notifications are disabled
    #schedule = [7,3,0]
    if event:
        print(event)
        #now = dt.strptime(event['Date'], date_format)
    tagged_resources = []
    
    paginator = tags.get_paginator("get_resources")
    
    params = {
        'TagFilters':[
            {
                'Key': control_tag,
                'Values': [f'{now.strftime(date_format)}']
            }
        ],
        'ResourcesPerPage':100
    }
    
    for page in paginator.paginate(**params):
        if not page['ResourceTagMappingList']:
            print(f"[INFO] No resources found with tag {control_tag} for {now.strftime("%d/%m/%Y")}.")
            print("[END] Exiting terminate routine...")
            return 0
        
        for item in page['ResourceTagMappingList']:
            tag = [tag['Value'] for tag in item['Tags'] if tag['Key'] == control_tag]
            tagged_resources.append({'ARN': item['ResourceARN'], control_tag: tag[0]})

    print("[INFO] Analyzing resources:")

    for resource in tagged_resources:
        slash = resource['ARN'].count('/')
        service = resource['ARN'].split(":")[2]
        if slash > 0:
            category = resource['ARN'].split(':')[5].split('/')[0]
            name = resource['ARN'].split('/')[1]
        else:
            separator = resource['ARN'].count(':')
            category = resource['ARN'].split(':')[separator-1]
            name = resource['ARN'].split(':')[separator]
            
        resource_type = [element for element in types_list if service in element.lower() and category in element.lower()]
            
        #Logic for resources that don't Terminate. Skipping the loop
        if resource[control_tag] == "NA":
            continue
        
        print(json.dumps({"Name": name,"Service": service.upper(),f"{control_tag}": terminate.strftime('%d/%m/%Y')}))

        # Here we use AWS Config to validate if the resources were already deleted, skipping manual inspection
        if resource_type:
            check_deletion(resource_type, name)
        else:
            print(f"[INFO] Resource '{name}' is not supported by AWS Config. Please verify if it has been scheduled for deletion.")
            
        resource['MESSAGE'] = f"Realizando o terminate do recurso"
        send_alert(service,resource,0)
        if service.upper() == "CLOUDFORMATION":
            print("[INFO] Starting resource termination")
            delete_resource(service,name)
                
    print("[END] Exiting terminate routine...")

def send_alert(service,resource,schedule):
    stream_name = service.upper()
    try:
        logs.create_log_stream(
            logGroupName=group_name,
            logStreamName=stream_name
        )
    except Exception as e:
        if e.response['Error']['Code'] != "ResourceAlreadyExistsException":
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


def check_deletion(resource_type, name):
    for item in resource_type:
        print(f"[INFO] Searching for mathces on type: {item}")
        try:
            response = config.get_resource_config_history(
                resourceType=item,
                resourceId=name,
                limit=1
            )
            for r in response['configurationItems']:
                if r['configurationItemStatus'] == "ResourceDeleted" or r['configurationItemStatus'] == "ResourceDeletedNotRecorded":
                    print(f"[INFO] Resource '{name}' already deleted")
                    return 0
        except Exception as e:
            if e.response['Error']['Code'] == "ResourceNotDiscoveredException":
                print(f"[WARN] Resource '{name}' not recorded by AWS Config")
                continue
            else:
                print(f"[ERROR] {e}")

def delete_resource(service,name):
    try:
        print(f"[INFO] Preparing deletion of Stack: '{name}'")
        print("[HALT] Deleting Stack...")
        response = cf.delete_stack(
            StackName=name,
        )
    except Exception as e:
        print(e)

def lambda_handler(event, context):
    create_log_group() 
    search_resources(event)
