import os
import logging
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_neptune_cluster_info(neptune_client, cluster_id):
    """Get Neptune cluster information with retries."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = neptune_client.describe_db_clusters(
                DBClusterIdentifier=cluster_id
            )
            if response['DBClusters']:
                return response['DBClusters'][0]
            raise ValueError(f"Neptune cluster {cluster_id} not found")
        except ClientError as e:
            if attempt == max_retries - 1:
                raise
            logger.warning(f"Attempt {attempt + 1} failed: {str(e)}")
            time.sleep(2 ** attempt)
    return None

def configure_security_group(ec2_client, sg_id, vpc_id):
    """Configure security group rules for Neptune access."""
    try:
        # First check if rule already exists
        sg_info = ec2_client.describe_security_groups(GroupIds=[sg_id])
        existing_rules = sg_info['SecurityGroups'][0]['IpPermissions']
        
        neptune_rules = [
            {
                'IpProtocol': 'tcp',
                'FromPort': 8182,
                'ToPort': 8182,
                'IpRanges': [{
                    'CidrIp': '0.0.0.0/0',
                    'Description': 'Allow Replit access to Neptune'
                }]
            },
            {
                'IpProtocol': 'tcp',
                'FromPort': 8182,
                'ToPort': 8182,
                'UserIdGroupPairs': [{
                    'GroupId': sg_id,
                    'Description': 'Allow self-referential access for Neptune'
                }]
            }
        ]
        
        # Check if Neptune rules exist
        for neptune_rule in neptune_rules:
            rule_exists = False
            
            if 'IpRanges' in neptune_rule:
                rule_exists = any(
                    rule.get('FromPort') == 8182 and
                    rule.get('ToPort') == 8182 and
                    any(ip_range.get('CidrIp') == '0.0.0.0/0' 
                        for ip_range in rule.get('IpRanges', []))
                    for rule in existing_rules
                )
            elif 'UserIdGroupPairs' in neptune_rule:
                rule_exists = any(
                    rule.get('FromPort') == 8182 and
                    rule.get('ToPort') == 8182 and
                    any(pair.get('GroupId') == sg_id
                        for pair in rule.get('UserIdGroupPairs', []))
                    for rule in existing_rules
                )
            
            if not rule_exists:
                logger.info(f"Adding new security group rule for port 8182...")
                try:
                    ec2_client.authorize_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=[neptune_rule]
                    )
                    logger.info("✓ Security group ingress rule added")
                except ClientError as e:
                    if e.response['Error']['Code'] != 'InvalidPermission.Duplicate':
                        raise
                    logger.info("Rule already exists, skipping...")
        
        # Configure egress rules
        egress_rules = [
            {
                'IpProtocol': '-1',  # All traffic
                'FromPort': -1,
                'ToPort': -1,
                'IpRanges': [{
                    'CidrIp': '0.0.0.0/0',
                    'Description': 'Allow all outbound traffic'
                }]
            },
            {
                'IpProtocol': 'tcp',
                'FromPort': 8182,
                'ToPort': 8182,
                'UserIdGroupPairs': [{
                    'GroupId': sg_id,
                    'Description': 'Allow Neptune cluster communication'
                }]
            }
        ]
        
        for egress_rule in egress_rules:
            try:
                ec2_client.authorize_security_group_egress(
                    GroupId=sg_id,
                    IpPermissions=[egress_rule]
                )
                logger.info("✓ Security group egress rule added")
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidPermission.Duplicate':
                    raise
                logger.info("Egress rule already exists, skipping...")
        
        logger.info("✓ All security group rules configured successfully")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
            logger.info("✓ Security group rules already exist")
            return True
        raise

def configure_subnet_groups(neptune_client, ec2_client, vpc_id, cluster_id):
    """Configure subnet groups for Neptune cluster."""
    try:
        # Get all subnets in the VPC
        subnets = ec2_client.describe_subnets(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'state', 'Values': ['available']}
            ]
        )['Subnets']
        
        if not subnets:
            raise ValueError(f"No subnets found in VPC {vpc_id}")
            
        # Group subnets by AZ and select one from each AZ
        az_subnets = {}
        for subnet in subnets:
            az = subnet['AvailabilityZone']
            if az not in az_subnets:
                az_subnets[az] = []
            az_subnets[az].append(subnet['SubnetId'])
            
        if len(az_subnets) < 2:
            raise ValueError(f"Neptune requires subnets in at least 2 AZs. Found only {len(az_subnets)} AZs")
            
        # Select one subnet from each AZ
        subnet_ids = [subnets[0] for subnets in az_subnets.values()]
        logger.info(f"Found {len(subnet_ids)} subnets across {len(az_subnets)} availability zones")
        
        # Create DB subnet group if it doesn't exist
        subnet_group_name = f"{cluster_id}-subnet-group"
        try:
            neptune_client.describe_db_subnet_groups(
                DBSubnetGroupName=subnet_group_name
            )
            logger.info(f"Subnet group {subnet_group_name} already exists")
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBSubnetGroupNotFoundFault':
                logger.info(f"Creating new subnet group: {subnet_group_name}")
                neptune_client.create_db_subnet_group(
                    DBSubnetGroupName=subnet_group_name,
                    DBSubnetGroupDescription=f"Subnet group for Neptune cluster {cluster_id}",
                    SubnetIds=subnet_ids
                )
                logger.info("✓ Created new DB subnet group")
            else:
                raise
                
        return subnet_ids
    except Exception as e:
        logger.error(f"Failed to configure subnet groups: {str(e)}")
        if isinstance(e, ClientError):
            logger.error(f"AWS Error Code: {e.response['Error']['Code']}")
            logger.error(f"AWS Error Message: {e.response['Error']['Message']}")
        raise

def configure_vpc_access():
    """Configure VPC and security group settings for Neptune access from Replit."""
    try:
        # Initialize boto3 clients with retry configuration
        logger.info("Initializing AWS clients...")
        # Set region to us-east-2 (Ohio)
        region = 'us-east-2'
        logger.info(f"Configuring AWS resources in region: {region} (Ohio)")
        config = Config(
            region_name=region,
            retries={
                'max_attempts': 3,
                'mode': 'standard'
            }
        )
        
        ec2 = boto3.client('ec2', config=config)
        neptune = boto3.client('neptune', config=config)
        
        # Get Neptune cluster info
        endpoint = os.getenv('NEPTUNE_ENDPOINT')
        if not endpoint:
            raise ValueError("NEPTUNE_ENDPOINT environment variable is missing")
            
        cluster_id = endpoint.split('.')[0]
        logger.info(f"Getting Neptune cluster info for: {cluster_id}")
        
        try:
            logger.info(f"Attempting to get cluster info for {cluster_id}...")
            cluster = get_neptune_cluster_info(neptune, cluster_id)
            if not cluster:
                raise ValueError(f"Could not retrieve cluster info for {cluster_id}")
            logger.info("Successfully retrieved cluster information")
            
            # Extract VPC and security group IDs
            vpc_security_groups = cluster.get('VpcSecurityGroups', [])
            logger.info(f"Found {len(vpc_security_groups)} VPC security groups")
            
            if not vpc_security_groups:
                raise ValueError("No VPC security groups found for Neptune cluster")
                
            sg_id = vpc_security_groups[0].get('VpcSecurityGroupId')
            if not sg_id:
                raise ValueError("Security group ID not found")
                
            # Get VPC ID from security group
            sg_info = ec2.describe_security_groups(GroupIds=[sg_id])
            vpc_id = sg_info['SecurityGroups'][0]['VpcId']
            
            logger.info(f"Neptune cluster VPC ID: {vpc_id}")
            logger.info(f"Neptune cluster Security Group ID: {sg_id}")
            
            # Configure security group rules
            if not configure_security_group(ec2, sg_id, vpc_id):
                raise ValueError("Failed to configure security group rules")
            
            # Configure subnet groups and get subnet IDs
            subnet_ids = configure_subnet_groups(neptune, ec2, vpc_id, cluster_id)
            if not subnet_ids:
                logger.error("Failed to configure subnet groups")
                return False
                
            logger.info(f"Successfully configured subnet groups with {len(subnet_ids)} subnets")
                
            # Check for existing VPC endpoints
            existing_endpoints = ec2.describe_vpc_endpoints(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'service-name', 'Values': [f'com.amazonaws.{region}.neptune-db']}
                ]
            )['VpcEndpoints']
            
            if not existing_endpoints:
                # Create VPC endpoint for Neptune service
                logger.info("Creating VPC endpoint for Neptune service...")
                try:
                    endpoint_service_name = f'com.amazonaws.{region}.neptune-db'
                    logger.info(f"Using Neptune service endpoint: {endpoint_service_name}")
                    vpc_endpoint = ec2.create_vpc_endpoint(
                        VpcId=vpc_id,
                        ServiceName=endpoint_service_name,
                        VpcEndpointType='Interface',
                        SecurityGroupIds=[sg_id],
                        SubnetIds=subnet_ids,
                        PrivateDnsEnabled=True,
                        TagSpecifications=[{
                            'ResourceType': 'vpc-endpoint',
                            'Tags': [{
                                'Key': 'Name',
                                'Value': f'neptune-endpoint-{cluster_id}'
                            }]
                        }]
                    )
                    logger.info("✓ VPC endpoint created successfully")
                    
                    # Wait for the endpoint to become available
                    waiter = ec2.get_waiter('vpc_endpoint_available')
                    waiter.wait(
                        VpcEndpointIds=[vpc_endpoint['VpcEndpoint']['VpcEndpointId']],
                        WaiterConfig={'Delay': 15, 'MaxAttempts': 40}
                    )
                    logger.info("✓ VPC endpoint is now available")
                    
                except ClientError as e:
                    if 'InvalidServiceName' in str(e):
                        logger.warning("Neptune service endpoint not available in this region")
                    else:
                        raise
            else:
                logger.info("✓ VPC endpoint already exists")
            
            logger.info("✓ VPC configuration completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to get cluster information: {str(e)}")
            if isinstance(e, ClientError):
                logger.error(f"AWS Error Code: {e.response['Error']['Code']}")
                logger.error(f"AWS Error Message: {e.response['Error']['Message']}")
            raise
            
    except Exception as e:
        logger.error(f"Failed to configure VPC access: {str(e)}")
        if isinstance(e, ClientError):
            logger.error(f"AWS Error Code: {e.response['Error']['Code']}")
            logger.error(f"AWS Error Message: {e.response['Error']['Message']}")
        return False

if __name__ == "__main__":
    configure_vpc_access()
