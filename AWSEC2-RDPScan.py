import boto3 #pip install boto3
profiles = ['default']#AN Array of AWS Profiles to query
targetPorts = [3389,1433,1434,21,23,135,137,138,139,53]
for profile in profiles:#Needed if you have more than one AWS profile.
    print("\nStarting Profile ",profile)
    boto3.setup_default_session(profile_name=profile)
    # Grab list of regions because for some reason ec2 doesn't scan all regions by default
    client = boto3.client('ec2')
    resRegions = client.describe_regions()
    #print(resRegions['Regions'])
    for region in resRegions['Regions']:
        client = boto3.client('ec2',region_name=region['RegionName'])
        runningEC2s = client.describe_instance_status()#List running instances
        intanceIds = []#An array of instance IDs to reduce the number of Network ACLs to pull
        for ec2 in runningEC2s['InstanceStatuses']:
            #print(profile, " ", ec2)
            intanceIds.append(ec2['InstanceId'])
        #Time to get the Network ACLs
        #print(profile, " ",intanceIds)
        #vpcFilter = [{'Name': 'vpc-id', 'Values': intanceIds}]
        securityGroups = client.describe_security_groups()#Filters=grpFilter #Filter doesn't work for some reason
        ec2Descriptions = client.describe_instances()
        targetGroupIds = [] #Store a list of vunerable security groups
        vulnFound = False#did we find something interesting
        for group in securityGroups['SecurityGroups']:
            for ipp in group['IpPermissions']:
                if ipp['IpProtocol']=='tcp'and ipp['FromPort'] in targetPorts and ipp['IpRanges']==[{'CidrIp': '0.0.0.0/0'}]:
                    targetGroupIds.append(group['GroupId'])
                    #print(group)
        #Filters=vpcFilter #Filter doesn't work for some reason
        reservations = ec2Descriptions['Reservations']
        #print("\nprofile|availabilityZone|instanceID|SecurityGroupID|publicDNSName")
        activeGroups = []#Keep a list of groups in play for refrence after we display the insecure instances
        for res in reservations:
            for inst in res['Instances']:
                #print(inst)
                if 'InstanceId' in inst and inst['InstanceId'] in intanceIds:
                    #We are only interested in instances that are running.
                    #print(inst)
                    groups = inst['SecurityGroups']
                    for group in groups:
                        if group['GroupId'] in targetGroupIds:#Vuln ports open
                            placement = inst['Placement']
                            print(profile,"|",placement['AvailabilityZone'],"|",inst['InstanceId'],"|",group['GroupId'],"|",inst['PublicDnsName'])
                            activeGroups.append(group['GroupId'])
                            vulnFound = True
        if vulnFound:
            #Give a list of active groups
            print("\n",profile,"vulnerable active groups in region ",region['RegionName'],":")
            for group in securityGroups['SecurityGroups']:
                 if group['GroupId'] in activeGroups:
                     print(group)

