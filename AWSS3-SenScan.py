import boto3 #pip install boto3
from os.path import splitext
#boto3.setup_default_session(profile_name='')#Needed if you have more than one AWS profile.
# Create an S3 client
s3 = boto3.resource('s3')
s3c = boto3.client('s3')
targetExtensions = ['.pem', '.bak', '.sql', '.p12', '.vhd', '.vhdx']
# Call S3 to list current buckets
buckets = s3c.list_buckets()
for bucket in buckets['Buckets']:
    publicBucket = False
    bucketResource = s3.Bucket(bucket['Name'])
    bucketACL = s3c.get_bucket_acl(Bucket=bucket['Name'])
    bucketFiles = s3.Bucket(bucket['Name']).objects.all()
    #print(bucket['Name'],"=", bucketACL)
    for perm in bucketACL['Grants']:
        if perm["Permission"]=="READ" and perm["Grantee"]=={'URI': 'http://acs.amazonaws.com/groups/global/AllUsers', 'Type': 'Group'}:
            print(bucket['Name']," is public.")
            publicBucket = True
            #What is in this public bucket?
            for file in bucketFiles:
                file_name,extension = splitext(file.key)
                if extension in targetExtensions:
                    print("PublicBucket:", bucket['name'], ", file:", file.key)
    #Inspect private bucket file permissions 1 by 1
    if publicBucket==False:
        print("Inspecting file permissions on ",bucket['Name'])
        for file in bucketFiles:
            file_name, extension = splitext(file.key)
            if extension in targetExtensions:
                fileACL = s3.ObjectAcl(bucket['Name'],file.key)
                #print(fileACL)
                for acl in fileACL.grants:
                    #print(acl)
                    #{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers', 'Type': 'Group'}, 'Permission': 'READ'}
                    if acl['Permission']=="READ" and acl["Grantee"]=={'URI': 'http://acs.amazonaws.com/groups/global/AllUsers', 'Type': 'Group'}:
                        print(bucket['name']," Shared ",file.key)
