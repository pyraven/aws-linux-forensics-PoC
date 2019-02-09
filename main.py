# imports
import boto3
import time

# client
client = boto3.client('ec2')
resource = boto3.resource('ec2')
ssm_client = boto3.client('ssm')
s3_client = boto3.client('s3')

# custom  configuration
iam_role = "ARNofSSMRole"
iam_role_name = "<SSMRoleName>"
forensics_bucket = "<bucket>"
linux_memory_file = "linux-file.mem"
evidence = "linux-evidence.ko"
infected_host = "<instance_id>"

# infected host
# I needed the region, instance id and instance type to create a copy of this host
infected_instance_id = resource.Instance(infected_host)  # update-instance-here
infected_image = infected_instance_id.image_id
instance_region = infected_instance_id.placement['AvailabilityZone'][:-1]
infected_instance_type = infected_instance_id.instance_type

# create image of host and capture ami id
print(f"[+] Making image of {infected_instance_id.id}. Standby.")
response = client.copy_image(Name='Experiment', SourceImageId=infected_image,
                             SourceRegion=instance_region)
ami_id = response['ImageId']

# wait until image has been created
waiter = client.get_waiter('image_available')
waiter.wait()
print("[+] Image creation complete.")

# launch new instance
print("Creating new instance from image.")
create_response = resource.create_instances(
    ImageId=ami_id, MinCount=1, MaxCount=1, InstanceType=infected_instance_type)
test_instance = create_response[0]
test_instance_id = test_instance.id
test_instance.wait_until_running()
print("Instance is running.")

# attach role to new instance
print("Instance Created. Attaching role and running commands.")
associate_iam_response = client.associate_iam_instance_profile(
    IamInstanceProfile={'Arn': iam_role, 'Name': iam_role_name}, InstanceId=test_instance_id)

# wait for instance to be managed
# this is no waiter for SSM? So I'm querying the inventory every minute and checking for the new instance ID here.
ready = False
while ready == False:
    inventory = ssm_client.get_inventory()['Entities']
    host_ids = [host['Id'] for host in inventory]
    if test_instance_id in host_ids:
        ready = True
        print("Instance managed.")
    else:
        print("Waiting.")
        time.sleep(60)

# run commands to create forensics file
commands = ["sudo yum install git -y",
            "sudo yum install kernel-devel-$(uname -r) -y",
            "sudo yum install gcc -y",
            "cd /tmp/",
            "sudo git clone https://github.com/504ensicsLabs/LiME",
            "cd LiME/src",
            "sudo make",
            f"sudo mv ./lime-$(uname -r).ko {evidence}",
            f"sudo aws s3 cp ./{evidence} s3://{forensics_bucket}",
            "sudo make clean"]
f_resp = ssm_client.send_command(DocumentName="AWS-RunShellScript",
                                 Parameters={'commands': commands},
                                 InstanceIds=[test_instance_id])

# wait until object is uploaded to s3
f_waiter = s3_client.get_waiter('object_exists')
f_waiter.wait(Bucket=forensics_bucket, Key=evidence)
print("[+] Object Uploaded")

# download file from s3 and use forensics file on infected host
second_commands = ["cd /tmp",
                   f"sudo aws s3 cp s3://{forensics_bucket}/{evidence} .",
                   f"sudo insmod /tmp/{evidence} 'path=/tmp/{linux_memory_file} format=lime'",
                   f"sudo sha256sum {linux_memory_file} > memory-sha-hash.txt",
                   f"sudo aws s3 cp {linux_memory_file} s3://{forensics_bucket}",
                   f"aws s3 cp memory-sha-hash.txt s3://{forensics_bucket}"]
s_resp = ssm_client.send_command(DocumentName="AWS-RunShellScript",
                                 Parameters={'commands': second_commands},
                                 InstanceIds=[infected_host])

# wait until file has been uploaded
l_waiter = s3_client.get_waiter('object_exists')
l_waiter.wait(Bucket=forensics_bucket, Key=linux_memory_file)
print("[+] Object Uploaded")

# cleaning up / terminating instance
client.terminate_instances(InstanceIds=[test_instance_id])
print("Instance Terminated")
