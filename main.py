# imports
import boto3
import time

# client
ec2_client = boto3.client('ec2')
ec2_resource = boto3.resource('ec2')
ssm_client = boto3.client('ssm')
s3_client = boto3.client('s3')

# custom  configuration
iam_instance_profile_arn = "arn:aws:iam::<account_id>:instance-profile/SSMRole"
iam_role_name = "SSMRole"
forensics_bucket = "<bucket_name>"
linux_memory_file = "linux-file.mem"
evidence = "linux-evidence.ko"
infected_host = "<instance_id>"

# infected host info
infected_instance = ec2_resource.Instance(infected_host)
infected_image = infected_instance.image_id
instance_region = infected_instance.placement['AvailabilityZone'][:-1]
infected_instance_type = infected_instance.instance_type

# create image of host and capture ami id
print(f"[+] Making image of {infected_instance.id}. Standby.")
response = ec2_client.copy_image(Name='AMI-Name', SourceImageId=infected_image,
                                 SourceRegion=instance_region)
ami_id = response['ImageId']
# this waiter takes a while.....wait for it
waiter = ec2_client.get_waiter('image_available')
waiter.wait()
print("[+] Image creation complete.")

# launch new instance and assign role
print("[+] Creating new instance from image.")
create_response = ec2_resource.create_instances(
    ImageId=ami_id, MinCount=1, MaxCount=1, InstanceType=infected_instance_type)
build_instance = create_response[0]
build_instance_id = build_instance.id
build_instance.wait_until_running()
print("[+] Instance Created. Attaching role and running commands.")
associate_iam_response = ec2_client.associate_iam_instance_profile(
    IamInstanceProfile={'Arn': iam_instance_profile_arn, 'Name': iam_role_name}, InstanceId=build_instance_id)

read_me = """ Wait for instance to be managed under SSM
This will allow the ssm commands to be run
I'm doing this because there are no waiters for SSM?
So I'm querying the inventory every minute and checking
for the new instance ID here. This normally takes a minute
or two for an instance to me managed.
Also, I'm using the Amazon AMI for this so the SSM Agent is
installed by default so this will have to be modified
per linux distro """

ready = False
while ready == False:
    inventory = ssm_client.get_inventory()['Entities']
    host_ids = [host['Id'] for host in inventory]
    if build_instance_id in host_ids:
        ready = True
        print("[+] Instance is now managed.")
    else:
        print("[+] Discovering")
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
resp = ssm_client.send_command(DocumentName="AWS-RunShellScript",
                               Parameters={'commands': commands},
                               InstanceIds=[build_instance_id])

# wait until object is uploaded to s3
waiter = s3_client.get_waiter('object_exists')
waiter.wait(Bucket=forensics_bucket, Key=evidence)
ec2_client.terminate_instances(InstanceIds=[build_instance_id])
print("[+] Object Uploaded and Instance Terminated.")

# download file from s3 and use forensics file on infected host
second_commands = ["cd /tmp",
                   f"sudo aws s3 cp s3://{forensics_bucket}/{evidence} .",
                   f"sudo insmod /tmp/{evidence} 'path=/tmp/{linux_memory_file} format=lime'",
                   f"sudo sha256sum {linux_memory_file} > memory-sha-hash.txt",
                   f"sudo aws s3 cp {linux_memory_file} s3://{forensics_bucket}",
                   f"aws s3 cp memory-sha-hash.txt s3://{forensics_bucket}"]
second_resp = ssm_client.send_command(DocumentName="AWS-RunShellScript",
                                      Parameters={'commands': second_commands},
                                      InstanceIds=[infected_host])
waiter = s3_client.get_waiter('object_exists')
waiter.wait(Bucket=forensics_bucket, Key=linux_memory_file)
print("[+] Memory File Uploaded")
