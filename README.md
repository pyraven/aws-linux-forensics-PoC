AWS Linux Forensics PoC

Just a proof of concept but this script does the following:
1. Makes a copy (AMI) of an infected host
2. Launches a test instance (of the same type) with the new AMI
3. Runs a bunch of commands (install git, download Lime, and Make .ko file)
4. Uploads the .ko  file to S3.
5. Downloads the .ko to the infected host, is loaded into memory  and executes to output a memory dump
6. A hash is generated and uploaded along with the memory dump to s3.
7. Terminates the test instance
8. Thank the demo gods?

After talking with a buddy, I think I want to go a much more efficient route (more to come soon). This was just a fun PoC to practice using waiters and wanted to get more experience using SSM.

Cheers!