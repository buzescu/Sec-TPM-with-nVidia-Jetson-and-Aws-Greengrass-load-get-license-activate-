
******************************* GREENGRASS PARSEC TPM PROVISIONING GUIDE ***************************

Device spec:

- AGX Orin dev kit
- Jetson Linux 36.3.0 with fTPM test system
- GG Nucleus version `2.13.0`

*******************************
# INSTALLATION PACKAGE

1- Follow instruction from integration kit to install fTPM test system for NVIDIA Jetson Linux 36.3.0

- EmSpark_Overlay_Integration_FTPM_NVIDIA_36.3.0_2025-06-26_0.tar.gz: https://secedge.sharepoint.com/:u:/s/InternalBuilds/EVBFl7lUdc1LrZuTVo1a2dIBd9eVZJlRAEq0aQM6wEU1ug?e=AI7Hze
- FTPM_test_system_36.3.0-2025-06-26_2.tar.gz: https://secedge.sharepoint.com/:u:/s/InternalBuilds/Ea7E9dX9He9PjIkoPnnmI9IBfos536mqBdT32YnRl-NN2Q?e=w3V8M6
- Instruction to enable tpm: https://secedge.sharepoint.com/:p:/s/WorkinProgress/EQRmse21Gs5Ou_Mk5sMP1JEBDdTqF1VXcm2czHDppqVkbg?e=7cTeNB


2- Install greengrass-parsec-tpm package on device

```bash
# sudo apt install ./greengrass-parsec-tpm_1.0_36.3.0-0_arm64_2025-08-22_0.deb
sudo dpkg -i /home/secedge/greengrass-parsec-tpm_1.0_36.3.0-0_arm64_2025-08-22_0.deb
```

System is changed as below structure:

├── etc
│   └── parsec
│       ├── aws.greengrass.crypto.ParsecProvider.jar
│       ├── config.toml
│       └── greengrass-nucleus-2.13.0.zip
├── usr
│   ├── libexec
│   │   └── parsec
│   │       └── parsec
│   └── sbin
│       └── parsec-tool
└── var
    ├── lib
    │   └── parsec
    └── run
        └── parsec


*******************************
# PROVISIONING STEPS

1- Install and configure AWS

On device:

```bash
cd ~
sudo apt-get update
sudo apt-get install unzip curl -y
curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

Access AWS cloudshell, create python script to get credentials

```bash
nano getTemporaryCredentialsCloudShell.py

import os
import requests
import json
from datetime import datetime, timezone

# Fetch the temporary credentials
credentials_uri = os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI")
auth_token = os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN")

if credentials_uri and auth_token:
        headers = {"Authorization": auth_token}
        response = requests.get(credentials_uri, headers=headers, timeout=(10, 20))
        response.raise_for_status()
        credentials_data = response.json()

        access_key = credentials_data.get("AccessKeyId")
        secret_key = credentials_data.get("SecretAccessKey")
        session_token = credentials_data.get("Token")
        expiration = credentials_data.get("Expiration")
        aws_default_region = os.environ.get('AWS_DEFAULT_REGION', 'us-west-2')

        if access_key and secret_key and session_token and expiration:
                expiration = expiration.rstrip("Z")
                expiration_time = datetime.fromisoformat(expiration).replace(tzinfo=timezone.utc)
                now = datetime.now(tz=timezone.utc)
                duration = expiration_time - now
                duration_seconds = int(duration.total_seconds())

                print(f"\nThis is the temporary credential valid for {duration_seconds} seconds.\nPaste them in your shell!\n")
                print(f"export AWS_ACCESS_KEY_ID={access_key}")
                print(f"export AWS_SECRET_ACCESS_KEY={secret_key}")
                print(f"export AWS_SESSION_TOKEN={session_token}\n")
                print(f"export AWS_DEFAULT_REGION={aws_default_region}\n")
else:
        print("AWS_CONTAINER_CREDENTIALS_FULL_URI or AWS_CONTAINER_AUTHORIZATION_TOKEN environment variable not found.")
```

And then run the script to get temporary credentials


```bash
python getTemporaryCredentialsCloudShell.py 
```

Copy EXPORT statements and paste to device console, for example:
```bash
export AWS_ACCESS_KEY_ID=#######
export AWS_SECRET_ACCESS_KEY=#####
export AWS_SESSION_TOKEN=######

export AWS_DEFAULT_REGION=us-west-2
```


2- Start parsec

```bash
sudo /usr/libexec/parsec/parsec --config /etc/parsec/config.toml
```


3- Create ggc_user and ggc_group

```bash
sudo useradd --system --create-home ggc_user
sudo groupadd --system ggc_group
sudo usermod -aG sudo ggc_user

echo "ggc_user ALL=(ALL:ALL) ALL" | sudo tee /etc/sudoers.d/ggc_user
sudo chmod 440 /etc/sudoers.d/ggc_user
sudo visudo -c

echo "%ggc_group ALL=(ALL:ALL) ALL" | sudo tee /etc/sudoers.d/ggc_group
sudo chmod 440 /etc/sudoers.d/ggc_group
sudo visudo -c

```


4- Generate parsec key with tpm provider

```bash
export KEY_NAME=gg_key
export CSR_NAME=iotdevicekey.csr
export CERT_NAME=thingCert.crt
cd ~
mkdir parsec_keys
cd parsec_keys
parsec-tool create-rsa-key -s --key-name ${KEY_NAME}
parsec-tool create-csr --key-name ${KEY_NAME} --cn "${GG_THING_NAME}" >${CSR_NAME}
```


5- Preapre and provision greengrass v2 core device manually

```bash
cd ~
unzip /etc/parsec/greengrass-nucleus-2.13.0.zip -d GreengrassInstaller
java -jar ./GreengrassInstaller/lib/Greengrass.jar --version

export GG_USER_HOME=/greengrass/v2
export GG_THING_NAME=agxorin7

# Retrieve iot_endpoint address
aws iot describe-endpoint --endpoint-type iot:Data-ATS
->
	{
		"endpointAddress": "xxxxxxxxxxxx.iot.us-west-2.amazonaws.com"
	}

# Get cred_endpoint address
aws iot describe-endpoint --endpoint-type iot:CredentialProvider
->
	{
		"endpointAddress": "xxxxxxxxxxxx.credentials.iot.us-west-2.amazonaws.com"
	}

# Create IoT thing 
aws iot create-thing --thing-name ${GG_THING_NAME}
->
	{
		"thingName": "agxorin7",
		"thingArn": "arn:aws:iot:us-west-2:092180775967:thing/agxorin7",
		"thingId": "9da392c3-6622-4867-901d-5cf293f38c19"
	}


# Generate certificate
cd parsec_keys
aws iot create-certificate-from-csr --set-as-active --certificate-signing-request=file://${CSR_NAME} --certificate-pem-outfile ${CERT_NAME}
->
	{
		"certificateArn": "arn:aws:iot:us-west-2:092180775967:cert/eb1695a656caa387d07c95ce97a6f2bfdc41178c158affd997c1a1dda77653e2",
		"certificateId": "eb1695a656caa387d07c95ce97a6f2bfdc41178c158affd997c1a1dda77653e2",
		"certificatePem": "-----BEGIN CERTIFICATE-----\nMIIDRjCCAi6gAwIBAgIUXLwC9OIIyA1HWZbUMGFhLTP2I0QwDQYJKoZIhvcNAQEL\nBQAwTTFLMEkGA1UECwxCQW1hem9uIFdlYiBTZXJ2aWNlcyBPPUFtYXpvbi5jb20g\nSW5jLiBMPVNlYXR0bGUgU1Q9V2FzaGluZ3RvbiBDPVVTMB4XDTI1MDgyNTA3NTAw\nNFoXDTQ5MTIzMTIzNTk1OVowCzEJMAcGA1UEAwwAMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAsBB84g0WQJgOdREotlzTQAzhMcj0KoPr3g45N+V/fROA\nEDmuegCQE2wHoJGgYFJYHBpyuXBYutdK5spz5IF/sF6oPpXLP5AmIL0USzUpvvcR\nf07V4kLyJrwLjELFpX7TR1VEdbI2GIwOBQPq/fpQDIP6CE+eQL1iPpuS7dY8Iv1Y\nxBLvpcVGDnVoLGu2hR7DvtBaTDbjDEDf08vog3LPMBfwymlV/UGu6CjN23A351eW\nE+yIFZV7/NNXsUKPD7V8PSO49/NluggJa4rRZLPiOZ8KqHc1OV8FX8rkGEiz13Pw\nPmbnRQoHv/mRYFGpqMbVudBqvi+ty39B6u4u90uT5wIDAQABo2AwXjAfBgNVHSME\nGDAWgBQsOSeZpaEU+QAxp619fS/CZIMURzAdBgNVHQ4EFgQU5IdiIrcEkGowORL9\nD8MoEpIUcrAwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcN\nAQELBQADggEBAEAlN+I8jHLuF16dB85ZpQ9hkQzOPbw/Gxp5+h/B+rZV9mHJSquV\nrNnzEVGrzchAWuv4d9O+EyapagVlvfRiCfAVBDy0W1gtHI8A7fbXg5CRBBJsKhjm\njygxI7vCgkNJpaNGV5XZ+d6qT7Ni8+F/tTmDEMSBzdlIMSBDQPi91nivAXtFPGxY\nBWu/LEY4YvCCKzDUcVbtYsTCmrvZH1lmr9f2fjvYRY8uEXqZHGHolpwi9q+UfD+Z\nZeujOlbZe4x5wf9tQf/iNZ/8UnrwufK//qsWGDLjqvvB5GBTn86XBDV7XRMxiUaD\nfw2Jq8WlWa6hoMYvtbQgbO0xxhTKyIA/BwE=\n-----END CERTIFICATE-----\n"
	}

# Attach certicate to IoT thing
aws iot attach-thing-principal --thing-name ${GG_THING_NAME} --principal arn:aws:iot:us-west-2:092180775967:cert/eb1695a656caa387d07c95ce97a6f2bfdc41178c158affd997c1a1dda77653e2


# Follow link to configure the thing certificate: https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#configure-thing-certificate . The results are CuongDGreengrassV2IoTThingPolicy and CuongDGreengrassCoreTokenExchangeRoleAliasPolicy, then attach them to new certificate
aws iot attach-policy --policy-name CuongDGreengrassV2IoTThingPolicy --target arn:aws:iot:us-west-2:092180775967:cert/eb1695a656caa387d07c95ce97a6f2bfdc41178c158affd997c1a1dda77653e2	
aws iot attach-policy --policy-name CuongDGreengrassCoreTokenExchangeRoleAliasPolicy --target arn:aws:iot:us-west-2:092180775967:cert/eb1695a656caa387d07c95ce97a6f2bfdc41178c158affd997c1a1dda77653e2


# Configure role access s3 bucket (gg-demo-datamodel-protection), create artifact policy then attach to your own role access (CuongDGreengrassV2TokenExchangeRole)
nano component-artifact-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::gg-demo-datamodel-protection/*"
    }
  ]
}

aws iam create-policy \
  --policy-name MyGreengrassV2ComponentArtifactPolicy \
  --policy-document file://component-artifact-policy.json
->
	{
		"Policy": {
			"PolicyName": "MyGreengrassV2ComponentArtifactPolicy",
			"PolicyId": "ANPARK5THAQPQROEVG6KC",
			"Arn": "arn:aws:iam::092180775967:policy/MyGreengrassV2ComponentArtifactPolicy",
			"Path": "/",
			"DefaultVersionId": "v1",
			"AttachmentCount": 0,
			"PermissionsBoundaryUsageCount": 0,
			"IsAttachable": true,
			"CreateDate": "2025-07-31T17:05:47+00:00",
			"UpdateDate": "2025-07-31T17:05:47+00:00"
		}
	}

aws iam attach-role-policy \
  --role-name CuongDGreengrassV2TokenExchangeRole \
  --policy-arn arn:aws:iam::092180775967:policy/MyGreengrassV2ComponentArtifactPolicy


# Configure greengrass v2 
sudo mkdir -p ${GG_USER_HOME}
sudo chmod 755 /greengrass
sudo cp -R ~/parsec_keys/* ${GG_USER_HOME}
sudo curl -o ${GG_USER_HOME}/AmazonRootCA1.pem https://www.amazontrust.com/repository/AmazonRootCA1.pem


# Store your own values to generate greengrass config
export AWS_REGION=us-west-2
export iot_role_alias=CuongDGreengrassCoreTokenExchangeRoleAlias
export iot_endpoint=xxxxxxxxxx-ats.iot.us-west-2.amazonaws.com
export cred_endpoint=xxxxxxxxxx.credentials.iot.us-west-2.amazonaws.com

sudo cat <<EOF >~/GreengrassInstaller/config.yaml
system:
  certificateFilePath: "parsec:import=${GG_USER_HOME}/${CERT_NAME};object=${KEY_NAME};type=cert"
  privateKeyPath: "parsec:object=${KEY_NAME};type=private"
  rootCaPath: "${GG_USER_HOME}/AmazonRootCA1.pem"
  rootpath: "${GG_USER_HOME}"
  thingName: "${GG_THING_NAME}"
services:
  aws.greengrass.Nucleus:
    componentType: "NUCLEUS"
    configuration:
      awsRegion: "${AWS_REGION}"
      iotRoleAlias: "${iot_role_alias}"
      iotDataEndpoint: "${iot_endpoint}"
      iotCredEndpoint: "${cred_endpoint}"
  aws.greengrass.crypto.ParsecProvider:
    configuration:
      name: "greengrass-parsec-plugin"
      parsecSocket: "/var/run/parsec/parsec.sock"
EOF


# Start the AWS IoT Greengrass Core software
cd ${GG_USER_HOME}
sudo -E java -Droot="/greengrass/v2" -Dlog.store=FILE \
  -jar ~/GreengrassInstaller/lib/Greengrass.jar \
  --trusted-plugin /etc/parsec/aws.greengrass.crypto.ParsecProvider.jar \
  --init-config ~/GreengrassInstaller/config.yaml \
  --component-default-user ggc_user:ggc_group \
  --setup-system-service true

```

6- Verify greengrass

On devive:
```
sudo systemctl status greengrass.service
```

on AWS IoT: 
Go to https://us-west-2.console.aws.amazon.com/iot/home, Mange -> Greegrass devices -> Core devices, to see the device name agxorin7 should appear here.


Check the AWS IoT Greengrass Core software logs:
    
```bash
sudo tail -f /greengrass/v2/logs/greengrass.log
```

The following INFO-level log messages indicate that the AWS IoT Greengrass Core software successfully connects to the AWS IoT and AWS IoT Greengrass services.

```
2025-01-09T15:23:24.935Z [INFO] (AwsEventLoop 3) com.aws.greengrass.mqttclient.AwsIotMqtt5Client: Successfully connected to AWS IoT Core. {clientId=agxorin7, sessionPresent=false}
```



