# AWS Greengrass Parsec TPM Provisioning Workshop

## Workshop Overview

This workshop guides you through setting up AWS IoT Greengrass v2 with Parsec TPM integration on an NVIDIA AGX Orin development kit. You'll learn how to provision a secure IoT edge device using hardware-backed cryptographic operations.

### Learning Objectives
- Configure fTPM on NVIDIA Jetson Linux
- Install and configure Parsec for TPM operations
- Provision AWS IoT Greengrass v2 core device with TPM-backed security
- Verify successful deployment and connectivity

### Prerequisites
- NVIDIA AGX Orin development kit
- Jetson Linux 36.3.0 installed
- AWS account with appropriate permissions
- Basic knowledge of Linux command line
- Network connectivity

### Device Specifications
- **Hardware**: AGX Orin dev kit
- **OS**: Jetson Linux 36.3.0 with fTPM test system
- **Greengrass**: Nucleus version 2.13.0

---

## Module 1: Environment Setup

### Step 1.1: Install fTPM Test System

Download and install the required packages from the SecEdge SharePoint:

1. **EmSpark Overlay Integration**: `EmSpark_Overlay_Integration_FTPM_NVIDIA_36.3.0_2025-06-26_0.tar.gz`
2. **fTPM Test System**: `FTPM_test_system_36.3.0-2025-06-26_2.tar.gz`
3. **TPM Enable Instructions**: Follow the PowerPoint guide provided

> **Note**: Links to these resources are available in the internal builds SharePoint location.

### Step 1.2: Install Greengrass-Parsec-TPM Package

```bash
# Install the Greengrass Parsec TPM package
sudo dpkg -i /home/secedge/greengrass-parsec-tpm_1.0_36.3.0-0_arm64_2025-08-22_0.deb
```

**Verify Installation Structure:**
```
├── etc
│   └── parsec
│       ├── aws.greengrass.crypto.ParsecProvider.jar
│       ├── config.toml
│       └── greengrass-nucleus-2.13.0.zip
├── usr
│   ├── libexec
│   │   └── parsec
│   │       └── parsec
│   └── sbin
│       └── parsec-tool
└── var
    ├── lib
    │   └── parsec
    └── run
        └── parsec
```

---

## Module 2: AWS Configuration

### Step 2.1: Install AWS CLI on Device

```bash
cd ~
sudo apt-get update
sudo apt-get install unzip curl -y
curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

### Step 2.2: Get AWS Temporary Credentials

**On AWS CloudShell**, create the credential helper script:

```bash
nano getTemporaryCredentialsCloudShell.py
```

**Paste the following Python code:**

```python
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

**Run the script:**
```bash
python getTemporaryCredentialsCloudShell.py
```

**Copy and paste the export statements to your device terminal.**

---

## Module 3: Parsec Configuration

### Step 3.1: Start Parsec Service

```bash
sudo /usr/libexec/parsec/parsec --config /etc/parsec/config.toml
```

### Step 3.2: Create Greengrass System Users

```bash
# Create system user and group
sudo useradd --system --create-home ggc_user
sudo groupadd --system ggc_group
sudo usermod -aG sudo ggc_user

# Configure sudo access
echo "ggc_user ALL=(ALL:ALL) ALL" | sudo tee /etc/sudoers.d/ggc_user
sudo chmod 440 /etc/sudoers.d/ggc_user
sudo visudo -c

echo "%ggc_group ALL=(ALL:ALL) ALL" | sudo tee /etc/sudoers.d/ggc_group
sudo chmod 440 /etc/sudoers.d/ggc_group
sudo visudo -c
```

### Step 3.3: Generate TPM-Backed Keys

```bash
# Set environment variables
export KEY_NAME=gg_key
export CSR_NAME=iotdevicekey.csr
export CERT_NAME=thingCert.crt
export GG_THING_NAME=agxorin7  # Replace with your device name

# Create key directory and generate keys
cd ~
mkdir parsec_keys
cd parsec_keys

# Generate RSA key in TPM
parsec-tool create-rsa-key -s --key-name ${KEY_NAME}

# Create Certificate Signing Request
parsec-tool create-csr --key-name ${KEY_NAME} --cn "${GG_THING_NAME}" > ${CSR_NAME}
```

---

## Module 4: AWS IoT Thing Provisioning

### Step 4.1: Set Environment Variables

```bash
export GG_USER_HOME=/greengrass/v2
export AWS_REGION=us-west-2
```

### Step 4.2: Get AWS IoT Endpoints

```bash
# Get IoT data endpoint
aws iot describe-endpoint --endpoint-type iot:Data-ATS

# Get credential provider endpoint  
aws iot describe-endpoint --endpoint-type iot:CredentialProvider
```

**Save these endpoint addresses - you'll need them later.**

### Step 4.3: Create IoT Thing

```bash
aws iot create-thing --thing-name ${GG_THING_NAME}
```

### Step 4.4: Generate and Configure Certificate

```bash
cd parsec_keys

# Create certificate from CSR
aws iot create-certificate-from-csr --set-as-active --certificate-signing-request=file://${CSR_NAME} --certificate-pem-outfile ${CERT_NAME}
```

**Save the certificateArn from the output.**

```bash
# Attach certificate to IoT thing (replace with your certificate ARN)
aws iot attach-thing-principal --thing-name ${GG_THING_NAME} --principal arn:aws:iot:us-west-2:092180775967:cert/YOUR_CERTIFICATE_ID
```

### Step 4.5: Attach Policies to Certificate

> **Prerequisites**: Follow the [AWS Greengrass manual installation guide](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#configure-thing-certificate) to create the required policies.

```bash
# Attach IoT thing policy (replace with your certificate ARN)
aws iot attach-policy --policy-name CuongDGreengrassV2IoTThingPolicy --target arn:aws:iot:us-west-2:092180775967:cert/YOUR_CERTIFICATE_ID

# Attach token exchange policy (replace with your certificate ARN)
aws iot attach-policy --policy-name CuongDGreengrassCoreTokenExchangeRoleAliasPolicy --target arn:aws:iot:us-west-2:092180775967:cert/YOUR_CERTIFICATE_ID
```

---

## Module 5: IAM Configuration

### Step 5.1: Create Component Artifact Policy

```bash
nano component-artifact-policy.json
```

**Paste the following JSON:**
```json
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
```

### Step 5.2: Create and Attach IAM Policy

```bash
# Create the policy
aws iam create-policy \
  --policy-name MyGreengrassV2ComponentArtifactPolicy \
  --policy-document file://component-artifact-policy.json

# Attach policy to role (replace with your role name)
aws iam attach-role-policy \
  --role-name CuongDGreengrassV2TokenExchangeRole \
  --policy-arn arn:aws:iam::092180775967:policy/MyGreengrassV2ComponentArtifactPolicy
```

---

## Module 6: Greengrass Installation

### Step 6.1: Prepare Installation Directory

```bash
cd ~
unzip /etc/parsec/greengrass-nucleus-2.13.0.zip -d GreengrassInstaller

# Verify Greengrass version
java -jar ./GreengrassInstaller/lib/Greengrass.jar --version

# Create Greengrass directory and copy certificates
sudo mkdir -p ${GG_USER_HOME}
sudo chmod 755 /greengrass
sudo cp -R ~/parsec_keys/* ${GG_USER_HOME}

# Download Amazon Root CA
sudo curl -o ${GG_USER_HOME}/AmazonRootCA1.pem https://www.amazontrust.com/repository/AmazonRootCA1.pem
```

### Step 6.2: Create Greengrass Configuration

**Set your specific values:**
```bash
export iot_role_alias=CuongDGreengrassCoreTokenExchangeRoleAlias
export iot_endpoint=YOUR_IOT_ENDPOINT  # From Step 4.2
export cred_endpoint=YOUR_CRED_ENDPOINT  # From Step 4.2
```

**Generate the configuration file:**
```bash
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
```

### Step 6.3: Install and Start Greengrass

```bash
cd ${GG_USER_HOME}
sudo -E java -Droot="/greengrass/v2" -Dlog.store=FILE \
  -jar ~/GreengrassInstaller/lib/Greengrass.jar \
  --trusted-plugin /etc/parsec/aws.greengrass.crypto.ParsecProvider.jar \
  --init-config ~/GreengrassInstaller/config.yaml \
  --component-default-user ggc_user:ggc_group \
  --setup-system-service true
```

---

## Module 7: Verification and Troubleshooting

### Step 7.1: Verify System Service

```bash
sudo systemctl status greengrass.service
```

### Step 7.2: Check AWS IoT Console

1. Navigate to [AWS IoT Console](https://us-west-2.console.aws.amazon.com/iot/home)
2. Go to **Manage** → **Greengrass devices** → **Core devices**
3. Verify your device (e.g., `agxorin7`) appears in the list

### Step 7.3: Monitor Logs

```bash
sudo tail -f /greengrass/v2/logs/greengrass.log
```

**Look for successful connection messages:**
```
2025-01-09T15:23:24.935Z [INFO] (AwsEventLoop 3) com.aws.greengrass.mqttclient.AwsIotMqtt5Client: Successfully connected to AWS IoT Core. {clientId=agxorin7, sessionPresent=false}
```

---

## Workshop Summary

### What You've Accomplished
- ✅ Configured NVIDIA AGX Orin with fTPM support
- ✅ Installed and configured Parsec for TPM operations
- ✅ Provisioned AWS IoT Thing with TPM-backed certificates
- ✅ Deployed AWS IoT Greengrass v2 with hardware security
- ✅ Verified successful cloud connectivity

### Key Security Features
- **Hardware Root of Trust**: TPM-backed private keys
- **Secure Certificate Storage**: Keys never leave the TPM
- **Identity Attestation**: Hardware-verified device identity
- **Secure Communication**: TLS with hardware-backed certificates

### Next Steps
- Deploy Greengrass components to your device
- Implement edge applications with secure crypto operations
- Scale your deployment to multiple devices
- Monitor device fleet through AWS IoT Device Management

### Troubleshooting Resources
- AWS IoT Greengrass documentation
- Parsec security service documentation  
- NVIDIA Jetson Linux developer resources
- AWS CloudWatch logs and metrics

---

## Additional Resources

- [AWS IoT Greengrass v2 Developer Guide](https://docs.aws.amazon.com/greengrass/v2/developerguide/)
- [Parsec Documentation](https://parallaxsecond.github.io/parsec-book/)
- [NVIDIA Jetson Developer Resources](https://developer.nvidia.com/jetson)
- [TPM 2.0 Specifications](https://trustedcomputinggroup.org/tpm/)
