# Cloud Audit — Credential Configuration

This guide explains how to configure credentials for each cloud provider supported by the `apileaks cloud-audit` command: **AWS**, **GCP**, and **Azure**.

Every provider follows the same principle: credentials are **never required in the YAML config file** — instead, the tool delegates to each provider's native SDK credential chain. Explicit options are available for automation and CI/CD scenarios.

---

## Table of Contents

- [AWS API Gateway](#aws-api-gateway)
- [GCP API Gateway / Cloud Endpoints](#gcp-api-gateway--cloud-endpoints)
- [Azure API Management](#azure-api-management)
- [YAML Config (`cloud_audit` section)](#yaml-config-cloud_audit-section)
- [Multi-Account / Multi-Project Scanning](#multi-account--multi-project-scanning)
- [No Plaintext Secrets in YAML](#no-plaintext-secrets-in-yaml)

---

## AWS API Gateway

### Default credential chain

When no explicit profile or role is configured, the auditor uses the **boto3 default credential chain** in this order:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. AWS credentials file (`~/.aws/credentials`)
3. AWS config file (`~/.aws/config`)
4. Container credentials (ECS task role)
5. Instance profile credentials (EC2 / EKS node role)

This is the recommended approach for running on AWS infrastructure (Lambda, EC2, EKS, CodeBuild, etc.) because no secrets ever leave the environment.

```bash
# Uses whatever the boto3 chain resolves — no flags needed
apileaks cloud-audit --provider aws
```

### Named profile (`--aws-profile`)

Use a profile from `~/.aws/credentials` or `~/.aws/config`:

```bash
apileaks cloud-audit --provider aws --aws-profile prod-readonly
```

Pass the flag multiple times to audit several accounts in one run:

```bash
apileaks cloud-audit --provider aws \
  --aws-profile dev \
  --aws-profile staging \
  --aws-profile prod-readonly
```

### Role assumption (`--aws-role-arn`)

Assume an IAM role before auditing. This is the recommended approach for cross-account audits:

```bash
apileaks cloud-audit --provider aws \
  --aws-role-arn arn:aws:iam::111122223333:role/APILeakReadOnly
```

Combine with a source profile if needed (the client assumes the role from that profile):

```bash
apileaks cloud-audit --provider aws \
  --aws-profile my-base-profile \
  --aws-role-arn arn:aws:iam::111122223333:role/APILeakReadOnly
```

### Region selection (`--aws-region`)

Default region is `us-east-1`. Override with one or more `--aws-region` flags:

```bash
apileaks cloud-audit --provider aws \
  --aws-region eu-west-1 \
  --aws-region ap-southeast-1
```

### Required AWS permissions (read-only)

The auditing identity needs at minimum:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "apigateway:GET",
        "wafv2:GetWebACLForResource",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## GCP API Gateway / Cloud Endpoints

### Application Default Credentials (default)

When no service account file is specified, the auditor uses **Application Default Credentials (ADC)**. ADC resolves in this order:

1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable pointing to a service account JSON file
2. User credentials set by `gcloud auth application-default login`
3. The service account attached to the Compute Engine / GKE / Cloud Run instance

```bash
# Uses ADC — works on GCP instances or after `gcloud auth application-default login`
apileaks cloud-audit --provider gcp --gcp-project-id my-project-id
```

### Explicit service account file (`--gcp-service-account-file`)

Provide a downloaded service account key JSON for environments where ADC is not available:

```bash
apileaks cloud-audit --provider gcp \
  --gcp-project-id my-project-id \
  --gcp-service-account-file /secrets/sa-apileak-readonly.json
```

> **Security note:** Service account key files are long-lived credentials. Prefer Workload Identity Federation or the `GOOGLE_APPLICATION_CREDENTIALS` environment variable over placing the path directly in a config file.

### Project IDs (`--gcp-project-id`)

One or more GCP project IDs to audit:

```bash
apileaks cloud-audit --provider gcp \
  --gcp-project-id project-alpha \
  --gcp-project-id project-beta
```

### Required GCP permissions

Grant the auditing service account the following roles (or a custom role with equivalent permissions):

- `roles/apigateway.viewer`
- `roles/servicemanagement.viewer`
- `roles/iam.securityReviewer` (for IAM binding checks)

---

## Azure API Management

### DefaultAzureCredential (default)

When no explicit service principal is configured, the auditor uses `DefaultAzureCredential` from the Azure SDK, which tries these sources in order:

1. Environment variables (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` / `AZURE_CLIENT_CERTIFICATE_PATH`)
2. Workload Identity (Azure Kubernetes Service)
3. Managed Identity (Azure VMs, App Service, Functions, etc.)
4. Azure CLI (`az login`)
5. Azure PowerShell
6. Interactive browser (development only)

```bash
# Uses DefaultAzureCredential — works on Azure infrastructure or after `az login`
apileaks cloud-audit --provider azure \
  --azure-subscription-id 00000000-1111-2222-3333-444444444444 \
  --azure-resource-group my-apim-rg
```

### Explicit service principal

For non-interactive automation and CI/CD pipelines, supply the service principal credentials as environment variables (recommended) or CLI flags:

**Via environment variables (recommended):**

```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"

apileaks cloud-audit --provider azure \
  --azure-subscription-id 00000000-1111-2222-3333-444444444444 \
  --azure-resource-group my-apim-rg
```

**Via CLI flags:**

```bash
apileaks cloud-audit --provider azure \
  --azure-subscription-id 00000000-1111-2222-3333-444444444444 \
  --azure-resource-group my-apim-rg \
  --azure-tenant-id "your-tenant-id" \
  --azure-client-id "your-client-id" \
  --azure-client-secret "your-client-secret"
```

> The `--azure-client-secret` flag reads the `AZURE_CLIENT_SECRET` environment variable automatically when not provided on the command line.

### Required Azure permissions

Assign the auditing identity the built-in **Reader** role at the subscription or resource group scope, plus:

- `Microsoft.ApiManagement/service/read`
- `Microsoft.ApiManagement/service/products/read`
- `Microsoft.ApiManagement/service/apis/read`
- `Microsoft.ApiManagement/service/subscriptions/read`
- `Microsoft.ApiManagement/service/backends/read`

The built-in **API Management Service Reader** role covers the APIM-specific permissions.

---

## YAML Config (`cloud_audit` section)

Add a `cloud_audit` top-level section to your APILeak YAML configuration file to persist settings across runs. All fields are optional and fall back to their defaults or the SDK credential chain when omitted.

```yaml
# apileaks.yaml
target:
  base_url: "https://api.example.com"

# Cloud audit configuration (optional)
cloud_audit:
  # Providers to audit (list)
  providers:
    - aws
    - gcp
    - azure

  # AWS
  aws_profiles:
    - prod-readonly
  aws_role_arns:
    - arn:aws:iam::111122223333:role/APILeakReadOnly
  aws_regions:
    - us-east-1
    - eu-west-1

  # GCP
  gcp_project_ids:
    - project-alpha
    - project-beta
  # Path to a service account key file (falls back to ADC when omitted)
  gcp_service_account_file: /secrets/sa-apileak.json

  # Azure
  azure_subscription_ids:
    - 00000000-1111-2222-3333-444444444444
  azure_resource_groups:
    - apim-production
  # Use environment variable references — never inline raw secrets
  azure_tenant_id: "${AZURE_TENANT_ID}"
  azure_client_id: "${AZURE_CLIENT_ID}"
  azure_client_secret: "${AZURE_CLIENT_SECRET}"

  # Safety knob — keep false unless you intentionally want write operations
  allow_destructive: false
```

### Single values vs lists

The YAML parser accepts both a single string and a list for all multi-value fields:

```yaml
cloud_audit:
  providers: aws          # also valid: providers: [aws]
  aws_profiles: default   # also valid: aws_profiles: [default, staging]
```

---

## Multi-Account / Multi-Project Scanning

All multi-value credential fields accept a list. The orchestrator creates one auditor instance per combination so findings are always tagged with the originating account context:

```bash
# Audit three AWS accounts in a single run
apileaks cloud-audit --provider aws \
  --aws-profile dev \
  --aws-profile staging \
  --aws-profile prod

# Audit two GCP projects
apileaks cloud-audit --provider gcp \
  --gcp-project-id project-frontend \
  --gcp-project-id project-backend

# Audit two Azure subscriptions
apileaks cloud-audit --provider azure \
  --azure-subscription-id aaa-bbb-ccc \
  --azure-subscription-id ddd-eee-fff \
  --azure-resource-group shared-apim
```

---

## No Plaintext Secrets in YAML

APILeak enforces a **no-secret-in-YAML** policy. If `azure_client_secret` (or any other sensitive field) contains a raw value in the YAML file, the tool logs a warning and `CloudAuditConfig.has_plaintext_secret()` returns `True`.

Use environment variable references instead:

```yaml
cloud_audit:
  azure_client_secret: "${AZURE_CLIENT_SECRET}"  # resolved at runtime
```

Supported reference formats:
- `${VAR_NAME}`
- `$VAR_NAME`
- `env:VAR_NAME`

The service account *file path* (`gcp_service_account_file`) is explicitly excluded from this check because it is a file reference, not the secret itself.
