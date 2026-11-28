# FortiSIEM AWS Parser 欄位對齊對照表

涵蓋來源：**CloudTrail** (`AwsS3CloudTrailJSONParser.xml`)、**GuardDuty** (`AwsS3GuardDutyJSONParser.xml`)、**Security Hub** (`AwsS3SecurityHubParser.xml`)

| 類別 | FortiSIEM 欄位 | CloudTrail Parser | GuardDuty Parser | Security Hub Parser |
| :--- | :--- | :--- | :--- | :--- |
| **帳號** | `accountId` | `accountId` / `userIdentity.accountId` / `resources[0].accountId` | `accountId` | `AwsAccountId` |
| **帳號** | `recipientAccountId` *(自訂)* | `recipientAccountId` | `-` | `-` |
| **帳號** | `accountName` | `userIdentity.userName` / `sessionIssuer.userName`（Root） | `-` | `AwsAccountName` |
| **帳號** | `awsRegion` | `awsRegion` | `region` | `Resources[0].Region` → `Region` |
| **身分** | `user` | `userIdentity.userName` / `invokedBy` / `accountId` / `principalId` / `arn` | `accessKeyDetails.userName` → `kubernetesUserDetails.username` → `rdsDbUserDetails.user` | `AwsIamAccessKey.UserName` → `PrincipalName` → `AwsIamUser.UserName` |
| **身分** | `identity` | `userIdentity.arn` | `accessKeyDetails.userIdentity.arn` → `iamInstanceProfile.arn` → `principalId` | `AwsEc2Instance.IamInstanceProfileArn` → `ProductFields["Resources:0/Id"]` → `principal` |
| **身分** | `identityType` | `userIdentity.type` / `userType` | `resource.accessKeyDetails.userType` | `Resources[0].Details.AwsIamAccessKey.PrincipalType` |
| **身分** | `principal` | `userIdentity.principalId` / `userPrincipalId` | `resource.accessKeyDetails.principalId` | `AwsIamAccessKey.PrincipalId` → `AwsIamUser.UserId` |
| **身分** | `caller` | `userIdentity.invokedBy`（識別 AWS 官方服務呼叫） | `-` | `-` |
| **身分** | `role` | `requestParameters.roleName` / `AssumedRole` / `sessionIssuer.userName` | `-` | `Resources[0].Details.AwsIamRole.RoleName` |
| **身分** | `appRole` | `userIdentity.sessionContext.sessionIssuer.arn` | `-` | `Resources[0].Details.AwsEc2Instance.IamInstanceProfileArn` |
| **身分** | `accessKeyId` | `userIdentity.accessKeyId` / `accessKeyId` / `credentials.accessKeyId` | `resource.accessKeyDetails.accessKeyId` | `-` |
| **資源** | `resourceType` | `resources[0].type` / `resourceType` | `resource.resourceType` | `Resources[0].Type` |
| **資源** | `resourceName` | `resources[0].ARN` / `serviceEventDetails.resourceArn` / `SecretARN` → `ec2InstanceId` → `bucketName` → `osObjName` | `s3ObjectDetails[0].objectArn` → `s3BucketDetails[0].arn` → `eksClusterDetails.arn` → `ecsClusterDetails.arn` → `lambdaDetails.functionArn` → `rdsDbInstanceDetails.dbInstanceArn` → `ec2InstanceId` → `accessKeyId` → Finding `arn` | `Resources[0].Id`（保留完整 ARN／ID） |
| **資源** | `resourceId` | `-` | `-` | `Resources[0].Id`（截短後的短 ID） |
| **資源** | `ec2InstanceId` | `requestParameters.instanceId` / `responseElements.instances...` / `responseElements.instancesSet.items[0].instanceId` | `resource.instanceDetails.instanceId` | `Resources[0].Id`（`AwsEc2Instance` 擷取） |
| **資源** | `vpcId` | `requestParameters.vpcId` | `instanceDetails.networkInterfaces[0].vpcId` | `Resources[0].Details.AwsEc2Instance.VpcId` |
| **資源** | `bucketName` | `requestParameters.bucketName` | `resource.s3BucketDetails[0].name` | `-` |
| **資源** | `filePath` | `requestParameters.key`（含 `bucketName` 時） | `s3BucketDetails[0].s3ObjectDetails[0].key` | `Malware[0].Path` |
| **資源** | `cluster` | `requestParameters.cluster` / `clusterArn` | `eksClusterDetails.name` / `ecsClusterDetails.name` | `AwsEksCluster.Name` / `AwsEcsCluster.ClusterArn` |
| **資源** | `dbName` | `-` | `resource.rdsDbUserDetails.database` | `Resources[0].Details.AwsRdsDbInstance.DBName` |
| **資源** | `appName` | `-` | `resource.rdsDbUserDetails.application` | `Resources[0].Details.AwsLambdaFunction.FunctionName` |
| **網路** | `srcIpAddr` | `sourceIPAddress`（合法 IP） | `service.action.*.remoteIpDetails.ipAddressV4` | `Action.*.RemoteIpDetails.IpAddressV4` / `Network.SourceIpV4\|V6` / `ProductFields` |
| **網路** | `destIpAddr` | `-` | `networkConnectionAction.localIpDetails.ipAddressV4` | `Action.*.LocalIpDetails.IpAddressV4` / `Network.DestinationIpV4\|V6` / `ProductFields` |
| **網路** | `srcIpPort` / `destIpPort` | `ipPermissions.items[0].fromPort` / `toPort` | `networkConnectionAction.remotePortDetails.port` / `localPortDetails.port` | `Action.*.RemotePortDetails.Port` / `LocalPortDetails.Port` / `Network` / `ProductFields` |
| **網路** | `srcName` | `sourceIPAddress`（非 IP 時） | `remoteIpDetails`（非 IP 時） | `Network.SourceDomain` |
| **網路** | `destName` | `requestParameters.Host` / `clientProvidedHostHeader` | `dnsRequestAction.domain` → `rdsDbInstanceDetails.dbInstanceIdentifier` | `Action.DnsRequestAction.Domain` / `Network.DestinationDomain` → `AwsRdsDbInstance.DBInstanceIdentifier` |
| **網路** | `hostIpAddr` | `requestParameters.filterSet...`（`DescribeInstances`） | `instanceDetails.networkInterfaces[0].privateIpAddress` | `Resources[0].Details.AwsEc2Instance.IpV4Addresses[0]` |
| **網路** | `ipProto` | `requestParameters.ipPermissions.items[0].ipProtocol` | `networkConnectionAction.protocol`（轉 IANA 數字） | `Action.NetworkConnectionAction.Protocol` / `Network.Protocol` / `ProductFields` |
| **網路** | `appClientVersion` | `userAgent` | `service.additionalInfo.userAgent.fullUserAgent` | `-` |
| **事件** | `eventType` | `AWS-CloudTrail-<SERVICE>-<eventName>` | `AWS_GUARDDUTY-<type>` | `AWS-Hub-<Namespace>-<Category>-<Classifier>` |
| **事件** | `serviceName` | `eventSource`（去 `.amazonaws.com` 轉大寫） | `service.serviceName`（`guardduty`） | `ProductArn` 短名稱（如 `securityhub`、`guardduty`） |
| **事件** | `actionName` | `eventType`（如 `AwsApiCall`） | `awsApiCallAction.api` → `service.action.actionType` | `Action.AwsApiCallAction.Api` |
| **事件** | `eventSeverity` | `-` | `severity` | `Severity.Label` / `Severity.Normalized`（轉 1–10） |
| **事件** | `policyName` | `requestParameters.policyName` | `-` | `Compliance.SecurityControlId`（如 `SSM.6`） |
| **事件** | `requestId` *(自訂)* | `requestID` / `responseElements.requestId` | `-` | `-` |
| **事件** | `correlationId` | `sharedEventID` | `-` | `-` |
| **事件** | `authenMethod` / `tlsVersion` | `AuthenticationMethod` / `tlsDetails.tlsVersion` | `rdsDbUserDetails.authMethod` / `rdsDbUserDetails.ssl` | `-` |
| **事件** | `virusName` / `sha256` | `-` | `malwareScanDetails.threats[0].name` / `s3ObjectDetails[0].hash` | `Malware[0].Name` / `-` |
| **事件** | `description` / `title` | `requestParameters.description` / `-` | `description` / `title` | `Description`（同步寫入 `msg`） / `Title` |
| **時間** | `deviceTime` | `eventTime` | `updatedAt` → `createdAt` | `UpdatedAt` → `LastObservedAt` → `FirstObservedAt` → `CreatedAt` |
| **時間** | `firstSeenTime` / `lastSeenTime` | `-` | `service.eventFirstSeen` / `service.eventLastSeen` | `FirstObservedAt` / `LastObservedAt` |

## FortiSIEM 事前準備
- 請至 **Admin > Device Support > Event Attributes** 新增以下 2 個自訂欄位（型別皆為 `String`）：
  1. `requestId`
  2. `recipientAccountId`
