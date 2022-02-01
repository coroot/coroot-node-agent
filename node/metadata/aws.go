package metadata

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"io"
	"k8s.io/klog/v2"
)

func getAwsMetadata() *CloudMetadata {
	ctx, cancel := context.WithTimeout(context.Background(), metadataServiceTimeout)
	defer cancel()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		klog.Errorln(err)
		return nil
	}
	c := imds.NewFromConfig(cfg)
	md := &CloudMetadata{
		Provider:           CloudProviderAWS,
		InstanceId:         getAwsMetadataVariable(ctx, c, "instance-id"),
		LifeCycle:          getAwsMetadataVariable(ctx, c, "instance-life-cycle"),
		InstanceType:       getAwsMetadataVariable(ctx, c, "instance-type"),
		Region:             getAwsMetadataVariable(ctx, c, "placement/region"),
		AvailabilityZone:   getAwsMetadataVariable(ctx, c, "placement/availability-zone"),
		AvailabilityZoneId: getAwsMetadataVariable(ctx, c, "placement/availability-zone-id"),
		LocalIPv4:          getAwsMetadataVariable(ctx, c, "local-ipv4"),
		PublicIPv4:         getAwsMetadataVariable(ctx, c, "public-ipv4"),
	}
	if infoJson := getAwsMetadataVariable(ctx, c, "identity-credentials/ec2/info"); infoJson != "" {
		m := map[string]string{}
		if err := json.Unmarshal([]byte(infoJson), &m); err != nil {
			klog.Errorln(err)
		} else {
			md.AccountId = m["AccountId"]
		}
	}
	return md
}

func getAwsMetadataVariable(ctx context.Context, client *imds.Client, path string) string {
	res, err := client.GetMetadata(ctx, &imds.GetMetadataInput{Path: path})
	if err != nil {
		klog.Errorln(path, err)
		return ""
	}
	defer res.Content.Close()
	payload, err := io.ReadAll(res.Content)
	if err != nil {
		klog.Errorln(path, err)
		return ""
	}
	return string(payload)
}
