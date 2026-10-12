package containers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	ecsLabelCluster              = "com.amazonaws.ecs.cluster"
	ecsLabelContainerName        = "com.amazonaws.ecs.container-name"
	ecsLabelTaskArn              = "com.amazonaws.ecs.task-arn"
	ecsLabelTaskDefinitionFamily = "com.amazonaws.ecs.task-definition-family"

	ecsPauseContainerName = "~internal~ecs~pause"

	ecsMetadataURIEnv        = "ECS_CONTAINER_METADATA_URI_V4"
	ecsMetadataTimeout       = 2 * time.Second
	ecsMetadataRetryInterval = 30 * time.Second
)

var (
	ecsMetadataClient     = &http.Client{Timeout: ecsMetadataTimeout}
	ecsMetadataRetryAfter time.Time
)

func ecsEnrichMetadata(md *ContainerMetadata) error {
	if md.labels[ecsLabelTaskArn] == "" || md.labels[ecsLabelContainerName] == ecsPauseContainerName {
		return nil
	}
	uri := md.env[ecsMetadataURIEnv]
	if uri == "" {
		return nil
	}
	if now := time.Now(); now.Before(ecsMetadataRetryAfter) {
		return fmt.Errorf("ECS task metadata endpoint is unavailable, next attempt in %s", ecsMetadataRetryAfter.Sub(now).Truncate(time.Second))
	}
	resp, err := ecsMetadataClient.Get(uri + "/task")
	if err != nil {
		ecsMetadataRetryAfter = time.Now().Add(ecsMetadataRetryInterval)
		return fmt.Errorf("failed to get ECS task metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get ECS task metadata: %s", resp.Status)
	}
	var task struct {
		ServiceName string `json:"ServiceName"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&task); err != nil {
		return fmt.Errorf("failed to decode ECS task metadata: %w", err)
	}
	md.ecsService = task.ServiceName
	return nil
}

func ecsContainerId(md *ContainerMetadata) ContainerID {
	taskArn := md.labels[ecsLabelTaskArn] // arn:aws:ecs:<region>:<account>:task/<cluster>/<task-id>
	name := md.labels[ecsLabelContainerName]
	cluster := md.labels[ecsLabelCluster]
	if taskArn == "" || name == "" || cluster == "" || name == ecsPauseContainerName {
		return ""
	}
	taskId := taskArn[strings.LastIndex(taskArn, "/")+1:]
	if taskId == "" {
		return ""
	}
	service := md.ecsService
	if service == "" {
		service = md.labels[ecsLabelTaskDefinitionFamily]
	}
	if service == "" {
		return ""
	}
	return ContainerID(fmt.Sprintf("/ecs/%s/%s/%s/%s", cluster, service, taskId, name))
}
