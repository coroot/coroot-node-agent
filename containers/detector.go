package containers

import (
	"strings"
	v1 "k8s.io/api/core/v1"
)

type ApplicationType string

const (
	TypeUnknown      ApplicationType = "unknown"
	TypeVault        ApplicationType = "vault"
	TypeNginx        ApplicationType = "nginx"
	TypePostgres     ApplicationType = "postgres"
	TypeRedis        ApplicationType = "redis"
	TypeMongoDB      ApplicationType = "mongodb"
	TypeMySQL        ApplicationType = "mysql"
	TypeElasticsearch ApplicationType = "elasticsearch"
	TypeKafka        ApplicationType = "kafka"
	TypeRabbitMQ     ApplicationType = "rabbitmq"
)

func DetectApplicationType(pod *v1.Pod) ApplicationType {
	if pod == nil {
		return TypeUnknown
	}

	primaryContainerName := GetPrimaryContainer(pod)
	if primaryContainerName == "" {
		return TypeUnknown
	}

	var primaryContainer *v1.Container
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == primaryContainerName {
			primaryContainer = &pod.Spec.Containers[i]
			break
		}
	}

	if primaryContainer == nil {
		return TypeUnknown
	}

	return detectContainerType(primaryContainer)
}

func detectContainerType(container *v1.Container) ApplicationType {
	if container == nil {
		return TypeUnknown
	}

	for _, port := range container.Ports {
		switch port.ContainerPort {
		case 5432:
			return TypePostgres
		case 6379:
			return TypeRedis
		case 27017:
			return TypeMongoDB
		case 3306:
			return TypeMySQL
		case 9200, 9300:
			return TypeElasticsearch
		case 9092:
			return TypeKafka
		case 5672:
			return TypeRabbitMQ
		case 8200:
			if strings.Contains(strings.ToLower(container.Name), "vault") {
				return TypeVault
			}
		}
	}

	containerName := strings.ToLower(container.Name)
	
	switch {
	case strings.Contains(containerName, "postgres"):
		return TypePostgres
	case strings.Contains(containerName, "redis"):
		return TypeRedis
	case strings.Contains(containerName, "mongo"):
		return TypeMongoDB
	case strings.Contains(containerName, "mysql"):
		return TypeMySQL
	case strings.Contains(containerName, "nginx"):
		return TypeNginx
	case strings.Contains(containerName, "elasticsearch") || strings.Contains(containerName, "elastic"):
		return TypeElasticsearch
	case strings.Contains(containerName, "kafka"):
		return TypeKafka
	case strings.Contains(containerName, "rabbitmq") || strings.Contains(containerName, "rabbit"):
		return TypeRabbitMQ
	}

	return TypeUnknown
}
