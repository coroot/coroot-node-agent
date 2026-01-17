package containers

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetPrimaryContainer_WithDefaultContainerAnnotation(t *testing.T) {
	tests := []struct {
		name     string
		pod      *v1.Pod
		expected string
	}{
		{
			name: "valid default-container annotation",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kubectl.kubernetes.io/default-container": "api",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{Name: "vault-agent"},
						{Name: "api"},
						{Name: "istio-proxy"},
					},
				},
			},
			expected: "api",
		},
		{
			name: "default-container not found in containers",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kubectl.kubernetes.io/default-container": "nonexistent",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{Name: "vault-agent"},
						{Name: "main"},
					},
				},
			},
			expected: "vault-agent",
		},
		{
			name: "empty default-container annotation",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kubectl.kubernetes.io/default-container": "",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{Name: "main"},
					},
				},
			},
			expected: "main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPrimaryContainer(tt.pod)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestGetPrimaryContainer_WithAppNameLabel(t *testing.T) {
	tests := []struct {
		name     string
		pod      *v1.Pod
		expected string
	}{
		{
			name: "valid app.kubernetes.io/name label",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name": "worker",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{Name: "vault-agent"},
						{Name: "worker"},
						{Name: "otel-collector"},
					},
				},
			},
			expected: "worker",
		},
		{
			name: "app name not matching any container",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name": "service-name",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{Name: "main"},
						{Name: "sidecar"},
					},
				},
			},
			expected: "main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPrimaryContainer(tt.pod)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestGetPrimaryContainer_Priority(t *testing.T) {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"kubectl.kubernetes.io/default-container": "api",
			},
			Labels: map[string]string{
				"app.kubernetes.io/name": "worker",
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Name: "vault-agent"},
				{Name: "api"},
				{Name: "worker"},
			},
		},
	}

	result := GetPrimaryContainer(pod)
	if result != "api" {
		t.Errorf("Expected 'api' (from annotation), got '%s'", result)
	}
}

func TestGetPrimaryContainer_Fallback(t *testing.T) {
	tests := []struct {
		name     string
		pod      *v1.Pod
		expected string
	}{
		{
			name: "no annotations or labels",
			pod: &v1.Pod{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{Name: "vault-agent"},
						{Name: "main"},
					},
				},
			},
			expected: "vault-agent",
		},
		{
			name: "single container",
			pod: &v1.Pod{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{Name: "app"},
					},
				},
			},
			expected: "app",
		},
		{
			name: "empty pod spec",
			pod: &v1.Pod{
				Spec: v1.PodSpec{
					Containers: []v1.Container{},
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPrimaryContainer(tt.pod)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestGetPrimaryContainer_NilPod(t *testing.T) {
	result := GetPrimaryContainer(nil)
	if result != "" {
		t.Errorf("Expected empty string for nil pod, got '%s'", result)
	}
}

func TestDetectApplicationType_MultiContainer(t *testing.T) {
	tests := []struct {
		name     string
		pod      *v1.Pod
		expected ApplicationType
	}{
		{
			name: "vault sidecar, main app is primary",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kubectl.kubernetes.io/default-container": "main",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "vault-agent",
							Image: "hashicorp/vault:1.16.2",
							Ports: []v1.ContainerPort{
								{ContainerPort: 8200},
							},
						},
						{
							Name:  "main",
							Image: "myapp:latest",
							Ports: []v1.ContainerPort{
								{ContainerPort: 8080},
							},
						},
					},
				},
			},
			expected: TypeUnknown,
		},
		{
			name: "postgres as primary with vault sidecar",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name": "postgres",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "vault-agent",
							Image: "hashicorp/vault:1.16.2",
						},
						{
							Name:  "postgres",
							Image: "custom-postgres:latest",
							Ports: []v1.ContainerPort{
								{ContainerPort: 5432},
							},
						},
					},
				},
			},
			expected: TypePostgres,
		},
		{
			name: "istio proxy sidecar with nginx primary",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kubectl.kubernetes.io/default-container": "nginx",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "istio-proxy",
							Image: "istio/proxyv2:1.20.0",
							Ports: []v1.ContainerPort{
								{ContainerPort: 15090},
							},
						},
						{
							Name:  "nginx",
							Image: "custom-registry.io/nginx:alpine",
							Ports: []v1.ContainerPort{
								{ContainerPort: 80},
							},
						},
					},
				},
			},
			expected: TypeNginx,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectApplicationType(tt.pod)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestDetectContainerType(t *testing.T) {
	tests := []struct {
		name      string
		container *v1.Container
		expected  ApplicationType
	}{
		{
			name: "postgres by port",
			container: &v1.Container{
				Name: "db",
				Ports: []v1.ContainerPort{
					{ContainerPort: 5432},
				},
			},
			expected: TypePostgres,
		},
		{
			name: "redis by port",
			container: &v1.Container{
				Name: "cache",
				Ports: []v1.ContainerPort{
					{ContainerPort: 6379},
				},
			},
			expected: TypeRedis,
		},
		{
			name: "postgres by container name",
			container: &v1.Container{
				Name: "postgres-primary",
			},
			expected: TypePostgres,
		},
		{
			name: "mysql by name",
			container: &v1.Container{
				Name: "mysql-db",
			},
			expected: TypeMySQL,
		},
		{
			name: "unknown type",
			container: &v1.Container{
				Name: "custom-app",
				Ports: []v1.ContainerPort{
					{ContainerPort: 8080},
				},
			},
			expected: TypeUnknown,
		},
		{
			name:      "nil container",
			container: nil,
			expected:  TypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectContainerType(tt.container)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestIssue496_RealWorld(t *testing.T) {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "apijs-6d7c75b8d8-kzcjq",
			Labels: map[string]string{
				"app.kubernetes.io/name": "apijs",
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "vault-agent",
					Image: "hashicorp/vault:1.16.2",
					Ports: []v1.ContainerPort{
						{ContainerPort: 8200},
					},
				},
				{
					Name:  "main",
					Image: "custom-registry/apijs:latest",
					Ports: []v1.ContainerPort{
						{Name: "http", ContainerPort: 8882},
					},
				},
			},
		},
	}

	primary := GetPrimaryContainer(pod)
	if primary != "main" {
		t.Errorf("Expected primary container 'main', got '%s'", primary)
	}

	appType := DetectApplicationType(pod)
	if appType == TypeVault {
		t.Error("Should not detect as Vault - vault-agent is just a sidecar")
	}
}

func TestIssue654_RealWorld(t *testing.T) {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"kubectl.kubernetes.io/default-container": "api",
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Name: "istio-proxy"},
				{Name: "otel-collector"},
				{
					Name: "api",
					Ports: []v1.ContainerPort{
						{ContainerPort: 8080},
					},
				},
			},
		},
	}

	primary := GetPrimaryContainer(pod)
	if primary != "api" {
		t.Errorf("Expected primary container 'api', got '%s'", primary)
	}

	appType := DetectApplicationType(pod)
	if appType != TypeUnknown {
		t.Errorf("Expected TypeUnknown for 'api' container, got '%s'", appType)
	}
}
