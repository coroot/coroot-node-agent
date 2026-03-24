ASSETS_DIR = ../jvm/assets

build:
	@echo ===BUILDING JAVA TLS AGENT===
	docker rmi -f java-tls-agent-builder 2>/dev/null || true
	docker build -t java-tls-agent-builder --progress plain .
	mkdir -p $(ASSETS_DIR)
	docker run --rm java-tls-agent-builder cat /tmp/java-agent/target/libcoroot_java_tls_amd64.so > $(ASSETS_DIR)/libcoroot_java_tls_amd64.so
	docker run --rm java-tls-agent-builder cat /tmp/java-agent/target/libcoroot_java_tls_arm64.so > $(ASSETS_DIR)/libcoroot_java_tls_arm64.so
	docker run --rm java-tls-agent-builder cat /tmp/java-agent/target/coroot-java-tls-agent-0.1.0.jar > $(ASSETS_DIR)/coroot-java-tls-agent.jar
	@echo
