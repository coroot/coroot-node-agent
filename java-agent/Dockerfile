FROM debian:bullseye

RUN apt-get update && apt-get install -y \
    default-jdk maven gcc gcc-aarch64-linux-gnu

ENV JAVA_HOME=/usr/lib/jvm/default-java

WORKDIR /tmp/java-agent
COPY . .

RUN mkdir -p target && \
    gcc -shared -fPIC -O2 -nostdlib -nodefaultlibs \
        -I${JAVA_HOME}/include \
        -I${JAVA_HOME}/include/linux \
        -o target/libcoroot_java_tls_amd64.so native/coroot_java_tls.c && \
    aarch64-linux-gnu-gcc -shared -fPIC -O2 -nostdlib -nodefaultlibs \
        -I${JAVA_HOME}/include \
        -I${JAVA_HOME}/include/linux \
        -o target/libcoroot_java_tls_arm64.so native/coroot_java_tls.c

RUN mvn package -q -DskipTests
