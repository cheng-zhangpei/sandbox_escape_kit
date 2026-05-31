#!/bin/bash
set -e
#  ./recon.sh host
# ./recon.sh container-docker sek-test，如果显示设备busy可以尝试重新创建容器哈
# ============================================================
# recon.sh — 信息收集脚本
# 分别在宿主机和容器内运行，收集两端数据
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_PATH="$SCRIPT_DIR/bin/sek"
OUTPUT_DIR="$SCRIPT_DIR/output"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    echo "Usage:"
    echo "  $0 host                           在宿主机上运行采集"
    echo "  $0 container                      在当前容器内运行采集"
    echo "  $0 container-docker <容器名>       从宿主机远程进入容器采集"
    echo ""
    echo "输出保存在 $OUTPUT_DIR/ 目录下"
}

check_bin() {
    if [ ! -f "$BIN_PATH" ]; then
        echo -e "${RED}[!] Binary not found: $BIN_PATH${NC}"
        echo "    Run: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $BIN_PATH ./cmd/sek/"
        exit 1
    fi
    if [ ! -x "$BIN_PATH" ]; then
        chmod +x "$BIN_PATH"
    fi
}

collect_host() {
    echo -e "${GREEN}[*] Collecting host recon...${NC}"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT="$OUTPUT_DIR/host.json"

    "$BIN_PATH" collect --target host -o "$OUTPUT"

    echo -e "${GREEN}[+] Host recon saved to: $OUTPUT${NC}"
}

collect_container() {
    echo -e "${GREEN}[*] Collecting container recon...${NC}"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT="$OUTPUT_DIR/container.json"

    "$BIN_PATH" collect --target container -o "$OUTPUT"

    echo -e "${GREEN}[+] Container recon saved to: $OUTPUT${NC}"
}

collect_container_remote() {
    CONTAINER_NAME="$1"
    if [ -z "$CONTAINER_NAME" ]; then
        echo -e "${RED}[!] Container name required${NC}"
        usage
        exit 1
    fi

    echo -e "${GREEN}[*] Collecting from container: $CONTAINER_NAME${NC}"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT="$OUTPUT_DIR/container_${CONTAINER_NAME}.json"

    # 先清理可能残留的旧文件
    docker exec "$CONTAINER_NAME" sh -c 'rm -f /tmp/sek-recon /tmp/sek-recon.json' 2>/dev/null || true

    # 拷贝二进制进容器
    echo -e "${YELLOW}[*] Copying binary into container...${NC}"
    docker cp "$BIN_PATH" "$CONTAINER_NAME:/tmp/sek-recon"
    docker exec "$CONTAINER_NAME" chmod +x /tmp/sek-recon

    # 在容器内执行采集
    echo -e "${YELLOW}[*] Running collect inside container...${NC}"
    docker exec "$CONTAINER_NAME" sh -c '/tmp/sek-recon collect --target container > /tmp/sek-recon.json'

    # 拷出结果
    docker cp "$CONTAINER_NAME:/tmp/sek-recon.json" "$OUTPUT"

    # 清理
    docker exec "$CONTAINER_NAME" sh -c 'rm -f /tmp/sek-recon /tmp/sek-recon.json'

    echo -e "${GREEN}[+] Container recon saved to: $OUTPUT${NC}"
}
check_bin

case "${1:-}" in
    host)
        collect_host
        ;;
    container)
        collect_container
        ;;
    container-docker)
        collect_container_remote "$2"
        ;;
    *)
        usage
        exit 1
        ;;
esac
