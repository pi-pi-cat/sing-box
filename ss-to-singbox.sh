#!/bin/bash

# SS to sing-box outbound converter
# 将 Shadowsocks 订阅链接转换为 sing-box outbound JSON 格式
# 作者: Assistant
# 版本: 1.0.0
# 创建日期: 2024-12-28

set -euo pipefail  # 严格模式：出错时退出，未定义变量报错，管道失败时退出

# 全局变量
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly SUPPORTED_METHODS=("aes-128-gcm" "aes-256-gcm" "chacha20-ietf-poly1305" "xchacha20-ietf-poly1305" "2022-blake3-aes-128-gcm" "2022-blake3-aes-256-gcm" "2022-blake3-chacha20-poly1305")

# 输出选项
VERBOSE=false
DEBUG=false
PRETTY_JSON=false
COMPACT_JSON=false
WRAP_CONFIG=false
TEST_CONNECTION=false

# 输入/输出
INPUT_FILE=""
OUTPUT_FILE=""
SUBSCRIPTION_URL=""

# 颜色定义（基于项目现有风格）
readonly RED='\e[31m'
readonly YELLOW='\e[33m'
readonly GREEN='\e[92m'
readonly BLUE='\e[94m'
readonly CYAN='\e[96m'
readonly NONE='\e[0m'

# 全局变量用于存储解析结果
SS_METHOD=""
SS_PASSWORD=""
SS_SERVER=""
SS_PORT=""
SS_TAG=""

# 全局变量用于 extract_method_password 函数
EXTRACTED_METHOD=""
EXTRACTED_PASSWORD=""

# 错误处理函数
error_exit() {
    echo -e "${RED}错误: $1${NONE}" >&2
    [[ $# -gt 1 ]] && exit "$2" || exit 1
}

# 警告信息
warn() {
    echo -e "${YELLOW}警告: $1${NONE}" >&2
}

# 信息输出
info() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${GREEN}信息: $1${NONE}" >&2
    fi
}

# 调试信息
debug() {
    if [[ "$DEBUG" == "true" ]]; then
        echo -e "${CYAN}调试: $1${NONE}" >&2
    fi
}

# 字符串去空白
trim() {
    local str="$1"
    # 去除前后空白字符
    str="${str#"${str%%[![:space:]]*}"}"
    str="${str%"${str##*[![:space:]]}"}"
    echo "$str"
}

# 检查系统依赖
check_dependencies() {
    local missing_deps=()
    
    # 检查必需的命令
    if ! command -v base64 >/dev/null 2>&1; then
        missing_deps+=("base64")
    fi
    
    if ! command -v jq >/dev/null 2>&1; then
        missing_deps+=("jq")
    fi
    
    # 检查可选的命令
    if ! command -v curl >/dev/null 2>&1; then
        warn "curl 未找到，订阅链接下载功能将不可用"
    fi
    
    # 报告缺失的必需依赖
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error_exit "缺少必需的依赖项: ${missing_deps[*]}。请安装后重试。"
    fi
    
    debug "依赖检查完成"
}

# 显示帮助信息
show_help() {
    cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}
将 Shadowsocks (SS) 订阅链接转换为 sing-box outbound JSON 格式

用法:
    ${SCRIPT_NAME} [选项] [SS_URL]
    ${SCRIPT_NAME} -f <文件>
    cat urls.txt | ${SCRIPT_NAME}

选项:
    -f, --file FILE         从文件读取 SS URL（每行一个）
    -o, --output FILE       输出到指定文件（默认为标准输出）
    -u, --subscription URL  下载并处理订阅链接
    -w, --wrap             包装为完整的 sing-box 配置文件
    -p, --pretty           美化 JSON 输出
    -c, --compact          压缩 JSON 输出（移除多余空白）
    -t, --test             测试生成配置的连接性（需要 sing-box）
    -v, --verbose          显示详细信息
    -d, --debug            显示调试信息
    -h, --help             显示此帮助信息
    --version              显示版本信息

示例:
    # 转换单个 SS URL
    ${SCRIPT_NAME} "ss://YWVzLTEyOC1nY206d296aGlhaTA=@38.60.109.178:18804#test"
    
    # 从文件批量转换
    ${SCRIPT_NAME} -f ss_urls.txt -o singbox_outbounds.json -p
    
    # 处理订阅链接
    ${SCRIPT_NAME} -u "https://example.com/subscription" -w -p
    
    # 使用管道
    echo "ss://..." | ${SCRIPT_NAME} -p

支持的加密方法:
    ${SUPPORTED_METHODS[*]}

输出格式:
    标准输出为 sing-box outbound JSON 格式，可选择包装为完整配置文件。

注意事项:
    - SS URL 必须符合标准格式: ss://base64(method:password)@server:port#tag
    - 订阅链接功能需要 curl 命令
    - 连接测试功能需要 sing-box 二进制文件

EOF
}

# 显示版本信息
show_version() {
    echo "${SCRIPT_NAME} v${SCRIPT_VERSION}"
}

# 验证 SS URL 格式
validate_ss_url() {
    local url="$1"
    
    debug "验证 SS URL: $url"
    
    # 检查是否以 ss:// 开头
    if [[ ! "$url" =~ ^ss:// ]]; then
        error_exit "无效的 SS URL 格式：必须以 'ss://' 开头"
    fi
    
    # 检查基本格式：ss://base64@server:port
    if [[ ! "$url" =~ ^ss://[A-Za-z0-9+/=_-]+@[^:]+:[0-9]+.*$ ]]; then
        error_exit "无效的 SS URL 格式：格式应为 ss://base64@server:port[#tag]"
    fi
    
    debug "SS URL 格式验证通过"
    return 0
}

# 解析 SS URL 各部分
parse_ss_url() {
    local url="$1"
    
    debug "开始解析 SS URL: $url"
    
    # 验证 URL 格式
    validate_ss_url "$url"
    
    # 移除 ss:// 前缀
    local url_body="${url#ss://}"
    debug "移除前缀后: $url_body"
    
    # 提取标签部分（# 后面的内容）
    local tag=""
    if [[ "$url_body" =~ ^(.*)#(.*)$ ]]; then
        url_body="${BASH_REMATCH[1]}"
        tag="${BASH_REMATCH[2]}"
        debug "提取标签: $tag"
    fi
    
    # 分离 base64 部分和服务器信息： base64@server:port
    if [[ ! "$url_body" =~ ^([A-Za-z0-9+/=_-]+)@([^:]+):([0-9]+)$ ]]; then
        error_exit "无法解析 SS URL：服务器信息格式错误"
    fi
    
    local base64_part="${BASH_REMATCH[1]}"
    local server="${BASH_REMATCH[2]}" 
    local port="${BASH_REMATCH[3]}"
    
    debug "Base64 部分: $base64_part"
    debug "服务器地址: $server"
    debug "端口: $port"
    
    # 解码 base64 部分获取认证信息
    local decoded_creds
    if ! decoded_creds=$(decode_ss_credentials "$base64_part"); then
        error_exit "无法解码 SS URL 中的认证信息"
    fi
    
    debug "解码的认证信息: $decoded_creds"
    
    # 分离加密方法和密码
    if ! extract_method_password "$decoded_creds"; then
        error_exit "无法分离加密方法和密码"
    fi
    
    # 验证端口范围
    if ! validate_port "$port"; then
        error_exit "无效的端口号: $port"
    fi
    
    # 验证加密方法
    if ! validate_method "$EXTRACTED_METHOD"; then
        warn "可能不支持的加密方法: $EXTRACTED_METHOD"
    fi
    
    # 生成默认标签（如果没有提供）
    if [[ -z "$tag" ]]; then
        tag="ss-${server}-${port}"
    fi
    
    # 使用全局变量存储解析结果（兼容 bash 3.2）
    SS_METHOD="$EXTRACTED_METHOD"
    SS_PASSWORD="$EXTRACTED_PASSWORD"
    SS_SERVER="$server"
    SS_PORT="$port"
    SS_TAG="$tag"
    
    debug "SS URL 解析完成"
    info "解析成功: $EXTRACTED_METHOD://$server:$port (#$tag)"
    
    return 0
}

# 解码 SS 认证信息
decode_ss_credentials() {
    local base64_str="$1"
    
    debug "解码 Base64 字符串: $base64_str"
    
    # 处理 URL-safe base64：替换 - 和 _ 为 + 和 /
    local normalized_b64="${base64_str//-/+}"
    normalized_b64="${normalized_b64//_/\/}"
    
    # 添加必要的 padding（base64 解码可能需要）
    local padding_len=$((4 - ${#normalized_b64} % 4))
    if [[ $padding_len -lt 4 ]]; then
        local padding=$(printf "%*s" $padding_len "")
        normalized_b64="${normalized_b64}${padding// /=}"
    fi
    
    debug "标准化后的 Base64: $normalized_b64"
    
    # 尝试解码
    local decoded
    if ! decoded=$(echo -n "$normalized_b64" | base64 -d 2>/dev/null); then
        debug "标准 base64 解码失败，尝试原始字符串"
        if ! decoded=$(echo -n "$base64_str" | base64 -d 2>/dev/null); then
            return 1
        fi
    fi
    
    echo "$decoded"
    return 0
}

# 分离加密方法和密码
extract_method_password() {
    local creds="$1"
    
    debug "分离认证信息: $creds"
    
    # 格式应该是 method:password
    if [[ ! "$creds" =~ ^([^:]+):(.*)$ ]]; then
        return 1
    fi
    
    # 直接使用全局变量返回结果（兼容 bash 3.2）
    EXTRACTED_METHOD="${BASH_REMATCH[1]}"
    EXTRACTED_PASSWORD="${BASH_REMATCH[2]}"
    
    debug "加密方法: $EXTRACTED_METHOD"
    debug "密码: $EXTRACTED_PASSWORD"
    
    return 0
}

# 验证加密方法
validate_method() {
    local method="$1"
    
    debug "验证加密方法: $method"
    
    # 检查是否在支持列表中
    for supported in "${SUPPORTED_METHODS[@]}"; do
        if [[ "$method" == "$supported" ]]; then
            debug "加密方法 $method 已验证"
            return 0
        fi
    done
    
    debug "加密方法 $method 可能不支持"
    return 1
}

# 验证服务器地址
validate_server() {
    local server="$1"
    
    debug "验证服务器地址: $server"
    
    # 简单验证：不能为空，不能包含非法字符
    if [[ -z "$server" ]]; then
        return 1
    fi
    
    # IPv4 地址验证 (简单)
    if [[ "$server" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        debug "检测到 IPv4 地址"
        return 0
    fi
    
    # IPv6 地址验证 (简单) 
    if [[ "$server" =~ ^\[.*\]$ ]] || [[ "$server" =~ : ]]; then
        debug "检测到 IPv6 地址"
        return 0
    fi
    
    # 域名验证 (简单)
    if [[ "$server" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        debug "检测到域名"
        return 0
    fi
    
    return 1
}

# 验证端口范围
validate_port() {
    local port="$1"
    
    debug "验证端口: $port"
    
    # 检查是否为数字
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    # 检查端口范围 (1-65535)
    if (( port < 1 || port > 65535 )); then
        return 1
    fi
    
    debug "端口 $port 验证通过"
    return 0
}

# 生成 sing-box outbound JSON 
generate_outbound_json() {
    local method="$1"
    local password="$2"
    local server="$3"
    local port="$4"
    local tag="$5"
    
    debug "生成 outbound JSON: $method://$server:$port"
    
    # 验证必要参数
    if [[ -z "$method" || -z "$password" || -z "$server" || -z "$port" || -z "$tag" ]]; then
        error_exit "生成 JSON 缺少必要参数"
    fi
    
    # 创建 JSON 对象
    local json_obj
    json_obj=$(jq -n \
        --arg tag "$tag" \
        --arg type "shadowsocks" \
        --arg server "$server" \
        --argjson port "$port" \
        --arg method "$method" \
        --arg password "$password" \
        '{
            tag: $tag,
            type: $type,
            server: $server,
            server_port: $port,
            method: $method,
            password: $password
        }')
    
    if [[ $? -ne 0 ]]; then
        error_exit "JSON 生成失败"
    fi
    
    echo "$json_obj"
    debug "outbound JSON 生成完成"
}

# 生成完整的 sing-box 配置
generate_full_config() {
    local outbound_json="$1"
    
    debug "生成完整 sing-box 配置"
    
    # 创建完整的配置文件结构
    local full_config
    full_config=$(jq -n \
        --argjson outbound "$outbound_json" \
        '{
            log: {
                level: "info"
            },
            dns: {
                servers: [
                    {
                        tag: "google",
                        address: "8.8.8.8"
                    }
                ]
            },
            outbounds: [
                $outbound,
                {
                    tag: "direct",
                    type: "direct"
                },
                {
                    tag: "block",
                    type: "block"
                }
            ]
        }')
    
    if [[ $? -ne 0 ]]; then
        error_exit "完整配置生成失败"
    fi
    
    echo "$full_config"
    debug "完整配置生成完成"
}

# 格式化 JSON 输出
format_json_output() {
    local json_content="$1"
    
    debug "格式化 JSON 输出"
    
    if [[ "$COMPACT_JSON" == "true" ]]; then
        # 压缩输出
        echo "$json_content" | jq -c '.'
    elif [[ "$PRETTY_JSON" == "true" ]]; then
        # 美化输出
        echo "$json_content" | jq '.'
    else
        # 默认输出
        echo "$json_content"
    fi
}

# 验证生成的 JSON
validate_json() {
    local json_content="$1"
    
    debug "验证 JSON 格式"
    
    # 使用 jq 验证 JSON 格式
    if ! echo "$json_content" | jq empty >/dev/null 2>&1; then
        return 1
    fi
    
    # 验证必要的字段
    local type server port method password
    type=$(echo "$json_content" | jq -r '.type' 2>/dev/null)
    server=$(echo "$json_content" | jq -r '.server' 2>/dev/null)
    port=$(echo "$json_content" | jq -r '.server_port' 2>/dev/null)
    method=$(echo "$json_content" | jq -r '.method' 2>/dev/null)
    password=$(echo "$json_content" | jq -r '.password' 2>/dev/null)
    
    if [[ "$type" != "shadowsocks" ]] || \
       [[ -z "$server" || "$server" == "null" ]] || \
       [[ -z "$port" || "$port" == "null" ]] || \
       [[ -z "$method" || "$method" == "null" ]] || \
       [[ -z "$password" || "$password" == "null" ]]; then
        return 1
    fi
    
    debug "JSON 验证通过"
    return 0
}

# 处理单个 SS URL
process_single_ss_url() {
    local ss_url="$1"
    
    info "处理 SS URL: $ss_url"
    
    # 解析 SS URL
    if ! parse_ss_url "$ss_url"; then
        error_exit "SS URL 解析失败"
    fi
    
    # 生成 outbound JSON
    local outbound_json
    if ! outbound_json=$(generate_outbound_json "$SS_METHOD" "$SS_PASSWORD" "$SS_SERVER" "$SS_PORT" "$SS_TAG"); then
        error_exit "outbound JSON 生成失败"
    fi
    
    # 验证生成的 JSON
    if ! validate_json "$outbound_json"; then
        error_exit "生成的 JSON 验证失败"
    fi
    
    # 是否包装为完整配置
    local final_json
    if [[ "$WRAP_CONFIG" == "true" ]]; then
        final_json=$(generate_full_config "$outbound_json")
    else
        final_json="$outbound_json"
    fi
    
    # 格式化并输出
    format_json_output "$final_json"
    
    info "SS URL 处理完成"
}

# 临时测试函数 - 稍后会被主逻辑替换
test_ss_parsing() {
    local test_url="ss://YWVzLTEyOC1nY206d296aGlhaTA=@38.60.109.178:18804#233boy-ss-38.60.109.178"
    
    info "测试 SS URL 解析功能"
    
    # 解析 SS URL
    if parse_ss_url "$test_url"; then
        echo "解析成功！"
        echo "加密方法: $SS_METHOD"
        echo "密码: $SS_PASSWORD"
        echo "服务器: $SS_SERVER"
        echo "端口: $SS_PORT"
        echo "标签: $SS_TAG"
    else
        echo "解析失败"
    fi
}

# 测试 JSON 生成功能
test_json_generation() {
    local test_url="ss://YWVzLTEyOC1nY206d296aGlhaTA=@38.60.109.178:18804#233boy-ss-38.60.109.178"
    
    info "测试完整的 SS URL 转换功能"
    
    echo "=== 测试基础 outbound JSON ==="
    PRETTY_JSON=true
    WRAP_CONFIG=false
    process_single_ss_url "$test_url"
    
    echo -e "\n=== 测试完整配置 JSON ==="
    WRAP_CONFIG=true
    process_single_ss_url "$test_url"
    
    echo -e "\n=== 测试压缩输出 ==="
    COMPACT_JSON=true
    PRETTY_JSON=false
    WRAP_CONFIG=false
    process_single_ss_url "$test_url"
}

# 主函数
main() {
    # 检查依赖
    check_dependencies
    
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            --version)
                show_version
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--debug)
                DEBUG=true
                VERBOSE=true  # 调试模式自动启用详细输出
                shift
                ;;
            -p|--pretty)
                PRETTY_JSON=true
                shift
                ;;
            -c|--compact)
                COMPACT_JSON=true
                shift
                ;;
            -w|--wrap)
                WRAP_CONFIG=true
                shift
                ;;
            -f|--file)
                if [[ -n "$2" ]]; then
                    INPUT_FILE="$2"
                    shift 2
                else
                    error_exit "选项 -f|--file 需要指定文件路径"
                fi
                ;;
            -o|--output)
                if [[ -n "$2" ]]; then
                    OUTPUT_FILE="$2"
                    shift 2
                else
                    error_exit "选项 -o|--output 需要指定文件路径"
                fi
                ;;
            -u|--subscription)
                if [[ -n "$2" ]]; then
                    SUBSCRIPTION_URL="$2"
                    shift 2
                else
                    error_exit "选项 -u|--subscription 需要指定 URL"
                fi
                ;;
            -t|--test)
                TEST_CONNECTION=true
                shift
                ;;
            --test-parse)
                # 临时测试选项
                test_ss_parsing
                exit 0
                ;;
            --test-json)
                # 测试 JSON 生成
                test_json_generation
                exit 0
                ;;
            -*)
                error_exit "未知选项: $1"
                ;;
            *)
                # 作为 SS URL 处理
                if [[ -n "$1" ]]; then
                    SS_URL="$1"
                fi
                shift
                ;;
        esac
    done
    
    # 处理输入源
    if [[ -n "$SS_URL" ]]; then
        # 处理命令行提供的 SS URL
        info "处理命令行 SS URL"
        if [[ -n "$OUTPUT_FILE" ]]; then
            process_single_ss_url "$SS_URL" > "$OUTPUT_FILE"
            info "结果已保存到: $OUTPUT_FILE"
        else
            process_single_ss_url "$SS_URL"
        fi
    elif [[ -n "$INPUT_FILE" ]]; then
        # 处理文件输入 - 稍后实现
        error_exit "文件输入功能尚未实现"
    elif [[ -n "$SUBSCRIPTION_URL" ]]; then
        # 处理订阅链接 - 稍后实现  
        error_exit "订阅链接功能尚未实现"
    elif [[ ! -t 0 ]]; then
        # 处理管道输入 - 稍后实现
        error_exit "管道输入功能尚未实现"
    else
        # 没有输入，显示帮助
        info "未提供输入，显示帮助信息"
        show_help
        exit 0
    fi
    
    info "脚本执行完成"
}

# 脚本入口点
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi 