#!/usr/bin/env bash
# ==============================================================================
# 腳本名稱: php2shell_threat_hunter.sh
# 說明: 針對 PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 的威脅獵殺與自動化檢測腳本
# 支援: Nginx 解析、PHP 設定動態檢測、systemd cgroup 限制檢查、WebShell 掃描
# ==============================================================================

set -u

# --- 顏色定義 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- 日誌紀錄設定 ---
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_LOG="/tmp/security_audit_${TIMESTAMP}.log"

log() {
    local level="$1"
    local message="$2"
    case "$level" in
        "OK")
            echo -e "[${GREEN}OK${NC}] $message" | tee -a "$OUTPUT_LOG"
            ;;
        "WARNING")
            echo -e "[${YELLOW}WARNING${NC}] $message" | tee -a "$OUTPUT_LOG"
            ;;
        "CRITICAL")
            echo -e "[${RED}CRITICAL${NC}] $message" | tee -a "$OUTPUT_LOG"
            ;;
        "INFO")
            echo -e "[${BLUE}INFO${NC}] $message" | tee -a "$OUTPUT_LOG"
            ;;
        *)
            echo "$message" | tee -a "$OUTPUT_LOG"
            ;;
    esac
}

echo "==================================================================" | tee "$OUTPUT_LOG"
echo " PHP2Shell (CVE-2026-109618/109619) 威脅獵殺與 Nginx 動態檢測腳本" | tee -a "$OUTPUT_LOG"
echo " 執行時間: $(date)" | tee -a "$OUTPUT_LOG"
echo " 檢測結果導出至: $OUTPUT_LOG" | tee -a "$OUTPUT_LOG"
echo "==================================================================" | tee -a "$OUTPUT_LOG"
echo "" | tee -a "$OUTPUT_LOG"

# 權限檢查
if [ "$EUID" -ne 0 ]; then
  log "WARNING" "建議以 root 權限執行此腳本，以確保能讀取所有設定與進程資訊。"
fi

# ==============================================================================
# 1. PHP 版本與核心設定安全檢查 (含 cgroup 檢查)
# ==============================================================================
log "INFO" ">>> [1/5] 開始檢查 PHP 環境與配置..."

if command -v php >/dev/null 2>&1; then
    PHP_VER=$(php -v | head -n 1 | awk '{print $2}')
    log "INFO" "偵測到系統 PHP 版本: $PHP_VER"

    # 比對修補版本 (8.2.35, 8.3.36, 8.4.27, 8.5.12)
    IS_VULN=0
    if [[ "$PHP_VER" =~ ^8\.2\. ]] && [[ $(echo -e "$PHP_VER\n8.2.35" | sort -V | head -n1) == "$PHP_VER" ]] && [ "$PHP_VER" != "8.2.35" ]; then IS_VULN=1; fi
    if [[ "$PHP_VER" =~ ^8\.3\. ]] && [[ $(echo -e "$PHP_VER\n8.3.36" | sort -V | head -n1) == "$PHP_VER" ]] && [ "$PHP_VER" != "8.3.36" ]; then IS_VULN=1; fi
    if [[ "$PHP_VER" =~ ^8\.4\. ]] && [[ $(echo -e "$PHP_VER\n8.4.27" | sort -V | head -n1) == "$PHP_VER" ]] && [ "$PHP_VER" != "8.4.27" ]; then IS_VULN=1; fi
    if [[ "$PHP_VER" =~ ^8\.5\. ]] && [[ $(echo -e "$PHP_VER\n8.5.12" | sort -V | head -n1) == "$PHP_VER" ]] && [ "$PHP_VER" != "8.5.12" ]; then IS_VULN=1; fi
    if [[ "$PHP_VER" =~ ^(5\.|7\.|8\.[01]\.) ]]; then IS_VULN=1; fi

    if [ "$IS_VULN" -eq 1 ]; then
        log "CRITICAL" "目前 PHP 版本 ($PHP_VER) 低於安全修補點，處於漏洞暴露風險中！"
    else
        log "OK" "目前 PHP 版本 ($PHP_VER) 處於安全區間或已更新。"
    fi

    # 透過 PHP CLI 獲取設定值
    eval $(php -r '
        $u_prog = ini_get("session.upload_progress.enabled");
        $mem_lim = ini_get("memory_limit");
        $post_max = ini_get("post_max_size");
        $upload_max = ini_get("upload_max_filesize");
        echo "U_PROG=\"$u_prog\"; MEM_LIM=\"$mem_lim\"; POST_MAX=\"$post_max\"; UPLOAD_MAX=\"$upload_max\";";
    ')

    log "INFO" "php.ini 設定掃描結果："
    log "INFO" "  ├─ session.upload_progress.enabled : ${U_PROG:-1}"
    log "INFO" "  ├─ memory_limit                    : ${MEM_LIM}"
    log "INFO" "  ├─ post_max_size                   : ${POST_MAX}"
    log "INFO" "  └─ upload_max_filesize             : ${UPLOAD_MAX}"

    # 1. 檢查 session.upload_progress.enabled
    if [ "$U_PROG" == "1" ] || [ -z "$U_PROG" ]; then
        log "WARNING" "[建議調整] session.upload_progress.enabled 當前為 1。"
        log "WARNING" "  └─ 建議在 php.ini 修改為 session.upload_progress.enabled = 0 (關閉上傳進度監控)"
    else
        log "OK" "[安全] session.upload_progress.enabled 已設為 0。"
    fi

    # 2. 檢查 memory_limit
    if [ "$IS_VULN" -eq 1 ] && [ "$MEM_LIM" != "-1" ]; then
        log "WARNING" "[建議調整] memory_limit 當前為 $MEM_LIM。"
        log "WARNING" "  └─ 為了防範 CVE-2026-109618 記憶體崩潰，建議暫時改為 memory_limit = -1 (並搭配 cgroup/Docker 限制記憶體)"
    else
        log "OK" "[安全] memory_limit 設定符合應急防禦或已完成版本更新。"
    fi

    # 3. 檢查 post_max_size 與 upload_max_filesize
    POST_NUM=$(echo "$POST_MAX" | sed 's/[^0-9]//g')
    UPLOAD_NUM=$(echo "$UPLOAD_MAX" | sed 's/[^0-9]//g')

    if [ -n "$POST_NUM" ] && [ "$POST_NUM" -gt 32 ]; then
        log "WARNING" "[建議調整] post_max_size 當前為 $POST_MAX (偏大)。"
        log "WARNING" "  └─ 建議降低上傳上限（不需要上傳者建議 8M，需要者建議 32M 以下）"
    else
        log "OK" "[安全] post_max_size 限制良好 ($POST_MAX)。"
    fi

    if [ -n "$POST_NUM" ] && [ -n "$UPLOAD_NUM" ] && [ "$UPLOAD_NUM" -gt "$POST_NUM" ]; then
        log "WARNING" "[建議調整] upload_max_filesize ($UPLOAD_MAX) 大於 post_max_size ($POST_MAX)。"
        log "WARNING" "  └─ 建議確保 upload_max_filesize 低於 post_max_size 的限制"
    fi

    # 4. 新增：systemd cgroup 記憶體限制檢查 (MemoryLimit)
    if command -v systemctl >/dev/null 2>&1; then
        FPM_SERVICE=$(systemctl list-units --type=service | grep -iE 'php.*fpm' | awk '{print $1}' | head -n 1)
        if [ -n "$FPM_SERVICE" ]; then
            CGROUP_MEM=$(systemctl show "$FPM_SERVICE" -p MemoryLimit | awk -F'=' '{print $2}')
            if [ -z "$CGROUP_MEM" ] || [ "$CGROUP_MEM" == "infinity" ] || [ "$CGROUP_MEM" == "18446744073709551615" ]; then
                log "WARNING" "[建議調整] $FPM_SERVICE 未設定 systemd cgroup 記憶體上限 (MemoryLimit)[cite: 3]！"
                log "WARNING" "  └─ 若 php.ini 設為 memory_limit = -1，請務必建立 override.conf 設定 MemoryLimit 以護航主機不致 Out of Memory 崩潰[cite: 3]。"
            else
                MEM_MB=$((CGROUP_MEM / 1024 / 1024))
                log "OK" "[安全] $FPM_SERVICE 已啟用 cgroup 記憶體邊界限制 (${MEM_MB} MB)[cite: 3]。"
            fi
        fi
    fi

else
    log "WARNING" "未在 PATH 中找到 php CLI 命令，跳過 PHP 內部設定檢查。"
fi

echo "" | tee -a "$OUTPUT_LOG"

# ==============================================================================
# 2. 自動解析 Nginx 設定檔 (提取 Web 根目錄與 Log 路徑)
# ==============================================================================
log "INFO" ">>> [2/5] 開始自動解析 Nginx 配置檔..."

NGINX_CONF_PATHS=("/etc/nginx/nginx.conf" "/etc/nginx/conf.d/*.conf" "/etc/nginx/sites-enabled/*" "/usr/local/nginx/conf/nginx.conf")
WEB_ROOTS=()
ACCESS_LOGS=()
ERROR_LOGS=()

CONF_FILES=$(ls ${NGINX_CONF_PATHS[@]} 2>/dev/null)

if [ -n "$CONF_FILES" ]; then
    for conf in $CONF_FILES; do
        if [ -f "$conf" ]; then
            roots=$(grep -E '^\s*root\s+' "$conf" | awk '{print $2}' | sed 's/;//g')
            for r in $roots; do WEB_ROOTS+=("$r"); done

            ac_logs=$(grep -E '^\s*access_log\s+' "$conf" | awk '{print $2}' | grep -v 'off' | sed 's/;//g')
            for al in $ac_logs; do ACCESS_LOGS+=("$al"); done

            er_logs=$(grep -E '^\s*error_log\s+' "$conf" | awk '{print $2}' | sed 's/;//g')
            for el in $er_logs; do ERROR_LOGS+=("$el"); done
        fi
    done
fi

if [ ${#WEB_ROOTS[@]} -eq 0 ]; then WEB_ROOTS+=("/var/www/html"); fi
if [ ${#ACCESS_LOGS[@]} -eq 0 ]; then ACCESS_LOGS+=("/var/log/nginx/access.log"); fi
if [ ${#ERROR_LOGS[@]} -eq 0 ]; then ERROR_LOGS+=("/var/log/nginx/error.log"); fi

UNIQUE_ROOTS=($(echo "${WEB_ROOTS[@]}" | tr ' ' '\n' | sort -u))
UNIQUE_ACCESS_LOGS=($(echo "${ACCESS_LOGS[@]}" | tr ' ' '\n' | sort -u))
UNIQUE_ERROR_LOGS=($(echo "${ERROR_LOGS[@]}" | tr ' ' '\n' | sort -u))

log "OK" "解析完成。定位到的 Web 根目錄: ${UNIQUE_ROOTS[*]}"
log "OK" "定位到的 Access Logs: ${UNIQUE_ACCESS_LOGS[*]}"
log "OK" "定位到的 Error Logs: ${UNIQUE_ERROR_LOGS[*]}"

echo "" | tee -a "$OUTPUT_LOG"

# ==============================================================================
# 3. 日誌分析與攻擊痕跡檢索
# ==============================================================================
log "INFO" ">>> [3/5] 開始進行日誌威脅獵殺 (Log Audit)..."

for err_log in "${UNIQUE_ERROR_LOGS[@]}"; do
    if [ -f "$err_log" ]; then
        log "INFO" "正在分析 Error Log: $err_log"
        FATAL_ERRS=$(grep -iE 'Fatal error|Uncaught Error|Maximum execution time exceeded|Segmentation fault|core dumped' "$err_log" | wc -l)
        if [ "$FATAL_ERRS" -gt 0 ]; then
            log "CRITICAL" "在 $err_log 中發現 $FATAL_ERRS 次 PHP 崩潰/嚴重錯誤紀錄！"
            echo "--- 最近 5 筆異常 Error 紀錄 ---" >> "$OUTPUT_LOG"
            grep -iE 'Fatal error|Uncaught Error|Maximum execution time exceeded|Segmentation fault|core dumped' "$err_log" | tail -n 5 >> "$OUTPUT_LOG"
        else
            log "OK" "未在 $err_log 中發現顯著崩潰紀錄。"
        fi
    fi
done

for acc_log in "${UNIQUE_ACCESS_LOGS[@]}"; do
    if [ -f "$acc_log" ]; then
        log "INFO" "正在分析 Access Log: $acc_log"
        SUSP_POST=$(grep -E 'POST ' "$acc_log" | grep -iE 'PHP_SESSION_UPLOAD_PROGRESS|base64|eval\(|passthru|shell_exec' | wc -l)
        if [ "$SUSP_POST" -gt 0 ]; then
            log "CRITICAL" "在 $acc_log 中發現 $SUSP_POST 次可疑的 POST Payload 請求！"
            echo "--- 最近 5 筆可疑 Access 紀錄 ---" >> "$OUTPUT_LOG"
            grep -E 'POST ' "$acc_log" | grep -iE 'PHP_SESSION_UPLOAD_PROGRESS|base64|eval\(|passthru|shell_exec' | tail -n 5 >> "$OUTPUT_LOG"
        else
            log "OK" "未在 $acc_log 中發現可疑 POST 攻擊特徵。"
        fi
    fi
done

echo "" | tee -a "$OUTPUT_LOG"

# ==============================================================================
# 4. Web 根目錄 WebShell 與變動檔案掃描
# ==============================================================================
log "INFO" ">>> [4/5] 開始掃描 Web 目錄異動與 WebShell 惡意特徵..."

for root_dir in "${UNIQUE_ROOTS[@]}"; do
    if [ -d "$root_dir" ]; then
        log "INFO" "正在掃描目錄: $root_dir"

        NEW_FILES=$(find "$root_dir" -type f -name "*.php" -mtime -7 2>/dev/null)
        if [ -n "$NEW_FILES" ]; then
            COUNT=$(echo "$NEW_FILES" | wc -l)
            log "WARNING" "在 $root_dir 下發現近 7 天內有 $COUNT 個 PHP 檔案被新增或修改。"
            echo "$NEW_FILES" | head -n 10 >> "$OUTPUT_LOG"
        else
            log "OK" "近 7 天內無異常 PHP 檔案異動。"
        fi

        WEBSHELL_MATCHES=$(grep -rnE '(eval\s*\(|assert\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|gzinflate\s*\(base64_decode)' "$root_dir" --include="*.php" 2>/dev/null)
        if [ -n "$WEBSHELL_MATCHES" ]; then
            log "CRITICAL" "在 $root_dir 發現潛在的 WebShell 或高風險代碼特徵！"
            echo "--- 惡意特徵比對結果 ---" >> "$OUTPUT_LOG"
            echo "$WEBSHELL_MATCHES" | head -n 10 >> "$OUTPUT_LOG"
        else
            log "OK" "未掃描到常見 WebShell 特徵碼。"
        fi

        HIDDEN_PHP=$(find "$root_dir" -type f -name ".*.php" 2>/dev/null)
        if [ -n "$HIDDEN_PHP" ]; then
            log "CRITICAL" "發現隱藏的 PHP 檔: $HIDDEN_PHP"
        fi
    fi
done

TMP_EXECS=$(find /tmp /var/tmp /dev/shm -type f \( -name "*.php" -o -name "*.sh" -o -executable \) 2>/dev/null)
if [ -n "$TMP_EXECS" ]; then
    log "WARNING" "在系統暫存目錄 (/tmp, /dev/shm) 發現可疑檔案/可執行檔:"
    echo "$TMP_EXECS" >> "$OUTPUT_LOG"
fi

echo "" | tee -a "$OUTPUT_LOG"

# ==============================================================================
# 5. 系統進程與網路外連檢查
# ==============================================================================
log "INFO" ">>> [5/5] 開始檢查系統異常進程與 Reverse Shell 連線..."

SUSP_PROC=$(ps aux | grep -iE 'php-fpm|apache|nginx' | grep -v grep | grep -E 'sh|bash|nc|python|perl|ruby')
if [ -n "$SUSP_PROC" ]; then
    log "CRITICAL" "偵測到 Web 服務進程衍生出異常的 Shell 或指令執行進程！"
    echo "$SUSP_PROC" >> "$OUTPUT_LOG"
else
    log "OK" "未發現 Web 進程衍生異常 Shell。"
fi

if command -v ss >/dev/null 2>&1; then
    ESTAB_CONN=$(ss -tupn | grep -iE 'php|www-data|apache|nginx' | grep 'ESTAB')
    if [ -n "$ESTAB_CONN" ]; then
        log "INFO" "當前 Web 服務對外連線狀態:"
        echo "$ESTAB_CONN" >> "$OUTPUT_LOG"
    fi
fi

echo "" | tee -a "$OUTPUT_LOG"

# ==============================================================================
# 報告輸出與臨時防禦建議
# ==============================================================================
log "INFO" "=================================================================="
log "INFO" "                    💡 臨時防禦手段調整建議                      "
log "INFO" "=================================================================="

cat << 'EOF' | tee -a "$OUTPUT_LOG"

【1. Nginx 應急防禦配置建議】
在 Nginx 設定檔的 server {} 區塊中加入以下規則限制攻擊面：

  # 封鎖 Upload Progress 攻擊
  if ($http_cookie ~* "PHP_SESSION_UPLOAD_PROGRESS") {
      return 403;
  }

  # 限制請求 Body 大小
  client_max_body_size 10M;

【2. PHP-FPM 緩解措施 (CVE-2026-109619)】
編輯 /etc/php-fpm.d/www.conf 或 pool 設定檔：

  pm.max_requests = 100   ; 強迫 Worker 經常重啟，斷絕跨請求狀態殘留

【3. systemd cgroup 記憶體邊界限制 (/etc/systemd/system/php-fpm.service.d/override.conf)】
由於將 PHP 內部 memory_limit 設為 -1，必須在系統層級建立 cgroup 記憶體硬邊界，保護主機不致崩潰：

  1. 建立並編輯覆蓋檔：
     mkdir -p /etc/systemd/system/php-fpm.service.d/
     cat << 'CONF' > /etc/systemd/system/php-fpm.service.d/override.conf
[Service]
MemoryAccounting=true
MemoryLimit=1.2G
CONF

  2. 載入設定並重啟 PHP-FPM：
     systemctl daemon-reload
     systemctl restart php-fpm

  3. 驗證限制是否生效：
     systemctl show php-fpm -p MemoryLimit
     # 預期顯示：MemoryLimit=1288490188 (即 1.2GB)

【4. php.ini 應急設定調整】
  session.upload_progress.enabled = 0   ; 關閉 Session 上傳進度監控
  memory_limit = -1                    ; 搭配 cgroup 防範觸發 PHP 層級 OOM
  post_max_size = 8M                   ; 降低 POST 請求容量邊界
  upload_max_filesize = 8M

【5. 最終處置建議】
請儘速將 PHP 版本升級至安全修補版本：
  • PHP 8.5 -> 8.5.12 | PHP 8.4 -> 8.4.27 | PHP 8.3 -> 8.3.36 | PHP 8.2 -> 8.2.35

EOF

log "INFO" "檢查完畢！詳細報告已彙整至: $OUTPUT_LOG"
