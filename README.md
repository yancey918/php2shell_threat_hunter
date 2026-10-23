# php2shell_threat_hunter
PHP2Shell 威脅獵殺腳本生成 Prompt 模板
```
# 使用方式
chmod +x php2shell_threat_hunter.sh
./php2shell_threat_hunter.sh

Note1: 若有CRITICAL再將產出的logs丟給AI分析是否為誤判
Note2: 網路上大多只提到 php.ini 設為 memory_limit = -1 , 但未說明 cgroup 邊界如何設定
```

<img width="588" height="513" alt="image" src="https://github.com/user-attachments/assets/9650568a-75cf-4d6d-ab38-d48cfb3caf0f" />


```
PHP2Shell 威脅獵殺腳本生成 Prompt 模板
【任務目標】
請為我撰寫一份自動化 Linux 安全檢測腳本（使用 Bash），用於針對近期爆發的 PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 進行伺服器威脅獵殺、Nginx 動態分析、PHP 環境安全檢查與防禦建議產出。

【腳本功能與架構需求】

基礎設定與執行紀錄：

採用原生 Bash 開發，預設包含顏色輸出（OK 綠色 / WARNING 黃色 / CRITICAL 紅色 / INFO 藍色）。

執行時自動建立時間戳記，將所有輸出同步寫入 /tmp/security_audit_<timestamp>.log。

檢查是否具備 root 權限，若無則跳出 warning 提示。

[1/5] PHP 環境與安全配置檢測：

版本比對： 檢查 php -v，比對目前版本是否低於安全修補點（8.2.35、8.3.36、8.4.27、8.5.12，以及所有 5.x / 7.x / 8.0 / 8.1 舊版）。低於安全版本則標示 CRITICAL。

PHP 內部設定檢測： 使用 php -r 動態抓取以下關鍵設定並給予調整建議：

session.upload_progress.enabled：若為 1 則 Warning 並建議改為 0。

memory_limit：若存在漏洞且非 -1，建議改為 -1 並搭配系統限制。

post_max_size & upload_max_filesize：比對大小（如大於 32M 或 upload > post），若不合理則給予建議。

systemd cgroup 邊界檢查： 自動尋找系統中的 php-fpm 服務，使用 systemctl show <service> -p MemoryLimit 檢查是否已有設定 MemoryLimit。若未設定且未更新 PHP，提示 Warning 並建議配置 cgroup 硬邊界。

[2/5] Nginx 設定檔自動動態解析：

自動掃描 Nginx 配置路徑（如 /etc/nginx/nginx.conf、/etc/nginx/conf.d/*.conf、/etc/nginx/sites-enabled/*）。

使用 awk/sed/grep 自動提取出所有作用中的 root（Web 根目錄）、access_log 與 error_log 路徑並去重。若找不到則使用標準預設路徑。

[3/5] 日誌威脅獵殺 (Log Audit)：

Error Logs： 掃描爆量的 Fatal error、Uncaught Error、Maximum execution time exceeded 或 Segmentation fault / core dumped 等記憶體崩潰紀錄。

Access Logs： 掃描 POST 請求中是否含有 PHP_SESSION_UPLOAD_PROGRESS、base64、eval(、passthru、shell_exec 等可疑攻擊 Payload。

[4/5] Web 根目錄 WebShell 與異動掃描：

針對動態定位到的各 Web 根目錄，搜尋近 7 天內異動/新增的 .php 檔案。

掃描高風險 WebShell 函式組合（eval(、assert(、system(、passthru(、shell_exec(、gzinflate(base64_decode）。

掃描隱藏檔（如 .*.php）以及 /tmp、/dev/shm 暫存目錄下的可疑可執行檔。

[5/5] 系統進程與 Reverse Shell 連線檢查：

檢查 PHP-FPM / Nginx / Apache 是否衍生出 /bin/sh、bash、nc、python 等異常指令執行進程。

使用 ss -tupn 或 netstat 檢視當前 Web 服務連線狀況。

報告產出與臨時防禦手段建議摘要：

在腳本最後，整理並輸出一份針對 PHP2Shell 的應急防禦指引：

Nginx 阻擋 PHP_SESSION_UPLOAD_PROGRESS Cookie 規則與 client_max_body_size 設定。

PHP-FPM pm.max_requests = 100 狀態殘留緩解手段。

override.conf systemd cgroup 記憶體邊界（MemoryAccounting=true、MemoryLimit=1.2G）完整的 cat << 'CONF' 建立與套用命令範例。

php.ini 設定建議（session.upload_progress.enabled = 0、memory_limit = -1）。

【腳本輸出要求】

語法必須嚴格符合 bash 規範，並在開頭宣告 set -u。

請直接輸出完整可直接執行的腳本內容，不需省略中間程式碼。
```
