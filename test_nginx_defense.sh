#!/usr/bin/env bash
# ==============================================================================
# 說明: 測試 Nginx 是否針對 PHP_SESSION_UPLOAD_PROGRESS 特徵回傳 403 Forbidden
# 用法: ./test_nginx_defense.sh https://your-domain.com
# ==============================================================================

set -u

# 檢查是否提供網址參數
if [ $# -ne 1 ]; then
    echo "使用方式: $0 <目標網址>"
    echo "範例: $0 https://example.com"
    exit 1
fi

TARGET_URL="$1"

echo "=================================================================="
echo "          Nginx 防禦規則 HTTP 回應驗證工具                         "
echo " 目標網址: $TARGET_URL"
echo "=================================================================="
echo ""

# 發送帶有防禦特徵 Cookie 的 HTTP Header 請求
echo "[+] 發送測試 Request (包含 PHP_SESSION_UPLOAD_PROGRESS Header)..."

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -I \
  -H "Cookie: PHPSESSID=test; PHP_SESSION_UPLOAD_PROGRESS=test_check" \
  "$TARGET_URL")

echo "[+] 收到 HTTP 回應狀態碼: $HTTP_STATUS"
echo ""

# 判斷驗證結果
if [ "$HTTP_STATUS" -eq 403 ]; then
    echo "【驗證結果：成功】"
    echo "  └─ Nginx 已正確辨識特徵並回傳 403 Forbidden，成功在入口端阻擋該請求！"
elif [ "$HTTP_STATUS" -eq 200 ] || [ "$HTTP_STATUS" -eq 301 ] || [ "$HTTP_STATUS" -eq 302 ]; then
    echo "【驗證結果：未阻擋 (HTTP $HTTP_STATUS)】"
    echo "  └─ Nginx 未對該 Header 設定 403 阻擋規則。"
    echo "  └─ 備註：若底層 PHP 已更新至安全版本 (如 8.4.27+)，系統整體依然安全。"
else
    echo "【驗證結果：其他狀態碼 (HTTP $HTTP_STATUS)】"
    echo "  └─ 請確認目標網址是否正確或伺服器連線狀態。"
fi

echo "=================================================================="
