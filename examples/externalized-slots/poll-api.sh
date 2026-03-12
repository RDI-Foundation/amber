httpd -f -p 9000 & while true; do echo "[root] calling $API_URL"; wget -qO- "$API_URL" || true; sleep 2; done
