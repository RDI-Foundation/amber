mkdir -p /www && echo 'ok' > /www/index.html && exec busybox httpd -f -p 8080 -h /www
