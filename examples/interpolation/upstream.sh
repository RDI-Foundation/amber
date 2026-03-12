mkdir -p /www; printf 'upstream\n' >/www/index.html; exec httpd -f -p 8080 -h /www
