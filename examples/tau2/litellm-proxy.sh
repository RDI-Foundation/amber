cat > /etc/nginx/conf.d/default.conf <<EOF
server {
  listen 8081;
  location / {
    proxy_pass $BACKEND_URL/v1$request_uri;
  }
}
server {
  listen 8082;
  location / {
    proxy_pass $BACKEND_URL/api$request_uri;
  }
}
EOF
nginx -g 'daemon off;'
