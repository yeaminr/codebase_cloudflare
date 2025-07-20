# syntax=docker/dockerfile:1
FROM container-soe.docker.internal.cba/ubuntu:jammy
# https://github.com/CBA-General/container-soe/blob/c2bb7758191fcde59efff7b171cc2320e8875657/ubuntu/Dockerfile#L6C1-L7C19
 
# Set timezone to Sydney time
ENV TZ="Australia/Sydney"

USER root
 
RUN apt-get -y update && apt-get install -y --no-install-recommends nginx
COPY <<EOF /etc/nginx/nginx.conf 
user www-data;
worker_processes auto;
pid /tmp/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        # server_tokens off;

        # server_names_hash_bucket_size 64;
        # server_name_in_redirect off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        ##
        # SSL Settings
        ##

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
        ssl_prefer_server_ciphers on;

        ##
        # Logging Settings
        ##

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        ##
        # Gzip Settings
        ##

        gzip on;

        include /etc/nginx/sites-enabled/default;
}
EOF
RUN mkdir -p /var/lib/nginx/body /var/lib/nginx/proxy /var/lib/nginx/fastcgi /var/lib/nginx/uwsgi /var/lib/nginx/scgi
RUN chown www-data /var/lib/nginx/body /var/lib/nginx/proxy /var/lib/nginx/fastcgi /var/lib/nginx/uwsgi /var/lib/nginx/scgi

EXPOSE 80

USER www-data
# Set entry point
ENTRYPOINT []
#CMD ["/bin/bash"]
#CMD ["/etc/init.d/nginx", "start"]
CMD ["nginx", "-g", "daemon off;"]
HEALTHCHECK --interval=10s --timeout=30s --start-period=30s --retries=6 CMD curl http://localhost:80
