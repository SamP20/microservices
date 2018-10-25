FROM nginx:latest

COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/default.conf /etc/nginx/conf.d/default.conf
USER 999:999

EXPOSE 8080
EXPOSE 8443