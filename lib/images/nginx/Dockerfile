FROM nginx:latest

RUN rm -f /etc/nginx/conf.d/default.conf
RUN rm -f /etc/nginx/conf.d/example_ssl.conf

COPY wordpress.conf.template /etc/nginx/templates/wordpress.conf.template
COPY nginx.conf /etc/nginx/nginx.conf

CMD ["nginx"]