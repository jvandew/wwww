FROM wwww-base:test

COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisor/supervisord.conf

RUN rm -r /usr/share/nginx/html && ln -s /usr/src/wwww/www /usr/share/nginx/html

CMD supervisord -c /etc/supervisor/supervisord.conf
