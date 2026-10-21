FROM php:8.5-apache
# The remote chain needs Apache prefork + mod_php (libphp.so), PHP 8.x NTS.
RUN a2dismod mpm_event 2>/dev/null || true; \
    a2enmod mpm_prefork 2>/dev/null || true
COPY remote_app.php /var/www/html/remote_app.php
COPY php.ini /usr/local/etc/php/conf.d/php2shell-lab.ini
