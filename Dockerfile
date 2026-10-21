FROM php:8.4.26-apache

# mod_php is the default SAPI in this image, which is exactly what we want.
# Both CVEs were demonstrated against Apache + mod_php.

# Enable session support (needed for CVE-2026-109619 upload_progress path)
RUN docker-php-ext-install session

# Vulnerable configuration
COPY php-vuln.ini /usr/local/etc/php/conf.d/vuln-lab.ini

# Lab application
COPY app/ /var/www/html/

# Logging: send Apache error log to stderr so `docker logs` captures it
RUN ln -sf /dev/stderr /var/log/apache2/error.log

EXPOSE 80
