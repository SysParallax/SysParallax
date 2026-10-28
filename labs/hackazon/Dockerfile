FROM php:5.6-apache

ENV APACHE_DOCUMENT_ROOT=/var/www/html/web

RUN docker-php-ext-install bcmath pdo pdo_mysql \
    && a2enmod rewrite headers \
    && echo 'date.timezone=UTC' > /usr/local/etc/php/conf.d/hackazon.ini \
    && echo 'ServerName localhost' > /etc/apache2/conf-available/servername.conf \
    && a2enconf servername \
    && sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
    && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf \
    && { \
        echo '<Directory /var/www/html/web>'; \
        echo '    Options Indexes FollowSymLinks MultiViews'; \
        echo '    AllowOverride All'; \
        echo '    Require all granted'; \
        echo '</Directory>'; \
    } > /etc/apache2/conf-available/hackazon.conf \
    && a2enconf hackazon
