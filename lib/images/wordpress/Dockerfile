FROM wordpress:5.5.1-php7.3-fpm-alpine

COPY uploads.ini /usr/local/etc/php/conf.d/uploads.ini

RUN set -ex; \
	\
	apk add --no-cache --update \
		bash \
		bzip2 \
		less \
		memcached \
		mysql-client \
		unzip \
		zip \
		oniguruma \
	; \
	mkdir -p /usr/src/php/ext; \
	apk add --no-cache --virtual .build-deps \
		$PHPIZE_DEPS \
		curl-dev \
		freetype-dev \
		icu-dev \
		jpeg-dev \
		memcached-dev \
		libmemcached-dev \
		libpng-dev \
		libpq \
		libxml2-dev \
		libzip-dev \
		oniguruma-dev \
	; \
	docker-php-ext-configure gd; \
	docker-php-ext-install -j "$(nproc)" \
		exif \
		gd \
		intl \
		mbstring \
		mysqli \
		opcache \
		pcntl \
		pdo_mysql \
		soap \
		zip \
	; \
	pecl install \
		apcu \
		memcached \
	; \
	docker-php-ext-enable \
		apcu \
		memcached \
	 \
	&& chown www-data:www-data /var/www /var/www/html; \
	\
	runDeps="$( \
		scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions \
			| tr ',' '\n' \
			| sort -u \
			| awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' \
	)"; \
	apk add --virtual .wordpress-phpexts-rundeps $runDeps; \
	apk del .build-deps

RUN wget https://elasticache-downloads.s3.amazonaws.com/ClusterClient/PHP-7.3/latest-64bit &&\
    tar -zxvf latest-64bit &&\
    cp amazon-elasticache-cluster-client.so /usr/local/lib/php/extensions/ &&\
    echo 'extension=amazon-elasticache-cluster-client.so' >> $PHP_INI_DIR/php.ini

WORKDIR /var/www/html

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["php-fpm"]