FROM php:7.4-fpm-alpine
RUN apk add gmp-dev
RUN docker-php-ext-install gmp bcmath
COPY . /app
WORKDIR /app/src
EXPOSE 8080
CMD ["php","-S","0.0.0.0:8080"]
