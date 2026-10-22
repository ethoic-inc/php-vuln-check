# Demo only: a typical PHP service image, pinned one patch release behind the fix.
ARG PHP_VERSION=8.3.35
FROM composer:2 AS vendor
FROM php:${PHP_VERSION}-fpm-alpine
COPY --from=vendor /usr/bin/composer /usr/bin/composer
