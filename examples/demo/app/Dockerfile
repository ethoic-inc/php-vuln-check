# Demo only: a typical PHP service image, pinned one patch release behind the fix.
FROM composer:2 AS vendor
FROM php:8.3.35-fpm-alpine
COPY --from=vendor /usr/bin/composer /usr/bin/composer
