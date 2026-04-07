FROM php:8.2-apache

# 1. Installiamo mysqli (necessario per il tuo codice PHP)
RUN docker-php-ext-install mysqli

# 2. Installiamo l'utility 'ping' (necessaria per la Command Injection)
RUN apt-get update && apt-get install -y iputils-ping

# 3. Abilitiamo i permessi per la cartella uploads
# Creiamo la cartella e diamo i permessi all'utente del web server
RUN mkdir -p /var/www/html/uploads && \
    chown -R www-data:www-data /var/www/html/uploads && \
    chmod -R 777 /var/www/html/uploads