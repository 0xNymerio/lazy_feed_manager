FROM ubuntu

ENV TZ=America/Sao_Paulo
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN mkdir /lazy_feed_manager
COPY requirements.txt /lazy_feed_manager

# Dependencias Python 
RUN apt update && apt install -y python3 python3-pip apache2 && apt autoremove 
RUN python3 -m pip install -r /lazy_feed_manager/requirements.txt

COPY index.html nymsechouse_logo.png /var/www/html/

COPY status.sh /
RUN chmod +x /status.sh

WORKDIR /lazy_feed_manager

EXPOSE 80

ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_LOG_DIR /var/log/apache2

COPY . .

ENTRYPOINT [ "/status.sh" ]

