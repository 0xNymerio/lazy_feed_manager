#!/bin/bash

echo "=== [Running the status.sh] ==="

echo "Running feed collector"
echo "$(date): Running the feed collector" >> /var/www/html/python.txt
python3 /lazy_feed_manager/lazy_feed_manager.py

echo "Running Apache"
/usr/sbin/apachectl -D FOREGROUND &

echo "Feed Colletor Looping"
while sleep 2700; do
    echo "$(date): Running the feed collector" >> /var/www/html/python.txt
    python3 /lazy_feed_manager/lazy_feed_manager.py
done

