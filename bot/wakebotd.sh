#!/bin/sh
# Supervisor for the Telegram Wake-on-LAN relay.
# Restarts the poller if it ever exits (a curl or JSON edge case should not end
# the service until the next reboot).
while true; do
    /usr/bin/lua /etc/persistent/wakebot.lua >> /tmp/wakebot.log 2>&1
    echo "$(date '+%Y-%m-%d %H:%M:%S') poller exited, restarting in 10s" >> /tmp/wakebot.log
    sleep 10
done
