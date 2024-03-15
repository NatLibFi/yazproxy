#!/bin/sh
if [ $# -eq 0 ];then
  exec bin/yazproxy -a - -c $CONF @:$PORT -o
else
  exec bin/yazproxy $@
fi
