#!/bin/sh
# gunicorn -w 1 --threads 100 -b 0.0.0.0:5555 --access-logfile=- main:app 
gunicorn --worker-class eventlet -w 1 -b 0.0.0.0:5555 --access-logfile=- main:app