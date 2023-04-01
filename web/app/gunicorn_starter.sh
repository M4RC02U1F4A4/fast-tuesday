#!/bin/sh
gunicorn -w 1 --threads 100 -b 0.0.0.0:5555 main:app 