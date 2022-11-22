#!/bin/sh

/bin/rm ~/Desktop/crawl-data.sqlite
/usr/bin/sqlite3 ~/Desktop/crawl-data.sqlite < ~/install/OpenWPM/automation/schema.sql
