# Towards a Global Perspective on Web Tracking

This work is based on https://www.sciencedirect.com/science/article/pii/S0167404818314007

Note that this work used a very old version of OpenWPM (version - 0.7.0). Therefore, some of the source code changes may not be applicable in the latest version of OpenWPM, and a similar alternative should be adopted.

* ``database_scripts folder`` contain scripts to clean the OpenWPM database and recreate it with additional fields (e.g., source_country --- i.e., country from which the crawling is done).
* ``openwpm/source_code_changes`` contains tweaks to the scripts to failitate the crawling from different countries.
* ``openwpm/config`` includes OpenWPM manager and browser configuration
* ``openwpm/crawler`` has the crawler that is used to automate the browsing of the provided list of websites.
