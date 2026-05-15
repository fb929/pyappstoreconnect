#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import pyappstoreconnect
import yaml
from deepmerge import always_merger
import json

# init logger
logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)

# init appstore connect client
client = pyappstoreconnect.Client(
    userAgent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    logLevel='debug',
)

# load config file
configFile = './test.yml'
cfg = dict()
if os.path.isfile(configFile):
    with open(configFile, 'r') as ymlfile:
        try:
            cfg = always_merger.merge(cfg,yaml.load(ymlfile,Loader=yaml.Loader))
        except Exception as e:
            logger.warning(f"skipping load load config file='{configFile}', error='{str(e)}'")

def login():
    # get username and password
    username = cfg.get('username') or input("Please enter username: ")
    password = cfg.get('password') or input(f"Please enter password for username={username}: ")
    # login
    response = client.login(username=username, password=password)
    # check login:
    if response:
        logger.info(f"login success")
    else:
        logger.error(f"login failed")
        print(response)
        exit(1)


## tests functions

# get appAnalytics stat
def getAppAnalytics():
    logging.info("get appAnalytics")
    analyticsResponses = client.appAnalytics(appleId, startTime=dateFrom, endTime=dateTo, groupsByMap={"pageViewUnique":"source"})
    for analyticsResponse in analyticsResponses:
        if not analyticsResponses:
            logger.error(f"bad analyticsResponse={analyticsResponse}")
            exit(1)
        logger.info(f"analyticsResponse='{json.dumps(analyticsResponse,indent=4)}'")

# get benchmarks stat
def getBenchmarks():
    logging.info(f"get benchmarks")
    benchmarks = client.benchmarks(appleId, category='ProductivityApp')
    for benchmark in benchmarks:
        logger.info(f"category=ProductivityApp, benchmark='{json.dumps(benchmark,indent=4)}'")
    benchmarks = client.benchmarks(appleId, category='AllCategories')
    for benchmark in benchmarks:
        logger.info(f"categor='AllCategories', benchmark='{json.dumps(benchmark,indent=4)}'")

# get analytics (filter replacement)
def getAnalyticsByGroups():
    logger.info(f"get analytics by groups")
    analyticsResponses = client.metricsWithGroups(
        appleId,
        metrics = [
            'impressionsTotalUnique',
            'pageViewUnique',
            'totalDownloads',
        ],
        groups = [
            'source',
            'storefront',
            'appReferrer',
            'domainReferrer',
        ],
        startTime = dateFrom,
        endTime = dateTo,
        frequency = 'day',
    )
    for analyticsResponse in analyticsResponses:
        if not analyticsResponses:
            logger.error(f"bad analyticsResponse={analyticsResponse}")
            exit(1)
        logger.info(f"analyticsResponse='{json.dumps(analyticsResponse,indent=4)}'")

def getAcquisition():
    logger.info(f"get acquisition")
    analyticsResponses = client.acquisition(
        appleId,
        startTime = dateFrom,
        endTime = dateTo,
    )
    logger.info(f"getAcquisition: analyticsResponse='{json.dumps(analyticsResponses,indent=4)}")

## run tests:
if __name__ == "__main__":
    logger.info("starting script")
    login() # login to apple

    # get variables for tests
    appleId = cfg.get('appleId') or input("Please enter appleId: ")
    dateFrom = cfg.get('dateFrom') or input("Please enter dateFrom, example 2024-10-11T00:00:00Z: ")
    dateTo = cfg.get('dateTo') or input("Please enter dateTo, example 2024-10-18T00:00:00Z: ")

    getAppAnalytics()
    getBenchmarks()
    getAnalyticsByGroups()
    getAcquisition()
