#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, json
import jubatus
from jubatus.common import Datum

NAME = 'facebook_security'
FILE = 'data/activity.tsv'
HOST = '127.0.0.1'
PORT = 9199


def detect_anomaly_access(client):
    # prepare data
    with open(FILE) as f:
        for line in f:
            array = line.split('\t')
            datum = Datum({
                "activity":   array[0],
                "time":       array[1],
                "ip_address": array[2],
                "brawser":    array[3],
                "cookie":     array[4].replace("\n","")
            })
            ret = client.add(datum)


def main():
    client = jubatus.Anomaly(HOST,PORT,NAME)
    detect_anomaly_access(client)   

    anomal_datum = Datum({
        "activity": "DELETE",
        "time":     "2014年7月15日 17:59 UTC+12",
        "ip_address": "127.0.0.1",
        "brawser": "IE6",
        "cookie": "???"
    })
    anomality = client.calc_score(anomal_datum)
    print "anomality(anomal datum):", anomality

    
if __name__ == '__main__':
    main()

