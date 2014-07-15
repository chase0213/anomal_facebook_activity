#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re


def trim_access_log():
    for line in open('security.htm'):
        array = re.split("アカウントアクティビティ|Recognized Machines",line)
        activities = array[1].split('<li>')
        for activity in activities:
            print re.sub("<[^>]*>","\t",activity).rstrip()

if __name__ == '__main__':
    trim_access_log()

