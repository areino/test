#!/usr/bin/env python3


import datetime
import os.path
import os
from falconpy import(IOC)
import redis


# Crowdstrike API creds
falcon_client_id =      ""
falcon_client_secret =  ""
falcon_base_url =       "https://api.eu-1.crowdstrike.com"

# Redis config
redis_host =            "192.168.68.108"
redis_port =            6379
redis_db =              0


limit = 2000
filename_pointer = "after"


# Define logging function
def log(msg):
    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '  ' + str(msg))


def main():

    log("Starting IOC import script")
    
    
    if os.path.exists(filename_pointer):
        with open(filename_pointer, "r") as f:
            after = f.readline()
            log("-- Found previous cursor " + after)
        f.close()
    else:
        after = ""
    
    
    log("Retrieving hashes from Falcon API")
    
    falcon = IOC(client_id=falcon_client_id, client_secret=falcon_client_secret)
    response = falcon.indicator_combined(filter="type:'sha256'+expired:false+deleted:false", limit=limit, after="")

    total = response['body']['meta']['pagination']['total']
    log("-- Query returned: " + str(total) + " hashes")

    log("Opening hash database at " + redis_host + ":" + str(redis_port))
    r = redis.Redis(host=redis_host, port=redis_port, db=redis_db)

    for ioc in response['body']['resources']:
        ioc_hash = ioc['value']
        ioc_severity = ioc['severity']
        if 'description' in ioc:
            ioc_description = ioc['description']
        else:
            ioc_description = ""
        
        # print("     " + ioc_hash + " " + ioc_severity + " " + ioc_description)
        r.set(ioc_hash, ioc_severity)


    with open(filename_pointer, "w") as f:
        new_after = response['body']['meta']['pagination']['after']
        f.write(new_after)
        log("Saving cursor " + new_after)
    f.close()
    
    log("End")

    
if __name__ == "__main__":
    main()    