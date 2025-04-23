#!/usr/bin/env python3

import datetime
from falconpy import(IOC, IntelligenceFeeds)
from urllib.request import urlretrieve
import gzip
import json
import redis


falcon_client_id =      ""
falcon_client_secret =  ""
falcon_base_url =       "https://api.crowdstrike.com"


# Redis config
redis_host =            "127.0.0.1"
redis_port =            6379
redis_db =              0


limit = 2000


# Define logging function
def log(msg):
    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '  ' + str(msg))


def main():

    log("Starting IOC import script")

    log("Opening hash database at " + redis_host + ":" + str(redis_port))
    r = redis.Redis(host=redis_host, port=redis_port, db=redis_db)

   
    log("Retrieving global list of file hashes from Falcon API")
    
    falcon = IntelligenceFeeds(client_id=falcon_client_id, client_secret=falcon_client_secret)
    response = falcon.query_feeds(feed_name="File", feed_interval="daily")

    count_total = 0
        
    for item in response["body"]["resources"]:
        created_timestamp = item["created_timestamp"]
        feed_item_id = item["feed_item_id"]
        interval = item["interval"]
        
        log("-- Feed item ID " + feed_item_id + " [" + created_timestamp + "]")
        
        response2 = falcon.download_feed(feed_item_id=feed_item_id)
        url = response2["headers"]["Location"]
        log("-- Downloading file")
        temp_file = "temp" + feed_item_id + ".gz"
        urlretrieve(url, temp_file)
        
        log("-- Uncompressing file")

        with gzip.open(temp_file, "rt", encoding="utf-8") as file_in:
            count = 0
            for line in file_in:
                ioc = json.loads(line)
                if "MaliciousConfidence" in ioc:
                    ioc_severity = ioc["MaliciousConfidence"]
                else:
                    ioc_severity = "Unknown"

                ioc_hash = ioc["FileDetails"]["SHA256"]
                r.set(ioc_hash, ioc_severity)
                count = count + 1
        log("-- Imported " + str(count) + " hashes")
        
        count_total = count_total + count
        

    
    
    log("Retrieving local list of file hashes from Falcon API")
    
    falcon = IOC(client_id=falcon_client_id, client_secret=falcon_client_secret)
    response = falcon.indicator_combined(filter="type:'sha256'+expired:false+deleted:false", limit=limit, after="")

    total = response['body']['meta']['pagination']['total']
    log("-- Query returned: " + str(total) + " hashes")

    for ioc in response['body']['resources']:
        ioc_hash = ioc['value']
        ioc_severity = ioc['severity']
        if 'description' in ioc:
            ioc_description = ioc['description']
        else:
            ioc_description = ""
        
        # print("     " + ioc_hash + " " + ioc_severity + " " + ioc_description)
        r.set(ioc_hash, ioc_severity)


    log("End")

    
if __name__ == "__main__":
    main()    
