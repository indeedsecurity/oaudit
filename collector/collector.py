import json
import os
from datetime import datetime, timedelta
from time import sleep

import elasticsearch
from elasticsearch.helpers import bulk
import googleapiclient.errors
from apiclient import discovery
from httplib2 import Http
from oauth2client import tools
from oauth2client.service_account import ServiceAccountCredentials
import argparse

parser = argparse.ArgumentParser(
    description='Oaudit-metadata scrapes Google API for Oauth events and inserts into Elasticsearch.')
parser.add_argument('--secret-file', required=False, type=str, dest='CLIENT_SECRET_FILE',
                    default='client_secret.json')
parser.add_argument('--service-account-email', required=True, type=str, dest='SERVICE_ACCOUNT_EMAIL')
parser.add_argument('--elasticsearch-hosts', required=False, type=str, dest='ELASTICSEARCH_HOSTS',
                    default='localhost:9200')
parser.add_argument('--elasticsearch-index', required=False, type=str, dest='INDEX_NAME', default='sec-oauth')
parser.add_argument('--historic-window', required=False, type=int, dest='HISTORIC_WINDOW', default=600)
parser.add_argument('--run-every', required=False, type=int, dest='RUN_EVERY', default=5)
args = parser.parse_args()
ES_HOSTS = args.ELASTICSEARCH_HOSTS.split(",")


# Note, if you have creds
# at ~/.credentials/admin-directory_v1-python-quickstart.json
# then the library may pick those up rather than the one we specify here
if not os.path.isfile(args.CLIENT_SECRET_FILE):
    print("Google API client secret file not found: {}".format(args.CLIENT_SECRET_FILE))

APPLICATION_NAME = 'Directory API Python Quickstart'


class AuthEvent:
    def __init__(self, appName, clientId, uniqueId, actor, scopes, eventTime):
        self.appName = appName
        self.clientId = clientId
        self.uniqueId = uniqueId
        self.actor = actor
        self.scopes = scopes
        self.eventTime = eventTime


class App:
    def __init__(self, api, es, index_name,
                 google_scopes, lag_time, historic_window):
        self.api = api
        self.es = es
        self.index_name = index_name
        self.google_scopes = google_scopes
        self.lag_time = lag_time
        self.historic_window = historic_window

    def insertElasticsearch(self, bulkItems, doc_type="authorize"):
        docs = []
        for item in bulkItems:
            doc = {
                '_id': item.uniqueId,
                '_index': todaysIndexName(self.index_name),
                '_type': doc_type,
                '_op_type': 'index',
                'client_id': item.clientId,
                'event_timestamp': item.eventTime,
                'username': item.actor.split("@")[0],
                'detailed_scopes': item.scopes,
                'scopes': [scope['Description'] for scope in item.scopes],
                'unique_id': item.uniqueId,
                'actor': item.actor,
                'app_name': item.appName
            }
            docs.append(doc)

        res = elasticsearch.helpers.bulk(self.es, actions=docs)
        return res

    def get_events(self):
        start, end = time_bucket_range(lag_time=self.lag_time,
                                       historic_window=self.historic_window)

        print("Results from {0} to {1}".format(start, end))
        # Get activities list for tokens
        results = self.api.activities().list(userKey='all', applicationName='token', eventName='authorize',
                                             startTime=start.isoformat() + "Z", endTime=end.isoformat() + "Z",
                                             maxResults='500').execute()

        # process data as long as there are results to process
        while results is not None:
            # get user list and page token
            activities = results.get('items', [])
            nextPage = results.get('nextPageToken')

            bulkItems = []

            for activity in activities:
                appName = activity['events'][0]['parameters'][1]['value']
                clientId = activity['events'][0]['parameters'][0]['value']
                grantedScopes = activity['events'][0]['parameters'][2]['multiValue']
                actor = activity['actor']['email']
                uniqueId = activity['id']['uniqueQualifier']
                eventTime = activity['id']['time']

                scopes = []
                for scope in grantedScopes:
                    if scope in self.google_scopes:
                        scopes.append({
                            "Scope": scope,
                            "Description": self.google_scopes[scope]["Description"],
                            "Weight": self.google_scopes[scope]["Weight"]
                        })

                auth = AuthEvent(appName=appName,
                                 clientId=clientId,
                                 actor=actor,
                                 scopes=scopes,
                                 uniqueId=uniqueId,
                                 eventTime=eventTime)

                bulkItems.append(auth)

            self.insertElasticsearch(bulkItems=bulkItems)
            print("\nBulk inserted {} items into Elasticsearch".format(len(bulkItems)))

            # if there are no more results, end program
            if nextPage is None:
                break
            # otherwise get next set
            else:
                try:
                    results = self.api.activities().list(userKey='all', applicationName='token', eventName='authorize',
                                                         startTime=start.isoformat() + "Z",
                                                         endTime=end.isoformat() + "Z",
                                                         maxResults='500',
                                                         pageToken=nextPage).execute()
                except googleapiclient.errors.HttpError:
                    print("Error occurred on Google API. Sleeping for a bit before trying again.")
                    sleep(10)


def time_bucket_range(lag_time, historic_window):
    now = datetime.utcnow()
    end = now - timedelta(minutes=lag_time)
    start = end - timedelta(minutes=historic_window)

    return start, end


def get_credentials():
    scopes = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']
    credentials = ServiceAccountCredentials.from_json_keyfile_name(args.CLIENT_SECRET_FILE, scopes=scopes)
    delegated_credentials = credentials.create_delegated(args.SERVICE_ACCOUNT_EMAIL)
    return delegated_credentials


def todaysIndexName(baseName):
    return "{}-{}".format(baseName, datetime.today().strftime('%Y.%m.%d'))


def main():
    # Historically the reports API has lagged upwards of 36 hours
    # and has done backfilling. We grab events from a large period of
    # time because that's the only way we can effectively account
    # for these fluctuations with the current API
    LAG_TIME = 0  # minutes

    es = elasticsearch.Elasticsearch(hosts=ES_HOSTS)
    credentials = get_credentials()
    http = credentials.authorize(Http())
    api = discovery.build('admin', 'reports_v1', http=http)

    with open('scopes.json', 'r') as s:
        google_scopes = json.loads(s.read())

    app = App(api=api,
              es=es,
              index_name=args.INDEX_NAME,
              google_scopes=google_scopes,
              lag_time=LAG_TIME,
              historic_window=args.HISTORIC_WINDOW)

    next_run = datetime.now()
    while True:
        sleep(1)
        now = datetime.now()
        if now > next_run:
            next_run = datetime.now() + timedelta(minutes=args.RUN_EVERY)
            app.get_events()


if __name__ == '__main__':
    main()
