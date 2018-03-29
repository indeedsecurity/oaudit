import json
from datetime import datetime, timedelta
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from time import sleep
import smtplib
import dateutil.parser
import os
import argparse

import elasticsearch
from jinja2 import Template

from httplib2 import Http
from oauth2client import tools
from oauth2client.service_account import ServiceAccountCredentials
from apiclient import discovery

parser = argparse.ArgumentParser(
    description='Oaudit-metadata scrapes Google API for Oauth events and inserts into Elasticsearch.')
parser.add_argument('--secret-file', required=False, type=str, dest='CLIENT_SECRET_FILE',
                    default='client_secret.json')
parser.add_argument('--service-account-email', required=True, type=str, dest='SERVICE_ACCOUNT_EMAIL')
parser.add_argument('--sender-email', required=True, type=str, dest='SENDER_EMAIL')
parser.add_argument('--elasticsearch-hosts', required=False, type=str, dest='ELASTICSEARCH_HOSTS',
                    default='localhost:9200')
parser.add_argument('--elasticsearch-data-index', required=False, type=str, dest='DATA_INDEX_NAME', default='sec-oauth')
parser.add_argument('--elasticsearch-state-index', required=False, type=str, dest='STATE_INDEX_NAME',
                    default='oauditnotify-state')
parser.add_argument('--smtp-server', required=True, type=str, dest='SMTP_SERVER')
parser.add_argument('--test-email', required=True, type=str, dest='TEST_EMAIL')
args = parser.parse_args()
ES_HOSTS = args.ELASTICSEARCH_HOSTS.split(",")

# If modifying these scopes, delete your previously saved credentials
# at ~/.credentials/admin-directory_v1-python-quickstart.json
if not os.path.isfile(args.CLIENT_SECRET_FILE):
    print("Google API client secret file not found: {}".format(args.CLIENT_SECRET_FILE))
APPLICATION_NAME = 'OAuth Notifier'


class AuthEvent:
    def __init__(self, appName, clientId, uniqueId, actor, scopes, eventTime):
        self.appName = appName
        self.clientId = clientId
        self.uniqueId = uniqueId
        self.actor = actor
        self.scopes = scopes
        self.eventTime = eventTime


class App:
    def __init__(self, api, es, state_index_name, data_index_name, whitelist, blacklist,
                 google_scopes, template, blacklistTemplate):
        self.api = api
        self.es = es
        self.state_index_name = state_index_name
        self.data_index_name = data_index_name
        self.whitelist = whitelist
        self.blacklist = blacklist
        self.google_scopes = google_scopes
        self.template = template
        self.blacklistTemplate = blacklistTemplate


def get_credentials():
    scopes = [
        'https://www.googleapis.com/auth/admin.reports.audit.readonly https://www.googleapis.com/auth/admin.directory.user.security']
    credentials = ServiceAccountCredentials.from_json_keyfile_name(args.CLIENT_SECRET_FILE, scopes=scopes)
    delegated_credentials = credentials.create_delegated(args.SERVICE_ACCOUNT_EMAIL)
    return delegated_credentials


def inElasticsearch(es, state_index_name, uniqueId, doc_type="authorize"):
    date = datetime.today()
    today = date.strftime('%Y.%m.%d')
    yesterday = (date - timedelta(days=1)).strftime('%Y.%m.%d')
    day_before_yesterday = (date - timedelta(days=2)).strftime('%Y.%m.%d')

    exists_today = es.exists(index=state_index_name + '-' + today,
                             doc_type=doc_type,
                             id=uniqueId)

    exists_yesterday = es.exists(index=state_index_name + '-' + yesterday,
                                 doc_type=doc_type,
                                 id=uniqueId)

    exists_day_before_yesterday = es.exists(index=state_index_name + '-' + day_before_yesterday,
                                            doc_type=doc_type,
                                            id=uniqueId)

    return exists_today or exists_yesterday or exists_day_before_yesterday


def insertElasticsearch(es, state_index_name, doc, doc_type="authorize"):
    res = es.create(index=todaysIndexName(state_index_name),
                    doc_type=doc_type,
                    id=doc['unique_id'],
                    body=json.dumps({
                        'event_timestamp': doc['event_timestamp']
                    }))
    return res


def todaysIndexName(baseName):
    return "{}-{}".format(baseName, datetime.today().strftime('%Y.%m.%d'))


def checkWhitelist(whitelist, clientId, appName):
    if not any((clientId == x or appName == x) for x in whitelist):
        return False
    else:
        return True


def checkBlacklist(blacklist, clientId):
    if not any(clientId == x for x in blacklist):
        return False
    else:
        return True


def deleteToken(api, actor, clientId):
    try:
        results = api.tokens().delete(userKey=actor, clientId=clientId).execute()
        print('Deleted token {0} for {1}'.format(clientId, actor))
    except Exception as e:
        print('Token cannot be deleted {0}'.format(e))
        pass


def sendMail(app, doc, template):
    scopes = []
    for scope in doc['scopes']:
        if scope in app.google_scopes:
            scopes.append({
                "Scope": app.google_scopes[scope]["Scope"],
                "Description": app.google_scopes[scope]["Description"],
                "Weight": app.google_scopes[scope]["Weight"]
            })
    doc['scopes'] = scopes
    prettyDate = dateutil.parser.parse(doc['event_timestamp'])
    timestamp = prettyDate.strftime("%a %b %d, %H:%M")

    msg = MIMEMultipart()
    msg['From'] = formataddr((str(Header(u'Google Apps Notification', 'utf-8')), args.SENDER_EMAIL))
    msg['To'] = doc['actor']
    msg['Subject'] = "[Notification] You have authorized {0} access".format(doc['app_name'])

    body = Template(template).render(auth=doc, timestamp=timestamp)

    msgPart = MIMEText(body, 'html')
    msg.attach(msgPart)
    server = smtplib.SMTP(args.SMTP_SERVER, 25)
    server.sendmail(args.SENDER_EMAIL, args.TEST_EMAIL, msg.as_string())
    server.sendmail(args.SENDER_EMAIL, doc['actor'], msg.as_string())
    server.quit()
    print("Sent email to {0} at {1} ({2}".format(doc['actor'], doc['event_timestamp'], timestamp))


def getAuthsFromES(app):
    blacklisted = []
    for id in app.blacklist:
        blacklisted.append(
            {
                "match": {
                    "client_id": {
                        "query": id
                    }
                }
            })

    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "event_timestamp": {
                                "gte": "now-48h",
                                "format": "epoch_millis"
                            }
                        }
                    }
                ],
                "must_not": blacklisted,
            }
        }
    }

    docs = []
    res = app.es.search(index=app.data_index_name + '-*',
                        doc_type="authorize",
                        body=query,
                        size=1000,
                        scroll='2m')
    docs += [hit['_source'] for hit in res['hits']['hits']]
    sid = res['_scroll_id']
    scroll_size = res['hits']['total']
    while scroll_size > 0:
        res = app.es.scroll(scroll_id=sid, scroll='1h')
        # Update the scroll ID
        sid = res['_scroll_id']
        # Get the number of results that we returned in the last scroll
        scroll_size = len(res['hits']['hits'])
        docs += [hit['_source'] for hit in res['hits']['hits']]
    print("Authorizations received: {}".format(len(docs)))
    return docs


def notify(app):
    authTotal = 0
    restrictedAuthTotal = 0
    exists = 0

    docs = getAuthsFromES(app)
    print("Got {} docs from ES".format(len(docs)))

    for doc in docs:
        if not inElasticsearch(es=app.es, state_index_name=app.state_index_name, uniqueId=doc['unique_id']):
            # check whether app is in whitelist/blacklist
            if not (checkWhitelist(app.whitelist, doc['client_id'], doc['app_name']) or
                        checkBlacklist(app.blacklist, doc['client_id'])):
                print('Not in whitelist or blacklist: {0} {1}'.format(doc['actor'], doc['app_name']))
                restrictedAuthTotal += 1
                sendMail(app=app, doc=doc, template=app.template)
            elif checkWhitelist(app.whitelist, doc['client_id'], doc['app_name']):
                pass
            elif checkBlacklist(app.blacklist, doc['client_id']):
                print('In blacklist: {0} {1}'.format(doc['actor'], doc['app_name']))
                deleteToken(app.api, doc['actor'], doc['client_id'])
                sendMail(app=app, doc=doc, template=app.blacklistTemplate)
            authTotal += 1
            insertElasticsearch(es=app.es, state_index_name=app.state_index_name, doc=doc)
        else:
            exists += 1
    print("{} new authorizations out of {} authorizations received from ES".format(len(docs) - exists, len(docs)))


def main():
    credentials = get_credentials()
    http = credentials.authorize(Http())
    print("Found credentials")
    api = discovery.build('admin', 'directory_v1', http=http)
    print("Constructed API resource")

    es = elasticsearch.Elasticsearch(hosts=ES_HOSTS)
    print(es.info())

    whitelist = []
    with open('appwhitelist', 'r') as f:
        for line in f:
            line = line.split('#', 1)[0]
            line = line.rstrip()
            whitelist.append(line)

    blacklist = []
    with open('appblacklist', 'r') as f:
        for line in f:
            line = line.split('#', 1)[0]
            line = line.rstrip()
            blacklist.append(line)

    with open('scopes.json', 'r') as s:
        google_scopes = {}
        scopes = json.loads(s.read())
        for k, v in scopes.items():
            google_scopes[v['Description']] = {
                "Weight": v['Weight'],
                "Description": v['Description'],
                "Scope": k
            }

    with open('template.htm.j2', 'r') as t:
        template = t.read()

    with open('blacklisttemplate.htm.j2', 'r') as t2:
        blacklistTemplate = t2.read()

    app = App(api=api,
              es=es,
              data_index_name=args.DATA_INDEX_NAME,
              state_index_name=args.STATE_INDEX_NAME,
              whitelist=whitelist,
              blacklist=blacklist,
              google_scopes=google_scopes,
              template=template,
              blacklistTemplate=blacklistTemplate)

    next_run = datetime.now()
    while True:
        sleep(1)
        now = datetime.now()
        if now > next_run:
            next_run = datetime.now() + timedelta(minutes=5)
            notify(app)


if __name__ == '__main__':
    main()
