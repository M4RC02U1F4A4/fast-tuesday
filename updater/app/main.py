import requests
from datetime import datetime
import redis
from cvss import CVSS3
from apscheduler.schedulers.blocking import BlockingScheduler
import os

redis_host = str(os.getenv('REDIS_HOST'))

def extract_max_score(CVSSScoreSets):
    max_score = 0
    temp = []
    for cvss in CVSSScoreSets:
        if cvss['BaseScore'] > max_score:
            temp = [cvss]
    return temp

def extract_cvss_full(vector):
    cvss3 = CVSS3(vector)
    return {
        "Attack Vector": cvss3.get_value_description("AV"),
        "Attack Complexity": cvss3.get_value_description("AC"),
        "Privileges Required": cvss3.get_value_description("PR"),
        "User Interaction": cvss3.get_value_description("UI"),
        "Scope": cvss3.get_value_description("S"),
        "Confidentiality": cvss3.get_value_description("C"),
        "Integrity": cvss3.get_value_description("I"),
        "Availability": cvss3.get_value_description("A"),
        "Exploit Code Maturity": cvss3.get_value_description("E"),
        "Remediation Level": cvss3.get_value_description("RL"),
        "Report Confidence": cvss3.get_value_description("RC")
    }

def update():
    r_vuln = redis.Redis(host = redis_host, port = 6379, db = 0)
    r_stats = redis.Redis(host = redis_host, port = 6379, db = 3, decode_responses = True)

    month = f"{datetime.now().year}-{datetime.now().strftime('%b')}"
    print(f"Update {datetime.now()}")
    r = requests.get(f"https://api.msrc.microsoft.com/cvrf/{month}", headers={"Accept":"application/json"})
    if r.status_code == 404:
        r_stats.set("NA", 1, 21600)
    else:
        r_stats.set("NA", 0, 21600)
        jsonResponseMicrosoft = r.json()

        total_number = len(jsonResponseMicrosoft['Vulnerability'])
        critical_number = 0
        high_number = 0
        medium_number = 0
        low_number = 0
        to_analyze_number = 0

        for i in jsonResponseMicrosoft['Vulnerability']:
            if len(i['CVSSScoreSets']) > 0 and len(i['Title']) > 0:
                if float(i['CVSSScoreSets'][0]['BaseScore']) >= 0.1 and float(i['CVSSScoreSets'][0]['BaseScore']) <= 3.9:
                    low_number += 1
                elif float(i['CVSSScoreSets'][0]['BaseScore']) >= 4.0 and float(i['CVSSScoreSets'][0]['BaseScore']) <=6.9:
                    medium_number += 1
                elif float(i['CVSSScoreSets'][0]['BaseScore']) >= 7.0 and float(i['CVSSScoreSets'][0]['BaseScore']) <= 8.9:
                    high_number += 1
                elif float(i['CVSSScoreSets'][0]['BaseScore']) >= 9.0 and float(i['CVSSScoreSets'][0]['BaseScore']) <= 10.0:
                    critical_number += 1

                if float(i['CVSSScoreSets'][0]['BaseScore']) >= 7.0:
                    i['RevisionHistory'] = sorted(i['RevisionHistory'], key=lambda d: d['Date']) 
                    i['CVSSScoreSets'] = extract_max_score(i['CVSSScoreSets'])
                    i['CVSSScoreSets'][0]['BaseScoreFULL'] = extract_cvss_full(i['CVSSScoreSets'][0]['Vector'])
                    r_vuln.json().set(f"{month}:{i['CVE']}", "$", i)
                    r_vuln.expire(f"{month}:{i['CVE']}", 21600)
                    to_analyze_number += 1

        r_stats.set("total_number", total_number, 21600)
        r_stats.set("critical_number", critical_number, 21600)
        r_stats.set("high_number", high_number, 21600)
        r_stats.set("medium_number", medium_number, 21600)
        r_stats.set("low_number", low_number, 21600)
        r_stats.set("to_analyze_number", to_analyze_number, 21600)
        r_stats.expire("total_number", 21600)
        r_stats.expire("critical_number", 21600)
        r_stats.expire("high_number", 21600)
        r_stats.expire("medium_number", 21600)
        r_stats.expire("low_number", 21600)
        r_stats.expire("to_analyze_number", 21600)


        r_item = redis.Redis(host = redis_host, port = 6379, db = 1)

        for item in jsonResponseMicrosoft['ProductTree']['FullProductName']:
            r_item.set(f"{item['ProductID']}", item['Value'])
            r_item.expire(f"{item['ProductID']}", 21600)

update()