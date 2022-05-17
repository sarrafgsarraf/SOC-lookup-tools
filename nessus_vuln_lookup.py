#!/usr/bin/env python
'''
This script can be used to query a Database (connected with nessus) to find certain vulnerability based on IP address. 
- GS
'''
import MySQLdb
import os
import datetime
import sys
import types

cursor=""
dateStr=""
db=""

def dbConnect():
  '''
  This function connects the script to the database. 
  '''
  global cursor, db
  config={
    "host":"<YOUR HOST>",
    "user":"<YOUR USERNAME>",
    "passwd":"<YOUR PASSWORD>",
    "db":"<DB NAME>"
  }
  try:
    db = MySQLdb.connect(**config)
  except MySQLdb.Error, e:
    print "Got some error in executing. The error is:"+str(e)
  cursor=db.cursor()
  
def executeAllVulQuery(ip):
  '''
  This function takes the IP as input and then checks the nessus status table for IP for its vulnerablities
  '''
  global cursor
  sql_query="SELECT hostos,risk_factor,cve,synopsis,description,solution FROM nessus_import  WHERE ( hostip='"+ip+"' AND ( risk_factor='Critical' OR risk_factor='High' OR risk_factor='Medium' OR risk_factor='Low' ) ) ORDER BY risk_factor ASC"
  try:
    cursor.execute(sql_query)
  except MySQLdb.Error, e:
    print "Got error while executing the query. The error is:"+str(e)
  results=cursor.fetchall()
  prev=""
  if len(results) != 0:
    for row in results:
      if row[2] == prev:
        continue
      else:
        prev=row[2]
        print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        print "IP:{}\nHostOS:{}\nPriority:{}\nCVE:{}\nSynopsis:{}\nDescription:{}\nSolution:{}".format(ip,row[0],row[1],row[2],row[3],row[4],row[5])  
        print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
  else:
    print "This IP doesn't have any vulnerabilities."

def executeHeartBleedQuery(ip):
  '''
  This function takes the IP as input and then checks the nessus status table for IP with CVE which are vulnerable to Heartbleed.
  '''
  global cursor, dateStr
  is_found = False
  sql_query="SELECT hostos,risk_factor,cve,synopsis,description,solution FROM nessus_import  WHERE ( hostip='"+ip+"' AND ( risk_factor='Critical' OR risk_factor='High' OR risk_factor='Medium' OR risk_factor='Low' ) ) ORDER BY risk_factor ASC"
  try:
    cursor.execute(sql_query)
  except MySQLdb.Error, e:
    print "Got error while executing the query. The error is:"+str(e)
  results=cursor.fetchall()
  for row in results:
    if "heartbeat" in row[4]:
      if not is_found:
        is_found=True
      print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
      print "IP:{}\nHostOS:{}\nPriority:{}\nCVE:{}\nSynopsis:{}\nDescription:{}\nSolution:{}".format(ip,row[0],row[1],row[2],row[3],row[4],row[5])  
      print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

  if not is_found:
    print "The given IP is not vulnerable to heartbleed attack."

def executeHeartBleedQueryBulk(ip_list):
  '''
  This function takes the IP as input and then checks the nessus status table for IP with CVE which are vulnerable to Heartbleed.
  '''
  global cursor, dateStr
  is_found = False
  for ip in ip_list:
    print "####################     "+ip+"     #####################"
    sql_query="SELECT hostos,risk_factor,cve,synopsis,description,solution FROM nessus_import  WHERE ( hostip='"+ip+"' AND ( risk_factor='Critical' OR risk_factor='High' OR risk_factor='Medium' OR risk_factor='Low' ) ) ORDER BY risk_factor ASC"
    try:
      cursor.execute(sql_query)
    except MySQLdb.Error, e:
      print "Got error while executing the query. The error is:"+str(e)
    results=cursor.fetchall()
    for row in results:
      if "heartbeat" in row[4]:
        if not is_found:
          is_found=True
        print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        print "IP:{}\nHostOS:{}\nPriority:{}\nCVE:{}\nSynopsis:{}\nDescription:{}\nSolution:{}".format(ip,row[0],row[1],row[2],row[3],row[4],row[5])  
        print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
 
    if not is_found:
      print "The given IP is not vulnerable to heartbleed attack."

def executeIREQuery(ip):
  '''
  This function outputs the format for IRE
  '''
  global cursor, dateStr
  is_found = False
  dateStr=(datetime.date.today()-datetime.timedelta(days=8)).strftime("%Y-%m-%d")
  texttocopy=""
  texttodisp=""
  sql_query="SELECT Record,Priority,CVE,Synopsis,RiskFactor,LastSeen,Description,PluginOutput,FirstSeen FROM nessus_status WHERE ( IPnumber='"+ip+"'  AND ( Priority='High' OR Priority='Critical' ) AND LastSeen > '"+dateStr+"' ) "
  try:
    cursor.execute(sql_query)
    results=cursor.fetchall()
    texttocopy="Text to copy:\n||IP address||Record No.||Priority||Title||Description||CVE||First Seen||Last Seen||\n"
    for row in results:
      if "BaseScore" in row[4]:
        basescr=(row[4].split(":"))[1][1:]
        sql_import_query="SELECT plugin_name FROM nessus_import WHERE ( hostip='"+ip+"' AND cvss_base_score='"+basescr+"' )"
        cursor.execute(sql_import_query)
        final_results=cursor.fetchone()
      else:
        sql_import_query="SELECT plugin_name FROM nessus_import WHERE ( hostip='"+ip+"' AND synopsis='"+row[3]+"' ) "
        cursor.execute(sql_import_query)
        final_results=cursor.fetchone()

      texttodisp+="~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
      texttodisp+="IP:{}\nRecord:{}\nPriority:{}\nCVE:{}\nFirst Seen:{}\nLast Seen:{}\nPlugin Name:{}\nPlugin Output:{}\nDescription:{}\n".format(str(ip),str(row[0]),str(row[1]),str(row[2]),row[8].strftime("%Y-%m-%d"),row[5].strftime("%Y-%m-%d"),str(final_results[0]),str(row[7]),str(row[6]))  
      texttodisp+="~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
      texttocopy+= "|"+ip+"|"+str(row[0])+"|"+row[1]+"|"+final_results[0]+"|"+row[6]+"|"+row[2]+"|"+row[8].strftime("%Y-%m-%d")+"|"+row[5].strftime("%Y-%m-%d")+"|\n" 
      
  except MySQLdb.Error, e:
    print "Got error while executing the query. The error is:"+str(e)

  print texttodisp+"\n"+texttocopy

def processIP(ip_list):
  newlist=[]
  if type(ip_list) is types.ListType:
    for ip in ip_list:
      if (len(ip) < 8 and len(ip) > 3):
        newlist.append("<ORGANIZATION IP PREFIX>"+ip)
      else:
        newlist.append(ip)
    return newlist
  elif type(ip_list) is types.StringType:
    if (len(ip_list) < 8 and len(ip_list) > 3):
      ip_list="<ORGANIZATION IP PREFIX>"+ip_list
    return ip_list

def usage():
  print "##############################################################################################################################################################"
  print "#     This script is used to find vulnerabilties for a particular IP from"
  print "#                 the latest scan performed by the nessus"
  print "# Usage - "+sys.argv[0]+" [mode] [IP1] [IP2] [IP3] [IP4]"
  print "# Arguments"
  print "# 1) IP address - If its within syracuse network, you can enter last two"
  print "#                 octets. For eg, <ORGANIZATION IP> can run as"
  print "#         "+sys.argv[0]+" [mode] 64.56 or "+sys.argv[0]+" [mode] <ORGANIZATION IP>
  print "#"
  print "# 2) Mode - a   - to get all vulnerabilites for all IP's"
  print "#           b   - to find if the IP is vulnerable to heartbleed"
  print "#           ire - to get the IRE format for a particular IP"
  print "#           bb  - to find list of IP's vulnerable to heartbleed"
  print "#"
  print "#   Eg - "+sys.argv[0]+" ire <ORGANIZATION IP>"
  print "#        "+sys.argv[0]+" ire <ORGANIZATION IP> 2017-04-01"
  print "#        "+sys.argv[0]+" b 64.126"
  print "#        "+sys.argv[0]+" b 64.126 <ORGANIZATION IP> 94.32"
  print "##############################################################################################################################################################"

def cleanup():
  global db
  db.close()

def main():
  #Initialization of variables
  global dateStr
  if (len(sys.argv) < 3):
    print "You need to supply the IP and mode as an argument. Printing Usage Instructions."
    usage()
    exit()
  #Processing the Mode and setting it
  if len(sys.argv[1]) < 5:
    mode=sys.argv[1]
  else:
    print "Length of mode string too long."
    usage()
  #Processing the IP and setting it
  if (len(sys.argv) > 3):
    ip_list=sys.argv
    ip_list.reverse()
    ip_list.pop()
    ip_list.pop()
    ip_list.reverse()
  else:
    ip_list=sys.argv[2]

  ip=processIP(ip_list)
  print ip
  #Setting the date
  dateStr=(datetime.date.today()-datetime.timedelta(days=7)).strftime("%Y-%m-%d")
  #Connecting the database
  dbConnect()  
  #Setting different modes to call different functions as per needed
  mode_dict={
    "b": executeHeartBleedQuery,	#Function calls
    "a": executeAllVulQuery,
    "bb": executeHeartBleedQueryBulk,
    "ire": executeIREQuery,
    "help": usage
  }
  if mode_dict.has_key(mode):
    mode_dict.get(mode)(ip)
  else:
    print "Invalid Mode Entered. Type "+sys.argv[0]+" help to get usage." 
  
  #Cleaning up the variables
  cleanup()

if __name__=="__main__":
  main()
