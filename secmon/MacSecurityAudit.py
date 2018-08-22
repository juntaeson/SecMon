import re
import subprocess
import json
from datetime import datetime
#from elasticsearch import Elasticsearch

#es = Elasticsearch(['http://192.168.0.13:9200'])


class audit:
    ################## GET BASIC INFO ######################
    def getHostName(self):
        return str(subprocess.check_output('hostname', shell=True))
    
    def getUserAcc(self):
        return str(subprocess.check_output('whoami', shell=True))
    
    def getIPnMAC(self):
        ret = str(subprocess.check_output("ifconfig en0", shell=True))
        rIP = re.compile(r"(inet )(((\d{1,3}[.]){3})\d{1,3})")
        rMAC = re.compile(r"(..[:]){5}..")
        return rIP.search(ret).group(2), rMAC.search(ret).group()
    
    ####################### END #############################
    
    ############### AUDIT START ##############################
    def getVers(self): #1.0
        ret = str(subprocess.check_output("sw_vers", shell=True))
        rProductName = re.compile(r"ProductName:(.+?)$")
        rProductVersion = re.compile(r"ProductVersion:(.+?)$")
        rBuildVersion = re.compile(r"BuildVersion:(.+?)$")
        return rProductVersion.search(ret).group(1)
     
    def getUpdateHistory(self): # 1-1  update history
        output = str(subprocess.check_output('softwareupdate --history', shell=True))
        output = output.split("\\n")
        pDate = re.compile(r"(\d{4})[.]\s?(\d{2}[.]\s?){2}\s?\d+:\d+:\d+")
        pName = re.compile(r".*\d{4}-\d{3}")
        updates = []
        for line in output:
            name = pName.search(line)
            if name != None:
                update = {
                     "name" : name.group(),
                     "date" : pDate.search(line).group()
                }
                updates.append(update)
        return json.dumps(updates)
    
    def getAutoUpdate(self): #1-2
        output = str(subprocess.check_output('defaults read /library/preferences/com.apple.commerce', shell=True))
        pAutoUpdate = re.compile(r'(?<=AutoUpdate\s=\s)\d')
        AutoUpdate = pAutoUpdate.search(output)
        return AutoUpdate.group()
        #appUpdate Check disable 0, check enable 1

    def getjava(self): # 1-3 taylor
        output = subprocess.check_output(['java', '-version'],stderr=subprocess.STDOUT)
        pjava = re.compile(r"java version \"(\d+\.\d+\.\d+)\"")
        mjava = pjava.search(output)
        if mjava != None:
            return mjava.group(1)
        else:
            return 'None'
    
    def getGatekeeper(self): #2-0 kyumm
        output = str(subprocess.check_output('spctl --status', shell=True))
        pStatus = re.compile("enable")
        mStatus = pStatus.search(output)
        if mStatus.group() == "enable":
            return 1
        else: 
            return 0
    
    def getTime(self): # 2-3 taylor
        output = str(subprocess.check_output('systemsetup -getusingnetworktime',shell=True))
        if output.find("On") != -1:
            return 1
        else:
            return 0
        
    def isScreenShareOn(self): #2-6
            output = str(subprocess.check_output('launchctl load /System/Library/LaunchDaemons/com.apple.screensharing.plist', shell=True))
            if output.find("disabled") == -1:
                    return 0
            else:
                    return 1
                
    def getRemoteLogin(self): #2-7 kyumm
        output = str(subprocess.check_output('sudo systemsetup -getremotelogin', shell=True))
        pRlogin = re.compile(r'(?<=Remote\sLogin:\s)\w*')
        Rlogin = pRlogin.search(output)
        if Rlogin.group() == "Off":
            return 1
        else: 
            return 0      
    
    def askForPW(self): # 2-10 taylor
        try:
            output = str(subprocess.check_output('defaults read com.apple.screensaver askForPassword',shell=True))
        except subprocess.CalledProcessError:
            return 1
        else:
            if output.find('0') != -1:
                return 0
            else:
                return 1
        
    def getWebSandbox(self): #2-11 kyumm
        try:
            output = subprocess.check_output('defaults read com.apple.Safari AutoOpenSafeDownloads', shell=True)
        except subprocess.CalledProcessError:
            return 0
        else:
            pWebsandbox = re.compile("\d")
            Websandbox = pWebsandbox.search(output)
            #if Websandbox == "1":
            #   return 1
            #else:
            #   return 0
            return Websandbox.group()

    def isBluetoothOn(self): # 3.0 Bluetooth
        output = str(subprocess.check_output('Defaults read /library/preferences/com.apple.bluetooth ControllerPowerState', shell=True))
        if output.find('1') != -1:
            return 1
        else:
            return 0
                
    def isBluetoothMode(self): #3-0-1
        try:
            output = str(subprocess.check_output('/usr/sbin/system_profiler SPBluetoothDataType | grep -i discoverable',shell=True))
        except subprocess.CalledProcessError:
            return 0
        else:
            if output.find("off") == -1:
                return 0
            else:
                return 1
                
    def isBluetoothHotspot(self): #3-0-2
        try:
            output = str(subprocess.check_output('defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i enable', shell=True))
        except subprocess.CalledProcessError:
            return 'None'
        else:
            hotspot = re.compile('(.+?(\d)){,2}')
            return hotspot.search(output).group(2)
            
    def isBluetoothShare(self): # 3-0-3 taylor
        try:
            output = str(subprocess.check_output('/usr/sbin/system_profiler SPBluetoothDataType | grep State',shell=True))
        except subprocess.CalledProcessError:
            return 0
        else:
            pShare = re.compile(r"^.+(?<=State:\s)(.+?)$", re.MULTILINE)
            mShare = pShare.search(output)
            if mShare.group(1) == "Enabled":
                return 1
            else: 
                return 0

    def isInternettShare(self): # 3-1 taylor
        try:
            output = str(subprocess.check_output('defaults read /Library/preferences/SystemConfiguration/com.apple.nat | grep -i Enabled',shell=True))
        except subprocess.CalledProcessError:
            return 0
        else:
            if output.find('1') != -1:
                return 1
            else:
                return 0
        
    def isOnAppFileServer(self): # 3-2
            #launchctl list | egrep AppleFileServer output = str(subprocess.check_output('',shell=True)
        try:
            output = str(subprocess.check_output('launchctl list | grep AppleFileServer',shell=True))
        except subprocess.CalledProcessError:
            return 0
        else:
            if output.find('0') != -1:
                return 1 # 0 if there is '0' in result, AppFileServer is On
            else:            # as we discussed, 1 dose mean turn on
                return 0
                
    def isSmbOn(self): # 3-3
            output = str(subprocess.check_output('launchctl list | egrep smbd',shell=True))
            if output.find('0') != -1:
                    return 1
            else:
                    return 0
                
    def isFWOn(self): # 3-4
            output = str(subprocess.check_output('Defaults read /library/preferences/com.apple.alf globalstate',shell=True))
            if output.find('1') != -1:
                    return 1
            else:
                    return 0
                
    def getHomeDirPermission(self): #4-1  kyumm
        output = subprocess.check_output('ls -l /Users/ | egrep -iE -v "root|administrator|total"', shell=True)
        pUsers = re.compile(r'(\D{12})(\d+)(\D+\d+)', re.MULTILINE)
        #output = output.split()
        #pUsers = re.compile('^.+', re.MULTILINE)
        mUsers = pUsers.search(output)
        if mUsers != None:
            return mUsers.group(1), mUsers.group(3)
        else:
            return 0
        
    def AppDirPermission(self): # 4-2 taylor
        output=str(subprocess.check_output('sudo find /applications -iname "*\.app" -type d -perm -2 -ls',shell=True))
        if output == ' ':
            return 1
        else:
            return 0
        
    def SystemDirPermission(self): # 4-3 taylor
        output=str(subprocess.check_output('sudo find /System -type d -perm -2 -ls | grep -v "Public/Drop Box"',shell=True))
        #output=str(subprocess.check_output('sudo find /System -type d -perm -2 -ls | grep -v "p'))
        
        if output == ' ':
            return 1
        else:
            return 0
        
    def getAccountLockThreshold(self): #4-4  kyumm
        try:
            output = subprocess.check_output('pwpolicy -getglobalpolicy', shell=True)
            Ppwpolicy = re.compile(r"(.+?)$")
            Mpwpolicy = Ppwpolicy.search(output)
            Mpwpolicy.group()
        except AttributeError:
            return 'None'
        else:
            if Mpwpolicy != None:
                return Mpwpolicy.group()
            else:
                return 'None'

    def AutoLogin(self): # 4-6 taylor
        output=str(subprocess.check_output('defaults read /library/preferences/com.apple.loginwindow',shell=True))
        pUser = re.compile(r"autoLoginUser\s\=\s(\w+?)\;")
        mUser = pUser.search(output)
        if mUser != None:
            return mUser.group(1)
        else:
            return 'None'
        
    def RequirePasswordForSystem(self): # 4-7 taylor
        output=str(subprocess.check_output('security authorizationdb read system.preferences 2> /dev/null | grep -A1 shared | grep -E "(true|false)"',shell=True))
        if output.find('true') != -1:    # true :  no require / false = require
            return 0
        else:
            return 1

    def getUseGuestAccount(self): #4-8 kyumm
        output = str(subprocess.check_output('Defaults read /library/preferences/com.apple.loginwindow.plist GuestEnabled', shell=True))
        #pGuest = re.compile("0")
        #mGuest = pGuest.search(output)
        if output.find('0') != -1:
            return 1
        else:
            return 0
        
    ######################### END ######################




#test  = audit()
#print(test.getIP())

aud = audit()
IP, MAC = aud.getIPnMAC()
result = {
        'ip': IP,
        'mac':MAC,
        'time': datetime.now(),
        'AudidtResult' :     {
            # "A-1-CurrentOSVersion" : aud.getVers(),
             "A-2-LastOSUpdate" : aud.getUpdateHistory(),
             "A-3-AutomaticUpdate" : aud.getAutoUpdate(),
             "A-4-JavaVersion" : aud.isScreenShareOn(),
             
             "B-1-Gatekeeper" : aud.getGatekeeper(),
             "B-2-PWPolicy" : "aaaa", #######
             "B-3-Time" : aud.getTime(), 
             "B-4-ScreenSleep" : "", #########
             "B-5-ScreenShare" : aud.isScreenShareOn(),
             "B-6-RemoteLogin" : aud.getRemoteLogin(),
             "B-7-ScreenAuth" : aud.askForPW(),
             "B-8-WebSandbox" : aud.getWebSandbox(),
             
             "C-1-Bluetooth" : aud.isBluetoothOn(),
             "C-1-Bluetooth-Mode" : aud.isBluetoothMode(),
             "C-1-Bluetooth-Hotspot" : aud.isBluetoothHotspot(),
             "C-1-Bluetooth-share" : aud.isBluetoothShare(),
             "C-2-InternetSharing" : aud.isInternettShare(),
             #"C-3-FileSharing" : aud.isOnAppFileServer(),
             "C-4-Firewall" : "a", #########
             "C-5-DropICMP" : aud.isFWOn(),
             
             "D-1-HomeDirPermission" : aud.getHomeDirPermission(),
             "D-2-AppDirPermission" : aud.AppDirPermission(),
             "D-3-SystemDirPermission" : aud.SystemDirPermission(),
             "D-4-AccountLockThreshold" : aud.getAccountLockThreshold(),
             "D-5-UseRootAccount" : "aa",   #########
             "D-6-UseAutoLogin" : aud.AutoLogin(),
             "D-7-RequirePasswordForSystem" : aud.RequirePasswordForSystem(),
             "D-8-UseGuestAccount" : aud.getUseGuestAccount()
             
            }
    }

print(result)
#es = es.delete(index="test-index", doc_type='audit-result',id=1)
#es.reindex(body=result)
#res = es.index(index="test-index", doc_type='audit-result1',id=1,body=result)
#print(res['result'])

#res = es.get(index="test-index", doc_type='_all',id=1)
#res = es.mget(index="test-index",body=1)
#print(res['_source']) 
