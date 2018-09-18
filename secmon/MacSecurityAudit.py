import re
import subprocess
import json
from datetime import datetime
#from elasticsearch import Elasticsearch

#es = Elasticsearch(['http://192.168.0.13:9200'])

class myElastic:
    def __init__(self, host=None, port=None, bTest=False):

        if bTest == False:
            try:
                if host == None and port==None:
                    self.es = Elasticsearch()
                elif host == None and port != None:
                    self.es = Elasticsearch(['localhost:%d'%(port)])
                else:
                    self.es = Elasticsearch(['%s:%d'%(host,port)])
            except:
                print("cannot connect to elasticsearch server, please report to administrator\n")
                exit(-1)
        self.auditor = audit()
    def doAuditNReport(self):
        currUserAcc = self.auditor.getUserAcc()
        IP, MAC = self.auditor.getIPnMAC()
        result = {
        'ip': IP,
        'mac':MAC,
        'time': datetime.now(),
        'self.esidtResult' :     {
             "A-1-CurrentOSVersion" : self.auditor.getVers(),
             "A-2-LastOSUpdate" : self.auditor.getUpdateHistory(),
             "A-3-AutomaticUpdate" : self.auditor.getAutoUpdate(),
             "A-4-JavaVersion" : self.auditor.isScreenShareOn(),
             
             "B-1-Gatekeeper" : self.auditor.getGatekeeper(),
             "B-2-PWPolicy" : "aaaa", #######
             "B-3-Time" : self.auditor.getTime(), 
             "B-4-ScreenSleep" : "", #########
             "B-5-ScreenShare" : self.auditor.isScreenShareOn(),
             "B-6-RemoteLogin" : self.auditor.getRemoteLogin(),
             "B-7-ScreenAuth" : self.auditor.askForPW(),
             "B-8-WebSandbox" : self.auditor.getWebSandbox(),
             
             "C-1-Bluetooth" : self.auditor.isBluetoothOn(),
             "C-1-Bluetooth-Mode" : self.auditor.isBluetoothMode(),
             "C-1-Bluetooth-Hotspot" : self.auditor.isBluetoothHotspot(),
             "C-1-Bluetooth-share" : self.auditor.isBluetoothShare(),
             "C-2-InternetSharing" : self.auditor.isInternettShare(),
             "C-3-FileSharing" : self.auditor.isOnAppFileServer(),
             "C-4-Firewall" : "a", #########
             "C-5-DropICMP" : self.auditor.isFWOn(),
             
             "D-1-HomeDirPermission" : self.auditor.getHomeDirPermission(currUserAcc),
             "D-2-AppDirPermission" : self.auditor.AppDirPermission(),
             "D-3-SystemDirPermission" : self.auditor.SystemDirPermission(),
             "D-4-AccountLockThreshold" : self.auditor.getAccountLockThreshold(),
             "D-5-UseRootAccount" : self.auditor.isUseRootAcc(),
             "D-6-UseAutoLogin" : self.auditor.AutoLogin(),
             "D-7-RequirePasswordForSystem" : self.auditor.RequirePasswordForSystem(),
             "D-8-UseGuestAccount" : self.auditor.getUseGuestAccount()
             
            }
        }
        print(result)
        #res = self.es.index(index="test-index", doc_type='self.esit-result1',id=1,body=result)
        #print(res['result'])
        
    def test(self):
        currUserAcc = self.auditor.getUserAcc()
        print(self.auditor.isUseRootAcc())
class audit:
    ################## GET BASIC INFO ######################
    def getHostName(self):
        return str(subprocess.check_output('hostname', shell=True))
    
    def getUserAcc(self):
        return str(subprocess.check_output('stat -f "%Su" /dev/console', shell=True)).strip()
    
    def getIPnMAC(self):
        ret = str(subprocess.check_output("ifconfig en0", shell=True))
        rIP = re.compile(r"(inet )(((\d{1,3}[.]){3})\d{1,3})")
        rMAC = re.compile(r"(..[:]){5}..")
        return rIP.search(ret).group(2), rMAC.search(ret).group()
    
    ####################### END #############################
    
    ############### self.esIT START ##############################
    def getVers(self): #1.0
        ret = str(subprocess.check_output("sw_vers", shell=True))
        rProductName = re.compile(r"ProductName:(.+?)$")
        rProductVersion = re.compile(r"ProductVersion:(.+?)$", re.MULTILINE)
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
        output = str(subprocess.check_output('systemsetup -getremotelogin', shell=True))
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
                
    def getHomeDirPermission(self, user): #4-1  kyumm
        output = subprocess.check_output('ls -l /Users/ | grep %s | egrep -iE -v "root|administrator|total"' % user , shell=True)
        pUsers = re.compile(r'(\D{12})(\d+)(\D+\d+)', re.MULTILINE)
        #output = output.split()
        #pUsers = re.compile('^.+', re.MULTILINE)
        mUsers = pUsers.search(output)
        if mUsers != None:
            return mUsers.group(1)#, mUsers.group(3)
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
        output = subprocess.check_output('pwpolicy -getaccountpolicies', shell=True)
        Ppwpolicy = re.compile(r"(.+?)$")
        Mpwpolicy = Ppwpolicy.search(output)
        #return Mpwpolicy.group()
        if Mpwpolicy != None:
            return Mpwpolicy.group()
        else:
            return "0"
            
    def useRootLogin(self): # 4-6 taylor
        output=str(subprocess.check_output('defaults read /Library/Preferences/com.apple.alf globalstate',shell=True))
        return output
    
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
        
    def isUseRootAcc(self):
        cmd = 'dscl . -read /Users/root AuthenticationAuthority'
        output = str(subprocess.check_output(cmd,stderr=subprocess.STDOUT, shell=True))
        if output.find('No such key: AuthenticationAuthority') != -1:
            return 1
        else:
            return 0
    ######################### END ######################

if __name__ == '__main__':
    test = myElastic(bTest=True)
    test.test()
    #test.te()

