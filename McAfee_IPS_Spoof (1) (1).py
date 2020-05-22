import csv
from datetime import datetime
from random import randint
import time
import datetime
import random
import pdb



value={}

value["src_host"]=["10.20.3.110" ,"10.20.3.121","10.20.3.100","10.20.3.115","10.20.3.109" ,"10.20.3.141","10.20.3.156"]
value["Log_format"]=['SyslogAlertForwarder:','SyslogAlertForwarder:']
value["ALERT_ID"]=['6414080755721214437','6414080755721214436','6414080755721214440','6414080755721214438','6414080755721214441','6414080755721214585','6414080755721214590']
value["ALERT_TYPE"]=['Signature','Host Sweep','Simple Threshold Anomaly','Signature','Host Sweep','Simple Threshold Anomaly','Host Sweep']
value["ATTACK_NAME"]=['"P2P: TeamViewer Traffic Detected"','"TCP: SYN Host Sweep"','"HTTP: Overly Long POST URI in HTTP Request"','"TCP: Full-Connect Host Sweep"','"HTTP: Response UTF16/32 Encoding"','"Too Many Outbound Rejected TCP Packets"','"UDP: Host Sweep"']
value["ATTACK_ID"]=['0x40017000','0x40009a00','0x40018700','0x42c05f00','0x40018700','0x40223600','0x40009b00']
value["ATTACK_SEVERITY"]=['Medium','Low','High','Medium','Low','High','Medium']
value["ATTACK_SIGNATURE"]=['http_long_uri','N/A','invitee-https-access','utf16-encoding-le','ms-file-spoof-vuln','teamviewer_conn3','server-renegotiation']
value["ATTACK_CONFIDENCE"]=['Low','N/A','Medium','Low','N/A','Medium','high']
value["ADMIN_DOMAIN"]=['Quinnox','Quinnox']                    
value["SENSOR_NAME"]=['BGLR-IPS','MUM-IPS']      
value["INTERFACE"]=['8A-8B','7A-7B']
value["SOURCE_IP"]=['10.30.2.35','10.30.2.48','10.30.3.97','10.20.28.71','10.20.3.98','10.20.3.4','10.20.16.92']  
value["SOURCE_PORT"]=['49851','49847','63451','63458','63465','57860','50993']
value["TARGET_IP"]=['178.255.155.118','37.252.230.28','103.243.221.109','185.188.32.3','162.220.223.28','212.81.93.213','10.20.3.98']
value["TARGET_PORT"]=['5938','80','50993','443','53','59151','55807']
value["CATEGORY"]=['PolicyViolation','Exploit','Reconnaissance','VolumeDos','PolicyViolation','Exploit','Reconnaissance']
value["SUB_CATEGORY"]=['restricted-application','host-sweep','code-execution','evasion-attempt','protocol-violation','over-threshold','code-execution']
value["DIRECTION"]=['Outbound','Inbound']
value["RESULT_STATUS"]=['Inconclusive','N/A']
value["DETECTION_MECHANISM"]=['signature','multi-flow-correlation','protocol-anomaly','threshold','N/A','signature','threshold']                 
value["APPLICATION_PROTOCOL"]=['http','ssl']
value["NETWORK_PROTOCOL"]=['tcp','N/A'] 
#pdb.set_trace()

now = datetime.datetime.now()
newtime = now-datetime.timedelta(seconds=60)
res={}
log_file=open('McAfee_IPS_Spoof.log', mode='w')




while True:
    metadata=[]
    n = random.randint(10,90)
    new_time = newtime + datetime.timedelta(seconds=60)
    newtime=new_time
    
   
  
    i=randint(0,1)
    j=randint(0,1)
    k=randint(0,6)
    m=randint(0,6)
    n=randint(0,6)
    metadata=new_time.strftime("%Y-%m-%dT%H:%M:%S.000000+05:30")+" "+value["src_host"][k]+" "+value["Log_format"][j]+" |"+value["ALERT_ID"][m]+"|"+value["ALERT_TYPE"][n]+"|"+newtime.strftime('%Y-%m-%d %H:%M:%S IST')+"|"+value["ATTACK_NAME"][k]+"|"+value["ATTACK_ID"][m]+"|"+value["ATTACK_SEVERITY"][k]+"|"+value["ATTACK_SIGNATURE"][n]+"|"+value["ATTACK_CONFIDENCE"][m]+"|"+value["ADMIN_DOMAIN"][i]+"|"+value["SENSOR_NAME"][j]+"|"+value["INTERFACE"][j]+"|"+value["SOURCE_IP"][k]+"|"+value["SOURCE_PORT"][m]+"|"+value["TARGET_IP"][k]+"|"+value["TARGET_PORT"][n]+"|"+value["CATEGORY"][m]+"|"+value["SUB_CATEGORY"][k]+"|"+value["DIRECTION"][j]+"|"+value["RESULT_STATUS"][i]+"|"+value["DETECTION_MECHANISM"][n]+"|"+value["APPLICATION_PROTOCOL"][j]+"|"+value["NETWORK_PROTOCOL"][i]+"\n"
    
  
    if now < newtime :
        
        log_file.write(metadata)
        time.sleep(60)
        
        
    
    
    
    log_file = open("McAfee_IPS_Spoof.log", "r+")
    print(log_file.readline())
    
    



 
