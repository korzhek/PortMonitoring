import socket
from datetime import datetime, date, time
from libnmap.parser import NmapParser
from sys import argv
from libnmap.process import NmapProcess


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
f = open('logs.txt', 'a')

def nested_obj(objname):
    rval = None
    splitted = objname.split("::")
    if len(splitted) == 2:
        rval = splitted
    return rval

def get_ip():
    ip_list = []
    dik = {}
    try:
        url_txt = open(argv[1], "r")
        log_url = open('ip-url-log.txt', 'a')
        log_url.write('---------------------Update TIME: ' 
                + str(datetime.now())
                + '-------------------' + '\n')
        for url in url_txt:
            ip = socket.gethostbyname(url.strip())
            ip_list.append(ip)
            dik.setdefault(ip,[]).append(url[:-1])
        for key, value in dik.items():
            log_url.write('\n' + str(key) + '\n')
            for i in value:
                log_url.write('           |____' + i + '\n')
        ip_list = set(ip_list)
        ip_list = list(ip_list)
        url_txt.close()
        log_url.close()
    except socket.error:
        print ('[-] Error: not connect with DNS servers')
        exit()
    except IOError:
        print ('[-] No such file: \'url.txt\'')
        exit()
    print ('[+] IP -> URL added in: ip-url-log.txt')
    return ip_list

def nmap_scanning():
    nm = NmapProcess(get_ip(), options = '')
    rc = nm.run()

    if nm.rc == 0:
        try:
            oldrep = NmapParser.parse_fromfile('old.xml')
            newrep = NmapParser.parse(nm.stdout)
        except:
            print('[-] Not found: old.xml')
            q = open('old.xml', 'w')
            q.write(nm.stdout)
            q.close()
            print('[+] Create new: old.xml')
            exit()
    else:
        print (nm.stderr)
    print ('[+] Nmap scan complete')

    q = open('old.xml', 'w')
    q.write(nm.stdout)
    q.close()

    print ('[+] Nmap file save as: old.xml')
    return (newrep, oldrep)

def print_diff_added(obj1, obj2, added, ancestor):
    for akey in added:
        nested = nested_obj(akey)
        if nested is not None:
            if nested[0] == 'NmapHost':
                subobj1 = obj1.get_host_byid(nested[1]).services
                host1 = ('maxpatrol mp/scanner: [IP= {0} ] [change = added]\n'.format(nested[1]))
                s.send(host1.encode())
                f.write(host1)
                for i in subobj1:
                    korz = i.get_dict()
                    serv_host1 = ('maxpatrol mp/scanner: [IP= {0} ] [protocol= {1} ] [port= {2} ] [status= {3}] [service = {4}] [change = added]\n'.format(nested[1],korz['protocol'],korz['port'],korz['state'],korz['service']))
                    s.send(serv_host1.encode())
                    f.write(serv_host1)
            elif nested[0] == 'NmapService':
                subobj1 = obj1.get_service_byid(nested[1]).get_dict()
                serv1 = ('maxpatrol mp/scanner: [IP= {0} ] [protocol= {1} ] [port= {2} ] [status= {3}] [service = {4}] [change = added]\n'.format(ancestor,subobj1['protocol'],subobj1['port'],subobj1['state'],subobj1['service']))
                s.send(serv1.encode())
                f.write(serv1)

def print_diff_removed(obj1, obj2, removed, ancestor):
    for rkey in removed:
        nested = nested_obj(rkey)
        if nested is not None:
            if nested[0] == 'NmapHost':
                subobj2 = obj2.get_host_byid(nested[1]).services
                host2 = ('maxpatrol mp/scanner: [IP= {0} ] [change = removed]\n'.format(nested[1]))
                s.send(host2.encode())
                f.write(host2)
                for i in subobj2:
                    korz = i.get_dict()
                    serv_host2 = ('maxpatrol mp/scanner: [IP= {0} ] [protocol= {1} ] [port= {2} ] [status= {3}] [service = {4}] [change = removed]\n'.format(nested[1],korz['protocol'],korz['port'],korz['state'],korz['service']))
                    s.send(serv_host2.encode()) 
                    f.write(serv_host2)        
            elif nested[0] == 'NmapService':
                subobj2 = obj2.get_service_byid(nested[1]).get_dict()
                serv2 = ('maxpatrol mp/scanner: [IP= {0} ] [protocol= {1} ] [port= {2} ] [status= {3}] [service = {4}] [change = removed]\n'.format(ancestor,subobj2['protocol'],subobj2['port'],subobj2['state'],subobj2['service']))
                s.send(serv2.encode())
                f.write(serv2)

def print_diff_changed(obj1, obj2, changes, ancestor):
    for mkey in changes:
        nested = nested_obj(mkey)
        if nested is not None:
            if nested[0] == 'NmapHost':
                subobj1 = obj1.get_host_byid(nested[1])
                subobj2 = obj2.get_host_byid(nested[1])
                print_diff(subobj1, subobj2, nested[1])
            elif nested[0] == 'NmapService':
                subobj1 = obj1.get_service_byid(nested[1])
                subobj2 = obj2.get_service_byid(nested[1])
                print_diff(subobj1, subobj2, ancestor)
        else:
            obj = obj1.get_dict()

            if type(obj1).__name__ == 'NmapService':
                nserv = ('maxpatrol mp/scanner: [IP= {0} ] [protocol= {1} ] [port= {2} ] [status= {3}] [service = {4}] [changed {5}: {6} => {7}]\n'.format(ancestor,obj['protocol'],obj['port'],obj['state'],obj['service'], mkey, getattr(obj2, mkey), getattr(obj1, mkey)))
                s.send(nserv.encode())
                f.write(nserv)
            elif type(obj1).__name__ == 'NmapHost':
                nhost = ('maxpatrol mp/scanner: [IP= {0} ] [change {1}: {2} => {3}]\n'.format(obj['address'], mkey, getattr(obj2, mkey), getattr(obj1, mkey)))
                s.send(nhost.encode())
                f.write(nhost)


def print_diff(obj1, obj2, ancestor=None):
    ndiff = obj1.diff(obj2)
    print_diff_changed(obj1, obj2, ndiff.changed(), ancestor)
    print_diff_added(obj1, obj2, ndiff.added(), ancestor)
    print_diff_removed(obj1, obj2, ndiff.removed(), ancestor)


def main():
    try:
        if len(argv) != 4:
            print('Usage: portmon.py <dns.txt> <ip> <port>')
            print('Example: python portmon.py dns.txt 10.148.13.12 8000') 
            exit()
        newrep, oldrep = nmap_scanning() 
        host = str(argv[2])
        port = int(argv[3])
        s.connect((host,port))
        f.write('[+] ' + str(datetime.now()) + ' -> Complete' + '\n')
        print_diff(newrep, oldrep)
        s.close()
        f.close()
        print ('[+] Diff recived and send to server: ' + host + ':' + str(port))
        print ("[+] Added logstring in: logs.txt")
        print ("[+] Complete")
    except socket.error:
        print ("[-] Error connect")
        f.write('[-] ' + str(datetime.now()) + ' -> Error: not connect with host ' + host + ':' + str(port) + '\n')
        f.close()
        exit()


if __name__ == "__main__":
    main()

