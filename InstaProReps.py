from requests import post, get
import requests, os, re, uuid
from datetime import datetime   

try:
    import requests
except:
    os.system("pip install requests")    

try:
    from rich.console import Console
except:
    os.system("pip install rich")
    
    
mag = "\033[1m\033[35m"
g= "\033[1m\033[32m"
y= "\033[1m\033[33m"
red = "\033[1m\033[31m"
green = "\033[1m\033[32m"
yellow = "\033[1m\033[33m"
blue = "\033[1m\033[34m"
cyan = "\033[1m\033[36m"
magenta = "\033[1m\033[35m"
M = "\033[1m\033[36m"
white = "\033[1m\033[37m"
orange = "\033[1m\033[38;5;208m"
reset = "\033[0m"
org = "\033[1m\033[38;5;208m"

#This tool making about report instagram and been band the acc [ if your user report it ]
#        .. This tool is safer about any thinks  
#Done By Odwy X ZELD3X


uid=str(uuid.uuid4())
console=Console()

def check_date():
    current_date = datetime.now().date()
    target_date = datetime(2028, 1, 10, 23, 59, 59).date()
    if current_date >= target_date:
        print("""The tool's validity has expired.
To renew, please contact @EG0GG or @RJJVJ """)
        exit()
check_date()


def header():
    
    os.system("cls" if os.name=='nt' else "clear")
    print(f""" 
 
 Dev -  ________  ________  ________          _________  _______   ________  _____ ______      
|\   ____\|\   __  \|\_____  \        |\___   ___\\  ___ \ |\   __  \|\   _ \  _   \    
\ \  \___|\ \  \|\  \\|___/  /|       \|___ \  \_\ \   __/|\ \  \|\  \ \  \\\__\ \  \   
 \ \_____  \ \  \\\  \   /  / /            \ \  \ \ \  \_|/_\ \   __  \ \  \\|__| \  \  
  \|____|\  \ \  \\\  \ /  /_/__            \ \  \ \ \  \_|\ \ \  \ \  \ \  \    \ \  \ 
    ____\_\  \ \_______\\________\           \ \__\ \ \_______\ \__\ \__\ \__\    \ \__\
   |\_________\|_______|\|_______|            \|__|  \|_______|\|__|\|__|\|__|     \|__|
   \|_________|                                                                         
                                                                                        
                                                                                        )
    console.print(f"""
     ONLY 0DWY
""",style='bold purple4',justify='left')
    print("SOZ ~ 4r0ux")
    print("")



def Report_Instagram(target_id,sessionid,csrftoken):
    header()
    
    
    print(f"""
{cyan} _____________________________
|                             | 
| {y}~${mag} choose the report- {cyan}         ______     ______     ______        ______   ______     ______     __    __    
/\  ___\   /\  __ \   /\___  \      /\__  _\ /\  ___\   /\  __ \   /\ "-./  \   
\ \___  \  \ \ \/\ \  \/_/  /__     \/_/\ \/ \ \  __\   \ \  __ \  \ \ \-./\ \  
 \/\_____\  \ \_____\   /\_____\       \ \_\  \ \_____\  \ \_\ \_\  \ \_\ \ \_\ 
  \/_____/   \/_____/   \/_____/        \/_/   \/_____/   \/_/\/_/   \/_/  \/_/ 
                                                                                
|_____________________________|

------------------------------
| {g}1 ~ {y} - spam {cyan}                  |
------------------------------
| {g}2 ~ {y} - self {cyan}                  |
------------------------------
| {g}3 ~ {y} - sale {cyan}                  |
------------------------------
| {g}4 ~ {y} - Nudity  {cyan}              |
------------------------------
| {g}5 ~ {y} - violence {cyan}              |
------------------------------
| {g}6 ~ {y} - hate {cyan}                  |
------------------------------
| {g}7 ~ {y} - harassment {cyan}            |
------------------------------
| {g}8 ~ {y} - instagram {cyan}             |
------------------------------
| {g}9 ~ {y} - instagram business {cyan}    |
------------------------------
| {g}10 ~ {y} - copyright {cyan}            |
------------------------------
| {g}11 ~ {y} - Impression 3 business{cyan}                  |
------------------------------
| {g}12 ~ {y} - Impression 3 instagram {cyan}                  |
------------------------------
| {g}13 ~ {y} - Impression 4 business {cyan}                   |
------------------------------
| {g}14 ~ {y} - Impression 4 instagram {cyan}                  |
------------------------------
| {g}15 ~ {y}  - Violence 1 {cyan}               
TEAM SOZ Tool

------------------------------
""")

    try:
        reportType = int(input("-> type number (1-15): "))
        if reportType > 15 or reportType < 1:
            print("wrong number\ntry again")
        else:
            print(f"You chose report type {reportType}.")
    except ValueError:
        print("Invalid input. Please enter a number.")
    
    while 1:
        try:
            r3=post("https://i.instagram.com/users/"+target_id+"/flag/",headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0","Host": "i.instagram.com",'cookie': f"sessionid={sessionid}","X-CSRFToken": csrftoken,"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},data=f'source_name=&reason_id={reportType}&frx_context=',allow_redirects=False)
            #if 'ok' in r3.text: #   console.print(f"- Done Report")
            if r3.status_code==429:
                console.print(f"- Ban with status code [ {r3.status_code} ] ");exit()
            elif r3.status_code==500:
                console.print(f"- Target Not Found with status code [ {r3.status_code} ] ");exit()
            else:
                console.print(f"- Report Done with status code [ {r3.status_code} ] ") 				
        except requests.exceptions.TooManyRedirects:
            console.print(f"- Report Done with status code [ {r3.status_code} ] ")#;exit()
        except Exception as e:
            console.print(f"- Report Failed with status code [ {r3.status_code} ] ");exit()

def starter():
    user=input(f"{red}[+] USERRNAME :{reset}{cyan} ")
    if user=="":console.print("[!] You must write The user");exit()
    pess=input(f"{M}[+] PASSWD :{reset} ")
    if pess=="":console.print("[!] You must write The password");exit()
    r1=post('https://i.instagram.com/api/v1/accounts/login/',headers={'User-Agent': 'Instagram 114.0.0.38.120 Android (30/3.0; 216dpi; 1080x2340; huawei/google; Nexus 6P; angler; angler; en_US)',"Accept": "*/*","Accept-Encoding": "gzip, deflate","Accept-Language": "en-US","X-IG-Capabilities": "3brTvw==","X-IG-Connection-Type": "WIFI","Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",'Host': 'i.instagram.com'},data={'_uuid': uid,'password': pess,'username': user,'device_id': uid,'from_reg': 'false','_csrftoken': 'missing','login_attempt_count': '0'},allow_redirects=True)
    if 'logged_in_user' in r1.text:
        console.print("- Login Done [bold green]succ_Login[/bold green] ")
        sessionid=r1.cookies['sessionid']
        csrftoken=r1.cookies['csrftoken']
        target=input("- Target username : ") #The username Must Be Entered Manually Not Copy & Paste

        r2=post('https://i.instagram.com:443/api/v1/users/lookup/',headers={"Connection": "close", "X-IG-Connection-Type": "WIFI","mid":"XOSINgABAAG1IDmaral3noOozrK0rrNSbPuSbzHq","X-IG-Capabilities": "3R4=","Accept-Language": "ar-sa","Content-Type": "application/x-www-form-urlencoded; charset=UTF-8","User-Agent": "Instagram 99.4.0 TweakPY_vv1ck (TweakPY_vv1ck)","Accept-Encoding": "gzip, deflate"},data={"signed_body": "35a2d547d3b6ff400f713948cdffe0b789a903f86117eb6e2f3e573079b2f038.{\"q\":\"%s\"}" % target})
        if 'No users found' in r2.text:
            adv_search=get(f'https://www.instagram.com/{target}',headers={'Host': 'www.instagram.com','User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0','Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8','Accept-Language': 'ar,en-US;q=0.7,en;q=0.3','Accept-Encoding': 'gzip, deflate, br','Connection': 'keep-alive','Cookie': f'csrftoken={csrftoken}','Upgrade-Insecure-Requests': '1','Sec-Fetch-Dest': 'document','Sec-Fetch-Mode': 'navigate','Sec-Fetch-Site': 'none','Sec-Fetch-User': '?1','TE': 'trailers'})
            try:
                target_id=re.findall('"profile_id":"(.*?)"',adv_search.text)[0]
                Report_Instagram(target_id,sessionid,csrftoken)
            except IndexError:
                try:
                    target_id=re.findall('"page_id":"profilePage_(.*?)"',adv_search.text)[0]
                    Report_Instagram(target_id,sessionid,csrftoken)
                except IndexError:
                    try:
                        adv_search2=get(f'https://www.instagram.com/api/v1/users/web_profile_info/?username={target}',headers={'Host': 'www.instagram.com','User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0','Accept': '*/*','Accept-Language': 'ar,en-US;q=0.7,en;q=0.3','Accept-Encoding': 'gzip, deflate, br','X-CSRFToken': csrftoken,'X-IG-App-ID': '936619743392459','X-ASBD-ID': '198387','X-IG-WWW-Claim': 'hmac.AR3KPEPoXkWYhwtoCUKyUHK80GsE1g2PJI1uPtDlCyo4PHKn','X-Requested-With': 'XMLHttpRequest','Alt-Used': 'www.instagram.com','Connection': 'keep-alive','Referer': f'https://www.instagram.com/{target}/','Cookie':  f'sessionid={sessionid}','Sec-Fetch-Dest': 'empty','Sec-Fetch-Mode': 'cors','Sec-Fetch-Site': 'same-origin','TE': 'trailers'})
                        target_id=adv_search2.json()['data']['user']['id']
                        Report_Instagram(target_id,sessionid,csrftoken)
                    except KeyError:
                        console.print('\n- [bold red]Failed[/bold red] to get target username, Try entering the Target ID manually .\n')
                        target_id=input('- Enter The Target ID : ')
                        Report_Instagram(target_id,sessionid,csrftoken)
        elif '"spam":true' in r2.text:
            console.print("- Try again Later !");exit()
        else:
            try:
                target_id=str(r2.json()['user_id'])
                Report_Instagram(target_id,sessionid,csrftoken)
            except KeyError:
                console.print('- General [bold red]Error[/bold red] ...');exit() 

    elif 'ip_block' in r1.text:
        console.print("- You Have [bold red]banned[/bold red] from Instagram ( [bold red]ip block[/bold red] ) !");exit()
    elif 'The password you entered is incorrect' in r1.text:
        console.print("- Please check Your Password !");exit()
    elif "Please check your username and try again." in r1.text:
        console.print("- username Not Found !");exit()
    elif 'two_factor_required' in r1.text:
        console.print("- [bold orange3]Two Factor[/bold orange3] ! ...");exit()
    elif 'challenge_required' in r1.text:
        console.print("- [bold orange3]Secure[/bold orange3] Account ! ...");exit()
    elif 'inactive user' in r1.text:
        console.print('- This user is [bold red]banned[/bold red] from Instagram ...');exit()
    elif "We're working on it and we'll get it fixed as soon as we can." in r1.text:
        console.print("- Try again in a minute !");exit()
    elif 'Please wait a few minutes before you try again' in r1.text:
        console.print("- Try again in a minute !");exit()
    elif 'Bad request' in r1.text:
        console.print("- [bold red]Error[/bold red] in instagram, try again in 15 minutes ...");exit()
    elif 'Invalid Parameters' in r1.text:
        console.print("- [bold red]Error[/bold red] Please Reinstall The Tool From The original Source ... ");exit()
    else:
        console.print('- General [bold red]Error[/bold red] ...');exit()    



header();starter()

#0DWY & ZELD3X Legend of hell