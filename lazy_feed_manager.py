import requests
import ipaddress
from ipaddress import ip_address, IPv4Address
import zipfile
import os
import validators
from datetime import datetime

# Declare the paths
feeds_to_collect="ip_feeds.txt"
hashes_to_collect="hashes_feeds.txt"
tor_to_collect="tor_feeds.txt"
whitelist = "whitelist.txt"

# Output IP paths
output_ip_path = "/var/www/html/ip_all.txt"
output_ipv4_path = "/var/www/html/ipv4.txt"
output_ipv6_path = "/var/www/html/ipv6.txt"

# Output Tor paths
output_tor_path = "/var/www/html/all_tor.txt"
output_torIpv4_path = "/var/www/html/torIpv4.txt"
output_torIpv6_path = "/var/www/html/torIpv6.txt"

# OutPut Hashes Paths
output_hash_path= "/var/www/html/all_hashes.txt"
output_hash_sha256_path = "/var/www/html/sha256.txt"
output_hash_sha1_path = "/var/www/html/sha1.txt"
output_hash_md5_path = "/var/www/html/md5.txt"

# Log path
output_log_path = "/var/www/html/log.txt"

# Declare Variables
all_ipv4 = []
all_ipv6 = []
ipv4_to_whitelist = []
ipv6_to_whitelist = []

# ====================================
# [ Functions ]
# ====================================
def validate_ip_address(list_address):
    r_ipv4 = []
    r_ipv6 = []

    for ip in range(len(list_address)):
        try:
            valid_ip = ipaddress.ip_address(list_address[ip])

            # IPV4 or IPV6 ?
            try:
                if type(ipaddress.ip_address(valid_ip)) is IPv4Address:
                    ## Add ip in ipv4 list
                    r_ipv4.append(valid_ip.exploded)
                    #print(all_ipv4)
                else:
                    ## Add exploded ip in ipv6 list
                    r_ipv6.append(valid_ip.exploded)
                    #print(all_ipv6)
            except ValueError:
                pass 
        except ValueError:
            pass 

    return r_ipv4, r_ipv6
    

def read_file(path):
    feeds = []
    with open(path, 'r', encoding='utf-8') as file:
        for line in file:
            feeds.append(line.replace("\n",""))
    return feeds

def pop_whitelist(path,ipv4,ipv6):
    whitelist = []
    r_ipv4 = []
    r_ipv6 = []

    with open(path, 'r', encoding='utf-8') as file:
        for line in file:
            whitelist.append(line.replace("\n",""))

    try:
        for ip in range(len(whitelist)):

                if whitelist[ip] in ipv4:
                    ipv4.remove(whitelist[ip])
                
                else:
                    ipv6.remove(whitelist[ip]) 
    except ValueError:
        pass
    
    return ipv4, ipv6

def save_feeds(path,data):
    if path != output_log_path:
        output_file = open(path, 'w')
        output_file.write('\n'.join(data))
        output_file.write('\n')
        output_file.close()
    else:
        output_file = open(path, 'w')
        output_file.write(data)
        output_file.close()
    
def main_ip_feeds(feed_input):
    all_joined_feeds = ""
    ipv4_to_whitelist = []
    ipv6_to_whitelist = []
    r_all_ipv4 = []
    r_all_ipv6 = []

    all_feeds = read_file(feed_input)

    # GET all the feeds and join all in a single list
    for feed in range(len(all_feeds)):
        if validators.url(all_feeds[feed]):
            r = requests.get(all_feeds[feed])
            decoded_feed = r.content.decode()
            all_joined_feeds += decoded_feed

    # Remove [] from the ipv6
    all_joined_feeds = all_joined_feeds.replace("[","").replace("]","")
 
    # Split by lines to a array
    all_joined_feeds = all_joined_feeds.splitlines()

    # Only uniq values
    all_uniq = list(set(all_joined_feeds))

    # Validate and split ipv/ipv6 lists
    ipv4_to_whitelist, ipv6_to_whitelist = validate_ip_address(all_uniq)
    
    # Gloval variables ipv4/ipv6 is now avaliable
    r_all_ipv4, r_all_ipv6 = pop_whitelist(whitelist, ipv4_to_whitelist, ipv6_to_whitelist)

    return r_all_ipv4, r_all_ipv6 

def get_hashes_bazaar(url,file_name):

    extract_path = '.zipDump/'

    full_path = extract_path+file_name
    req = requests.get(url)
    
    # Writing the file to the local file system
    with open(full_path,'wb') as output_file:
        output_file.write(req.content)

    # Extract the zip file
    with zipfile.ZipFile(full_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)

    # Only to get the filename.txt inside the zipfile
    zip = zipfile.ZipFile(full_path)
    zip_files = zip.namelist()

    # Open the txt file 
    with open(extract_path+zip_files[0], 'r', encoding='utf-8') as file:
            file_hash = file.readlines()

    # clean comments section
    file_hash = file_hash[9:]
    file_hash.pop(-1)

    # Remove original zip and txt
    os.remove(full_path)
    os.remove(extract_path+zip_files[0])
    
    # Remove \n from all elements
    for hash in range(len(file_hash)):
        file_hash[hash]=file_hash[hash].replace('\n','')
    
    return file_hash


# ================= [ MAIN ]=====================

ip_feeds_ipv4, ip_feeds_ipv6 = main_ip_feeds(feeds_to_collect)
tor_feeds_ipv4, tor_feeds_ipv6 = main_ip_feeds(tor_to_collect)

hashes_sha256 = get_hashes_bazaar('https://bazaar.abuse.ch/export/txt/sha256/full/','bazaar_sha256_full.zip')
hashes_md5 = get_hashes_bazaar('https://bazaar.abuse.ch/export/txt/md5/full/','bazaar_md5_full.zip')
hashes_sha1 = get_hashes_bazaar('https://bazaar.abuse.ch/export/txt/sha1/full/','bazaar_sha1_full.zip')

# Create a log file
qty_ip_feeds_all = '[ALL-IP-FEEDS] - Number of entries: ' + str(len(ip_feeds_ipv4)+len(ip_feeds_ipv6))
qty_ip_feeds_ipv4 = '[IPV4] - Number of entries: ' + str(len(ip_feeds_ipv4))
qty_ip_feeds_ipv6 = '[IPV6] - Number of entries: ' + str(len(ip_feeds_ipv6))

qty_tor_feeds_all = '[ALL-TOR-IP] - Number of entries: ' + str(len(tor_feeds_ipv4)+ len(tor_feeds_ipv6))
qty_tor_feeds_ipv4 = '[TOR-IPV4] - Number of entries: ' + str(len(tor_feeds_ipv4))
qty_tor_feeds_ipv6 = '[TOR-IPV6] - Number of entries: ' + str(len(tor_feeds_ipv6))

qty_hashes_all = '[ALL-HASHES] - Number of entries: ' + str(len(hashes_sha256)+len(hashes_md5)+len(hashes_sha1))
qty_hashes_sha256 = '[SHA256] - Number of entries: ' + str(len(hashes_sha256))
qty_hashes_md5 = '[MD5] - Number of entries: ' + str(len(hashes_md5))
qty_hashes_sha1 = '[SHA1] - Number of entries: ' + str(len(hashes_sha1))

coments='#' * 50

# datetime object containing current date and time
now = datetime.now()
last_update = '[Last update] -  ' + now.strftime("%d/%m/%Y %H:%M:%S")

log_IP="""{0}
{1}
#
{2}
{3}
{4}
#"""
log_TOR="""{0}
{1}
{2}
#"""

log_HASH="""{0}
{1}
{2}
{3}
{4}"""

full_log="""{0}
{1}
{2}
"""
log_IP=log_IP.format(coments,last_update,qty_ip_feeds_all,qty_ip_feeds_ipv4,qty_ip_feeds_ipv6)
log_TOR=log_TOR.format(qty_tor_feeds_all,qty_tor_feeds_ipv4,qty_tor_feeds_ipv6)
log_HASH=log_HASH.format(qty_hashes_all,qty_hashes_sha256,qty_hashes_md5,qty_hashes_sha1,coments)
full_log=full_log.format(log_IP,log_TOR,log_HASH)

print(full_log)

# Save the data in their respective paths
save_feeds(output_log_path, full_log)

save_feeds(output_ip_path, ip_feeds_ipv4+ip_feeds_ipv6)
save_feeds(output_ipv4_path, ip_feeds_ipv4)
save_feeds(output_ipv6_path, ip_feeds_ipv6)

save_feeds(output_tor_path, tor_feeds_ipv4+tor_feeds_ipv6)
save_feeds(output_torIpv4_path, tor_feeds_ipv4)
save_feeds(output_torIpv6_path, tor_feeds_ipv6)

save_feeds(output_hash_path, hashes_sha256+hashes_md5+hashes_sha1)
save_feeds(output_hash_sha256_path, hashes_sha256)
save_feeds(output_hash_sha1_path, hashes_md5)
save_feeds(output_hash_md5_path, hashes_sha1)



