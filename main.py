import argparse
import hashlib
import subprocess
from OTXv2 import OTXv2
import get_malicious
from logger import logger

def block_ip(ip):
    logger.info(f"Blocking IP: {ip}")
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    logger.info(f"{ip} has been blocked")

def check():
    API_KEY = 'INSERT API KEY HERE'  
    OTX_SERVER = 'https://otx.alienvault.com/'
    otx = OTXv2(API_KEY, server=OTX_SERVER)

    parser = argparse.ArgumentParser(description='OTX CLI Threat Intelligence Module')
    parser.add_argument('-ip', help='IP address to check')
    parser.add_argument('-host', help='Hostname to check')
    parser.add_argument('-url', help='URL to check')
    parser.add_argument('-hash', help='Hash to check')
    parser.add_argument('-file', help='File to check (MD5 hashed)')
    parser.add_argument('-block', help='Block IP if malicious', action='store_true')

    args = parser.parse_args()

    if args.ip:
        logger.info(f"Checking IP: {args.ip}")
        alerts = get_malicious.ip(otx, args.ip)
        if alerts:
            logger.warning("IP flagged as malicious:")
            logger.warning(str(alerts))
            if args.block:
                cont = input("ip may be malicious. Would you like to block it? y/n").lower()
                if cont == 'y':
                    block_ip(args.ip)
                else:
                    print("ip not blocked.")
        else:
            logger.info("IP is clean.")

    if args.host:
        logger.info(f"Checking Hostname: {args.host}")
        alerts = get_malicious.hostname(otx, args.host)
        if alerts:
            logger.warning("Hostname flagged as malicious:")
            logger.warning(str(alerts))
        else:
            logger.info("Hostname is clean.")

    if args.url:
        logger.info(f"Checking URL: {args.url}")
        alerts = get_malicious.url(otx, args.url)
        if alerts:
            logger.warning("URL flagged as malicious:")
            logger.warning(str(alerts))
        else:
            logger.info("URL is clean.")

    if args.hash:
        logger.info(f"Checking Hash: {args.hash}")
        alerts = get_malicious.file(otx, args.hash)
        if alerts:
            logger.warning("Hash flagged as malicious:")
            logger.warning(str(alerts))
        else:
            logger.info("Hash is clean.")

    if args.file:
        try:
            with open(args.file, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
                logger.info(f"MD5 hash of file: {file_hash}")
                alerts = get_malicious.file(otx, file_hash)
                if alerts:
                    logger.warning("File flagged as malicious:")
                    logger.warning(str(alerts))
                else:
                    logger.info("File is clean.")
        except Exception as e:
            logger.error(f"Error reading file: {e}")

if __name__ == '__main__':
    check()
