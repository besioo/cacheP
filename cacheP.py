import requests
import argparse
import random
import sys
import threading
from queue import Queue
import urllib.parse
from termcolor import *
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define headers commonly used in cache poisoning attacks, all set to "testtest.com"
POISON_HEADERS = {
    "X-Forwarded-Host": "testtest.com",
    "X-Forwarded-Scheme": "http",
    "X-Forwarded-For": "testtest.com",
    "X-Host": "testtest.com",
    "X-Forwarded-Server": "testtest.com",
    "Forwarded": "host=testtest.com",
    "X-ProxyUser-Ip": "testtest.com",
    "X-Originating-IP": "testtest.com",
    "X-Forwarded-Proto": "testtest.com",
    "X-Client-IP": "testtest.com",
    "True-Client-IP": "testtest.com",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
}

# Function to add a cache buster to the URL if a query string exists
def add_cache_buster(url):
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    # Generate a random cache buster value
    cache_buster = random.randint(10000, 99999)

    # Add the cache buster to the query parameters
    query_params['cachebuster'] = [str(cache_buster)]
    
    # Rebuild the URL with the cache buster
    new_query_string = urllib.parse.urlencode(query_params, doseq=True)
    new_url = parsed_url._replace(query=new_query_string)
    
    return urllib.parse.urlunparse(new_url)

def log_message(message, output_file=None):
    """Prints to console and optionally writes to a file."""
    if output_file:
        with open(output_file, "a") as f:
            f.write(message + "\n")

def test_cache_poison(url, proxy=None, output_file=None):
    proxies = {"http": proxy, "https": proxy} if proxy else None
    cachebuster = random.randint(10000, 99999)
    
    # Add cache buster to the URL if a query string exists
    if '?' in url:
        url = add_cache_buster(url)
    else:
        # Add cache buster if there's no query string
        url += f"?cachebuster={cachebuster}"

    cprint(f"[+] Testing {url} for Cache Poisoning vulnerabilities...", "green")


    try:
        response = requests.get(url, verify=False, headers=POISON_HEADERS, proxies=proxies, timeout=100, allow_redirects=False)
        response_body = response.text
        response_headers = response.headers

        reflected_in_body = "testtest.com" in response_body
        reflected_in_headers = any("testtest.com" in str(h_val) for h_val in response_headers.values())

        if reflected_in_body or reflected_in_headers:
            log_message(f"[!] Possible Cache Poisoning detected at: {url}", output_file)
            cprint(f"[!] Possible Cache Poisoning detected at: {url}", "red")

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not connect to {url}: {e}")

def worker(queue, proxy, output_file):
    """Worker function for multithreading."""
    while not queue.empty():
        url = queue.get()
        test_cache_poison(url, proxy, output_file)
        queue.task_done()

def main():
    parser = argparse.ArgumentParser(description="Multithreaded Cache Poisoning Vulnerability Tester")
    parser.add_argument("-u", "--url", help="Single target URL (e.g., https://example.com)")
    parser.add_argument("-f", "--file", help="File containing multiple URLs (one per line)")
    parser.add_argument("--proxy", help="Use a proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-o", "--output", help="Save results to a file (e.g., results.txt)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads (default: 5)")

    args = parser.parse_args()

    if args.output:
        with open(args.output, "w") as f:
            f.write("Cache Poisoning Scan Results\n" + "=" * 30 + "\n")

    if args.url:
        test_cache_poison(args.url, args.proxy, args.output)
    elif args.file:
        queue = Queue()
        with open(args.file, "r") as file:
            urls = file.read().splitlines()
            for url in urls:
                queue.put(url.strip())

        # Start worker threads
        threads = []
        for _ in range(min(args.threads, queue.qsize())):
            thread = threading.Thread(target=worker, args=(queue, args.proxy, args.output))
            thread.start()
            threads.append(thread)

        # Wait for all threads to finish
        queue.join()
    else:
        print("[ERROR] You must provide a URL (-u) or a file (-f) with URLs.")
        sys.exit(1)

if __name__ == "__main__":
    main()
