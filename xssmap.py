import argparse
import subprocess
import re
import random
import string
import requests
from bs4 import BeautifulSoup
import threading
from queue import Queue
from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
import time
from exploit import *

# Generating a random string
def generate_random_string():
    characters = string.ascii_letters  # Contains both lowercase and uppercase letters
    random_string = ''.join(random.choice(characters) for _ in range(8))
    return random_string

def replace_xssmap(url, new_value):
    return url.replace('XSSMAP', new_value)

def find_word_occurrences_and_attributes(url, word):
    def describe_tag_location(tag, word):
        description = []
        while tag:
            if hasattr(tag, 'name'):
                tag_name = tag.name
                if tag_name == '[document]':
                    description.append("document")
                else:
                    if word_in_attributes(tag, word):
                        for attr in tag.attrs:
                            if word in str(tag[attr]):
                                description.append(f"{attr}:{tag_name}")
                    else:
                        description.append(tag_name)
            tag = tag.parent
        description.reverse()
        reversed_description = [element for element in reversed(description)]
        description_str = ','.join(reversed_description)
        return description_str
    
    def word_in_attributes(tag, word):
        for attr in tag.attrs:
            if isinstance(tag[attr], list):
                for val in tag[attr]:
                    if isinstance(val, str) and word in val:
                        return True
            elif isinstance(tag[attr], str) and word in tag[attr]:
                return True
        return False
    
    response = requests.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        
        occurrences = []
        occurrence_count = 0
        
        for tag in soup.find_all():
            if tag.name != 'script':
                text = tag.get_text()
                
                if word_in_attributes(tag, word):
                    occurrence_count += 1
                    tag_desc = describe_tag_location(tag, word)
                    occurrences.append(f"[{occurrence_count},{tag_desc}]")
                
                elif word in text:
                    occurrence_count += 1
                    tag_desc = describe_tag_location(tag, word)
                    occurrences.append(f"[{occurrence_count},{tag_desc}]")
        
        tags_set = set()
        attributes_set = set()
        
        for occurrence in occurrences:
            tag_desc = occurrence.split(',')[1:]
            tags_set.add(tag_desc[0].split(':')[0])
            
            for desc_part in tag_desc:
                if ':' in desc_part:
                    attributes_set.add(desc_part.split(':')[0])
        
        tags_list = list(tags_set)
        attributes_list = list(attributes_set)
        
        return occurrences, tags_list, attributes_list
    
    else:
        print(f"Failed to retrieve page: {response.status_code}")
        return [], [], []

def run_command(command):
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error: {result.stderr}")
        return result.stdout.splitlines()

def print_logo():
    ascii_art = """
▒██   ██▒  ██████   ██████  ███▄ ▄███▓ ▄▄▄       ██▓███  
▒▒ █ █ ▒░▒██    ▒ ▒██    ▒ ▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒
░░  █   ░░ ▓██▄   ░ ▓██▄   ▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒
 ░ █ █ ▒   ▒   ██▒  ▒   ██▒▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒
▒██▒ ▒██▒▒██████▒▒▒██████▒▒▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░
▒▒ ░ ░▓ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░
░░   ░▒ ░░ ░▒  ░ ░░ ░▒  ░ ░░  ░      ░  ▒   ▒▒ ░░▒ ░     
 ░    ░  ░  ░  ░  ░  ░  ░  ░      ░     ░   ▒   ░░       
 ░    ░        ░        ░         ░         ░  ░         
"""

        # ANSI escape code for red text
    RED = "\033[31m"
    RESET = "\033[0m"
    print(RED + ascii_art + RESET)

def main():
    parser = argparse.ArgumentParser(description="XSSmap URL processing script")
    parser.add_argument('-u', '--url', help='The target URL')
    parser.add_argument('-x', '--xss', help='URL to be processed with XSSMAP placeholder')
    parser.add_argument('--param', help='Parameter to test for XSS')
    parser.add_argument('--wordlist', help='Path to the wordlist file')
    parser.add_argument('--threads', type=int, help='Number of threads to use')
    args = parser.parse_args()

    if not args.url and not args.xss:
        print("")
        print_logo()
        print("")
        print("[\033[94mINF\033[0m] XSSmap v1.0.0 (\033[92mlatest\033[0m)")
        parser.print_help()
        return
    elif args.url and args.param and args.wordlist and args.threads:
        print("")
        print_logo()
        print("")
        print("[\033[94mINF\033[0m] XSSmap v1.0.0 (\033[92mlatest\033[0m)")

        url = args.url + '?' + args.param + '=XSSMAP'

        # Event to signal when XSS is found
        xss_found_event = threading.Event()

        def check_for_xss(url):
            options = Options()
            options.headless = True  # Set to True to run Firefox in headless mode
            service = Service('/home/kalili/.cargo/bin/geckodriver')  # Path to your GeckoDriver executable
            driver = webdriver.Firefox(service=service, options=options)

            try:
                # Open the URL
                driver.get(url)
                time.sleep(2)  # Adjust sleep time as necessary to ensure page loads completely

                # Check for alert with specific content
                alert = driver.switch_to.alert
                alert_text = alert.text

                if alert_text == 'XSSMAP':
                    return True  # XSS found
                else:
                    return False  # No XSS found

            except Exception as e:
                return False  # Return False if any error occurs

            finally:
                driver.quit()

        from urllib.parse import quote

        def evaluate_xss(urls, payload):
            if xss_found_event.is_set():
                return  # Skip further processing if XSS is already found
            
            payload = quote(payload)
            updated_url = urls.replace('XSSMAP', payload)
            result = check_for_xss(updated_url)
            
            if xss_found_event.is_set():
                return  # Check again before printing to ensure no output after XSS is found

            if result:
                print("\033[92m[ ! ] XSS FOUND !\033[0m")
                print(f"\033[92m[ ! ]\033[0m URL: \033[33m{urls}\033[0m")
                print(f"\033[92m[ ! ]\033[0m PAYLOAD: \033[92m{payload}\033[0m")
                
                # Set the event and run the custom function
                xss_found_event.set()
                interaction(url)
                return 'Go ----> Next'
            else:
                print(f"\033[31m[ ! ] XSS NOT FOUND using payload :\033[0m {payload}")

        def worker(url, queue):
            while True:
                if xss_found_event.is_set():
                    break  # Exit the loop if XSS is already found
                
                payload = queue.get()
                if payload is None:
                    break  # Exit the loop if there are no more payloads
                
                evaluate_xss(url, payload)
                queue.task_done()

        def main(url, wordlist_file, num_threads):
            with open(wordlist_file, 'r') as f:
                payloads = f.read().splitlines()

            # Create a queue to distribute payloads among threads
            queue = Queue()

            # Populate queue with payloads
            for payload in payloads:
                queue.put(payload)

            # Create and start threads
            threads = []
            for _ in range(num_threads):
                thread = threading.Thread(target=worker, args=(url, queue))
                thread.start()
                threads.append(thread)

            # Wait for all threads to complete
            queue.join()

            # Stop workers
            for _ in range(num_threads):
                queue.put(None)

            for thread in threads:
                thread.join()

        main(args.url + '?' + args.param + '=XSSMAP', args.wordlist, args.threads)

    elif args.xss:
        url = args.xss
        print(f"[\033[94mINF\033[0m] Target Url :  {url}")
        random_string = generate_random_string()
        print("[\033[92m + \033[0m] Generating random string: \033[92m" + random_string + "\033[0m")
        updated_url = replace_xssmap(url, random_string)
        word_to_find = random_string

        occurrences, tags, attributes = find_word_occurrences_and_attributes(updated_url, word_to_find)

        if occurrences:
            print(f"[\033[92m + \033[0m] Found [\033[92m {len(occurrences)} \033[0m] occurrences of '{word_to_find}' on the page:")
            for occurrence in occurrences:
                print(f"[\033[94mINF\033[0m]{occurrence}")

            print(f"[\033[94mINF\033[0m] Found [\033[92m {len(tags)} \033[0m] Unique HTML Tags:", end="")
            for tag in tags:
                print("\033[92m" + tag + "\033[0m", end=",")
            print("")

            print(f"[\033[94mINF\033[0m] Found [\033[92m {len(attributes)} \033[0m] Unique Attributes:", end="")
            for attribute in attributes:
                print("\033[92m" + attribute + "\033[0m", end=",")

        else:
            print(f"No occurrences found of '{word_to_find}' on the page.")

    elif args.url:
        target_url = args.url
        print("")
        print_logo()
        print("")
        print("[\033[94mINF\033[0m] XSSmap v1.0.0 (\033[92mlatest\033[0m)")

        print(f"[\033[94mINF\033[0m] Starting URL crawling with katana for {target_url} ...")
        katana_urls = run_command(["katana", "-u", target_url])
        print("[\033[94mINF\033[0m] URLs crawled with katana.")

        print(f"[\033[94mINF\033[0m] Starting URL crawling with waybackurls for {target_url} ...")
        wayback_urls = run_command(["waybackurls", target_url])
        print("[\033[94mINF\033[0m] URLs crawled with waybackurls.")

        print(f"[\033[94mINF\033[0m] Starting URL crawling with gau for {target_url} ...")
        gau_urls = run_command(["gau", target_url])
        print("[\033[94mINF\033[0m] URLs crawled with gau.")

        def filter_urls(urls):
            return [url for url in urls if url.startswith("http")]

        katana_urls = filter_urls(katana_urls)
        wayback_urls = filter_urls(wayback_urls)
        gau_urls = filter_urls(gau_urls)

        merged_urls = katana_urls + wayback_urls + gau_urls
        print("[\033[94mINF\033[0m] URLs successfully merged.")

        def check_alive_urls(urls):
            command = ["httpx-toolkit", "-status-code", "-mc", "200,302"]
            result = subprocess.run(command, input='\n'.join(urls), capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Error: {result.stderr}")
            return result.stdout.splitlines()

        print("[\033[94mINF\033[0m] Checking only for alive URLs.")
        alive_urls = check_alive_urls(merged_urls)
        print("[\033[94mINF\033[0m] Alive URLs checked.")

        def extract_urls(lines):
            urls = []
            for line in lines:
                url_match = re.search(r'(https?://\S+)', line)
                if url_match:
                    urls.append(url_match.group(1))
            return urls

        urls = extract_urls(alive_urls)
        print("[\033[94mINF\033[0m] Number of valid URLs extracted:", len(urls))

        def transform_url(url):
            parts = url.split("?")
            base_url = parts[0]
            if len(parts) > 1:
                query_params = parts[1]
                new_query_params = []
                for param in query_params.split("&"):
                    key_value = param.split("=")
                    if len(key_value) == 2:
                        key, value = key_value
                        if value != "random":
                            new_query_params.append(f"{key}=XSSMAP")
                        else:
                            new_query_params.append(f"{key}={value}")
                if new_query_params:
                    base_url += "?" + "&".join(new_query_params)
            return base_url

        transformed_urls = [transform_url(url) for url in urls]

        def remove_file_from_url(url):
            parts = url.split("/")
            if len(parts) > 3 and not any(parts[-1].endswith(extension) for extension in ['.php', '.html', '.aspx', '.json']):
                parts.pop()
            return "/".join(parts)

        urls_without_files = []
        for url in transformed_urls:
            if "?" not in url:
                urls_without_files.append(remove_file_from_url(url) + "/XSSMAP")
            else:
                urls_without_files.append(url)

        unique_urls = list(set(urls_without_files))
if __name__ == "__main__":
    main()
