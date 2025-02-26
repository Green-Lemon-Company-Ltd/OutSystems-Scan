from colorama import Fore, Style
import commons
import outputToJson

# Open wordlist file
with open("wordlist/ScreenNames.txt", "r") as file_screen_wordlist:
    # read content of file
    wordlist_screen_names = file_screen_wordlist.readlines()

# Close file
file_screen_wordlist.close()

# Remove spaces between words
wordlist_screen_names = [word.strip() for word in wordlist_screen_names]

def check_screenName(screen_name):
    for word in wordlist_screen_names:
       if word.lower() in screen_name.lower():
           return True
    return False

def get_all_pages(data,environment_url):
    # No comments
    potential_screen_found = False
    
    # Extract the list "urlMappings"
    url_mappings = data["manifest"]["urlMappings"]
    # Access dictionary keys
    for key in url_mappings.keys():
        # Check if the word "moduleservices" is in the key
        if "moduleservices" not in key.lower():
            # Check if the word "test" or "tests" is in the key
            if check_screenName(key.lower()):
                # Print the key in green
                
                # print(f"| {Fore.WHITE}[200]{Style.RESET_ALL} {Fore.YELLOW}[WARNING] {environment_url}{key}{Style.RESET_ALL}")

                # ---------- START OF CHANGED CODE ---------- #
                
                vulnerabilityName = "Potential Test Screens Found"
                screen = f"{environment_url}{key}"
                outputToJson.getTestScreensToJson(vulnerabilityName,screen)
                
                # ---------- END OF CHANGED CODE ---------- #

                if not potential_screen_found:
                    potential_screen_found = True
            else:
                # Print the key normally
                # print(f"| {Fore.WHITE}[200] {Style.DIM}{environment_url}{key}{Style.RESET_ALL}")

                # ---------- START OF CHANGED CODE ---------- #
        
                vulnerabilityName = "Screen Enumeration"
                screen = f"{environment_url}{key}"
                outputToJson.getScreensToJson(vulnerabilityName,screen)
                
                # ---------- END OF CHANGED CODE ---------- #
                
    # if potential_screen_found:
    #     print(f"{Fore.RED}[i] {commons.get_current_datetime()} Potentially vulnerable test screens were found in{Style.RESET_ALL} {Fore.YELLOW}yellow{Style.RESET_ALL} {Fore.RED}above.{Style.RESET_ALL}")
    #     print(f"{Fore.RED}[i] {commons.get_current_datetime()} Soon you will be able to use other commands to perform a full page scan.{Style.RESET_ALL}")