
# checks the ip
def check_ip(text):
    parts = text.split(".") 
    if len(parts) != 4:     # 4 parts he ip me ya nhi
        return False
    
    for p in parts:
        if p.isdigit() == False:
            return False
        num = int(p)            # har part 0-255 ke beech me hai ya nhi
        if num < 0 or num > 255:
            return False
    return True

def get_extension(domain):
    if "." in domain:           #extension me dot h ya nhi
        return domain.split(".")[-1].lower()
    return ""                   #extension nhi ho to empty string return krdo

def check_url(url):
    points = 0                    #risk points store krne ke liye
    msg = []                    #list of msg

    # http / https check
    if not url.startswith("http"):
        url = "http://" + url

    if not url.startswith("https"):
        points += 2
        msg.append("Not using HTTPS")

    # length check
    if len(url) > 50:
        points += 1
        msg.append("URL too long")

    # @ symbol he ya nhi
    if "@" in url:
        points += 2
        msg.append("'@' found in URL")

    # too many - characters
    if url.count("-") >= 3:
        points += 1
        msg.append("Too many '-' characters")

    # get domain only
    if "://" in url:
        url = url.split("://")[1]
    if "/" in url:
        domain = url.split("/")[0]
    else:
        domain = url

    # IP address check
    if check_ip(domain):
        points += 3
        msg.append("Domain looks like IP address")

    # Suspicious words
    bad_words = ["verify", "update", "login", "bank", "password", "confirm"]
    for word in bad_words:
        if word in url.lower():
            points += 2
            msg.append("Suspicious word found: " + word)
            break

    #  check Extension 
    bad_extension = ["xyz", "pw", "top", "click", "fit"]
    ext = get_extension(domain)
    if ext in bad_extension:
        points += 2
        msg.append("Suspicious extension: ." + ext)

    # Result category
    if points <= 2:
        status = "SAFE"
    elif points <= 5:
        status = "SUSPICIOUS"
    else:
        status = "HIGH RISK"

    return status, points, msg


# -------- MAIN PROGRAM --------

print("URL CHECKER")
url = input("Enter URL: ")

status, score, info = check_url(url)    #status = safe/suspicious/high risk, score = points, info = msg list

print("\nResult:", status)
print("Score:", score)
print("\nDetails:")

if len(info) == 0:
    print("No problem found")
else:
    for i in range(len(info)):
        print(str(i+1) + ". " + info[i])

# result file me store krna
file = open("log.txt", "a")
file.write(url + " | " + status + " | Score: " + str(score) + "\n")#log file me url, status and score store krdo
file.close()
