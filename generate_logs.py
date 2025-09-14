import random
from datetime import datetime, timedelta

def random_ip():
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))

def random_timestamp(base_time):
    delta = timedelta(seconds=random.randint(1, 3600))
    return (base_time + delta).strftime('%b %d %H:%M:%S')

def generate_auth_log_entries(num_entries=50):
    users = ['root', 'admin', 'user1', 'guest']
    base_time = datetime.now().replace(minute=0, second=0, microsecond=0)
    log_entries = []
    
    for _ in range(num_entries):
        timestamp = random_timestamp(base_time)
        user = random.choice(users)
        ip = random_ip()
        # Randomly generate failed or successful attempt (focus on failed)
        # Here we generate mostly failed logins to simulate attacks
        entry = f"Sep {timestamp} server sshd[1234]: Failed password for {user} from {ip} port 22 ssh2"
        log_entries.append(entry)
    return log_entries

def generate_web_log_entries(num_entries=50):
    base_time = datetime.now().replace(minute=0, second=0, microsecond=0)
    urls = [
        "/admin.php?id=1", "/login.php", "/search.php?q=test", "/upload.php",
        "/backup.sql", "/../../../../etc/passwd", "/index.php", "/dashboard.php"
    ]
    user_agents = [
        "Mozilla/5.0", "sqlmap/1.4.7", "nikto/2.1.6", "curl/7.68.0", "Mozilla/4.0",
        "dirb/2.22", "gobuster/3.1"
    ]
    attack_patterns = [
        "' OR '1'='1", "<script>alert('xss')</script>", "../../../../etc/passwd", "; DROP TABLE users;", 
        "union select password from users", "alert(document.cookie)"
    ]
    log_entries = []
    
    for _ in range(num_entries):
        timestamp = random_timestamp(base_time)
        ip = random_ip()
        url = random.choice(urls)
        # Randomly inject attack patterns for simulating attacks
        if random.random() < 0.3:
            url += random.choice(attack_patterns)
        user_agent = random.choice(user_agents)
        
        log_entry = f'{ip} - - [{timestamp} +0000] "GET {url} HTTP/1.1" 200 1234 "-" "{user_agent}"'
        log_entries.append(log_entry)
    return log_entries

def write_log_file(filename, log_entries):
    with open(filename, 'w') as f:
        for entry in log_entries:
            f.write(entry + "\n")

if __name__ == "__main__":
    # Generate and save logs
    auth_log = generate_auth_log_entries()
    web_log = generate_web_log_entries()
    
    write_log_file("auth.log", auth_log)
    write_log_file("access.log", web_log)
    
    print("✅ Generated auth.log and access.log with random entries.")
