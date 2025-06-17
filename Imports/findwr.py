import os
import re

default_paths = [
    '/var/www/html',  # Apache  Linux
    '/usr/share/nginx/html',  # Nginx  Linux
    'C:/xampp/htdocs',  # XAMPP  Windows
    'C:/wamp64/www',  # WAMP  Windows
    '/home/username/public_html',  # cPanel hosting
    '/var/www/vhosts/domain.com/httpdocs',  # Plesk hosting
    '/srv/http',  # Lighttpd Linux
    '/opt/lampp/htdocs',  # XAMPP  Linux
    'C:/inetpub/wwwroot',  # IIS  Windows
    '/usr/local/var/www',  # Lighttpd Linux
    '/var/www/tomcat/webapps',  # Tomcat (Apache Tomcat) Linux
    '/home/username/.node_modules',  # Node.js (with PHP-FPM) 
]

# Check DocumentRoot Apache
def get_apache_webroot(config_file='/etc/httpd/conf/httpd.conf'):
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            contents = f.read()
            match = re.search(r'DocumentRoot\s+"(.*)"', contents)
            if match:
                return match.group(1)
    return None

# Check root Nginx
def get_nginx_webroot(config_file='/etc/nginx/nginx.conf'):
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            contents = f.read()
            match = re.search(r'root\s+(.*);', contents)
            if match:
                return match.group(1)
    return None

# Check root IIS (Windows)
def get_iis_webroot(config_file='C:/Windows/System32/inetsrv/config/applicationHost.config'):
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            contents = f.read()
            match = re.search(r'<site name=".*" id=".*">.*?<physicalPath>(.*)</physicalPath>', contents, re.DOTALL)
            if match:
                return match.group(1)
    return None

# Check root Lighttpd
def get_lighttpd_webroot(config_file='/etc/lighttpd/lighttpd.conf'):
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            contents = f.read()
            match = re.search(r'document-root\s+(.*)', contents)
            if match:
                return match.group(1)
    return None

# Check root Caddy (Caddyfile)
def get_caddy_webroot(config_file='/etc/caddy/Caddyfile'):
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            contents = f.read()
            match = re.search(r'\s*root\s+(.*)', contents)
            if match:
                return match.group(1)
    return None

# Check root Cherokee (cherokee.conf)
def get_cherokee_webroot(config_file='/etc/cherokee/cherokee.conf'):
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            contents = f.read()
            match = re.search(r'root\s*=\s*(.*)', contents)
            if match:
                return match.group(1)
    return None

# Check root LiteSpeed (litespeed.conf)
def get_litespeed_webroot(config_file='/usr/local/lsws/conf/httpd_config.conf'):
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            contents = f.read()
            match = re.search(r'DocumentRoot\s+"(.*)"', contents)
            if match:
                return match.group(1)
    return None

# Check root Tomcat (server.xml)
def get_tomcat_webroot(config_file='/etc/tomcat9/server.xml'):
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            contents = f.read()
            match = re.search(r'(?<=<Host\s*name=".*"\s*appBase=")(.*?)(?=")', contents)
            if match:
                return match.group(1)
    return None

# Check default folder include PHP file
def check_default_paths_for_php(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.lower().endswith('.php'):
                        return path
    return None

def find_webroot():
    apache_root = get_apache_webroot()
    nginx_root = get_nginx_webroot()
    iis_root = get_iis_webroot()
    lighttpd_root = get_lighttpd_webroot()
    caddy_root = get_caddy_webroot()
    cherokee_root = get_cherokee_webroot()
    litespeed_root = get_litespeed_webroot()
    tomcat_root = get_tomcat_webroot()

    default_webroot = check_default_paths_for_php(default_paths)

    if apache_root:
        return f"Webroot Apache found: {apache_root}"
    elif nginx_root:
        return f"Webroot Nginx found: {nginx_root}"
    elif iis_root:
        return f"Webroot IIS found: {iis_root}"
    elif lighttpd_root:
        return f"Webroot Lighttpd found: {lighttpd_root}"
    elif caddy_root:
        return f"Webroot Caddy found: {caddy_root}"
    elif cherokee_root:
        return f"Webroot Cherokee found: {cherokee_root}"
    elif litespeed_root:
        return f"Webroot LiteSpeed found: {litespeed_root}"
    elif tomcat_root:
        return f"Webroot Tomcat found: {tomcat_root}"
    elif default_webroot:
        return f"Webroot is found include PHP: {default_webroot}"
    else:
        return "Not found webroot folder, please use manual search"
