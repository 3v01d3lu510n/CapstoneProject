import os
import re
from string import ascii_uppercase
from ctypes import windll

home_dir = os.path.expanduser("~")

default_paths = [
    "/var/www/html",
    "/usr/share/nginx/html",
    "/xampp/htdocs",
    "X:/wamp64/www",
    os.path.join(home_dir, "public_html"),
    "/var/www/vhosts/domain.com/httpdocs",
    "/srv/http",
    "/opt/lampp/htdocs",
    "X:/inetpub/wwwroot",  
    "/usr/local/var/www",
    "/var/www/tomcat/webapps",
    os.path.join(home_dir, ".node_modules"),
]

def expand_windows_drives(paths: list[str]) -> list[str]:
    if os.name != "nt":
        return paths

    bitmask = windll.kernel32.GetLogicalDrives()
    drives = [f"{d}:/" for i, d in enumerate(ascii_uppercase) if bitmask & (1 << i)]

    expanded: set[str] = set()
    for path in paths:
        p = path.replace("\\", "/")
        rel = re.sub(r"^[A-Z]:/", "", p, flags=re.IGNORECASE)
        rel = rel.lstrip("/")
        for drive in drives:
            candidate = os.path.join(drive, rel).replace("\\", "/")
            expanded.add(candidate)
    return sorted(expanded)

def get_apache_webroot(config_file: str = "/etc/httpd/conf/httpd.conf") -> str | None:
    if os.path.exists(config_file):
        content = open(config_file, "r").read()
        if m := re.search(r"DocumentRoot\s+\"(.*)\"", content):
            return m.group(1)
    return None

def get_nginx_webroot(config_file: str = "/etc/nginx/nginx.conf") -> str | None:
    if os.path.exists(config_file):
        content = open(config_file, "r").read()
        if m := re.search(r"root\s+(.*);", content):
            return m.group(1)
    return None

def get_iis_webroot(config_file: str = "C:/Windows/System32/inetsrv/config/applicationHost.config") -> str | None:
    if os.path.exists(config_file):
        content = open(config_file, "r").read()
        if m := re.search(r"<site name=\".*\" id=\".*\">.*?<physicalPath>(.*)</physicalPath>", content, re.DOTALL):
            return m.group(1)
    return None

def get_lighttpd_webroot(config_file: str = "/etc/lighttpd/lighttpd.conf") -> str | None:
    if os.path.exists(config_file):
        content = open(config_file, "r").read()
        if m := re.search(r"document-root\s+(.*)", content):
            return m.group(1)
    return None

def get_caddy_webroot(config_file: str = "/etc/caddy/Caddyfile") -> str | None:
    if os.path.exists(config_file):
        content = open(config_file, "r").read()
        if m := re.search(r"\s*root\s+(.*)", content):
            return m.group(1)
    return None

def get_cherokee_webroot(config_file: str = "/etc/cherokee/cherokee.conf") -> str | None:
    if os.path.exists(config_file):
        content = open(config_file, "r").read()
        if m := re.search(r"root\s*=\s*(.*)", content):
            return m.group(1)
    return None

def get_litespeed_webroot(config_file: str = "/usr/local/lsws/conf/httpd_config.conf") -> str | None:
    if os.path.exists(config_file):
        content = open(config_file, "r").read()
        if m := re.search(r"DocumentRoot\s+\"(.*)\"", content):
            return m.group(1)
    return None

def get_tomcat_webroot(config_file: str = "/etc/tomcat9/server.xml") -> str | None:
    if os.path.exists(config_file):
        content = open(config_file, "r").read()
        if m := re.search(r"(?<=<Host\s*name=\".*\"\s*appBase=\")(.*?)(?=\")", content):
            return m.group(1)
    return None

def check_default_paths_for_php(paths: list[str]) -> str | None:
    for path in paths:
        if os.path.isdir(path):
            for _root, _dirs, files in os.walk(path):
                if any(f.lower().endswith(".php") for f in files):
                    return path
    return None

def find_webroot() -> str:
    webroot = (
        get_apache_webroot()
        or get_nginx_webroot()
        or get_iis_webroot()
        or get_lighttpd_webroot()
        or get_caddy_webroot()
        or get_cherokee_webroot()
        or get_litespeed_webroot()
        or get_tomcat_webroot()
        or check_default_paths_for_php(expand_windows_drives(default_paths))
    )
    return webroot or "Not found webroot folder, please use manual search"
