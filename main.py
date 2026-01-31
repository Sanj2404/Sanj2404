#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import feedparser
import threading
import json
import requests
from datetime import datetime, timedelta
import webbrowser
import re


class CyberSecNewsViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("Kali Linux Cybersecurity News")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')

        # RSS feeds
        self.feeds = {
            "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
            "Krebs on Security": "https://krebsonsecurity.com/feed/",
            "ThreatPost": "https://threatpost.com/feed/",
            "SecurityWeek": "https://feeds.feedburner.com/securityweek",
            "Dark Reading": "https://www.darkreading.com/rss_simple.asp",
            "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
            "CISA Alerts": "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml",
            "Packet Storm": "https://rss.packetstormsecurity.com/news/",
            "SANS ISC": "https://isc.sans.edu/rssfeed_full.xml"
        }

        self.setup_ui()
        self.load_news()

    def setup_ui(self):
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')

        # Colors
        bg_color = '#1e1e1e'
        fg_color = '#ffffff'
        accent_color = '#00ff00'

        # Main frame
        main_frame = tk.Frame(self.root, bg=bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Title
        title = tk.Label(main_frame,
                         text="🔒 Kali Linux Cybersecurity News Dashboard",
                         font=("Courier", 18, "bold"),
                         bg=bg_color,
                         fg=accent_color)
        title.pack(pady=(0, 10))

        # Control frame
        control_frame = tk.Frame(main_frame, bg=bg_color)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        # Refresh button
        refresh_btn = tk.Button(control_frame,
                                text="🔄 Refresh All",
                                command=self.load_news,
                                bg='#333',
                                fg=fg_color,
                                font=("Arial", 10, "bold"),
                                relief=tk.FLAT)
        refresh_btn.pack(side=tk.LEFT, padx=(0, 10))

        # Source selection
        tk.Label(control_frame,
                 text="Source:",
                 bg=bg_color,
                 fg=fg_color).pack(side=tk.LEFT, padx=(20, 5))

        self.source_var = tk.StringVar(value="All Sources")
        source_menu = ttk.Combobox(control_frame,
                                   textvariable=self.source_var,
                                   values=["All Sources"] + list(self.feeds.keys()),
                                   state="readonly",
                                   width=20)
        source_menu.pack(side=tk.LEFT)
        source_menu.bind('<<ComboboxSelected>>', self.filter_news)

        # CVE Source selection
        tk.Label(control_frame,
                 text="CVE Source:",
                 bg=bg_color,
                 fg=fg_color).pack(side=tk.LEFT, padx=(20, 5))

        self.cve_source_var = tk.StringVar(value="NVD RSS")
        cve_sources = ["NVD RSS", "CIRCL API", "MITRE", "Multiple Sources"]
        cve_source_menu = ttk.Combobox(control_frame,
                                       textvariable=self.cve_source_var,
                                       values=cve_sources,
                                       state="readonly",
                                       width=15)
        cve_source_menu.pack(side=tk.LEFT)
        cve_source_menu.bind('<<ComboboxSelected>>', self.change_cve_source)

        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create tabs
        self.news_tab = tk.Frame(self.notebook, bg=bg_color)
        self.cve_tab = tk.Frame(self.notebook, bg=bg_color)
        self.tools_tab = tk.Frame(self.notebook, bg=bg_color)
        self.status_tab = tk.Frame(self.notebook, bg=bg_color)

        self.notebook.add(self.news_tab, text="📰 News")
        self.notebook.add(self.cve_tab, text="⚠️ CVEs")
        self.notebook.add(self.tools_tab, text="🛠️ Tools")
        self.notebook.add(self.status_tab, text="📊 Status")

        # Setup all tabs
        self.setup_news_tab()
        self.setup_cve_tab()
        self.setup_tools_tab()
        self.setup_status_tab()

    def setup_news_tab(self):
        # Text widget for news display
        self.news_text = scrolledtext.ScrolledText(self.news_tab,
                                                   wrap=tk.WORD,
                                                   bg='#2d2d2d',
                                                   fg='#ffffff',
                                                   font=("Monospace", 10),
                                                   relief=tk.FLAT)
        self.news_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Configure tags for formatting
        self.news_text.tag_config('title', foreground='#00ff00', font=("Monospace", 11, "bold"))
        self.news_text.tag_config('source', foreground='#ff9900')
        self.news_text.tag_config('date', foreground='#cccccc')
        self.news_text.tag_config('link', foreground='#3399ff', underline=1)

        # Bind click event for links
        self.news_text.tag_bind('link', '<Button-1>', self.open_link)

    def setup_cve_tab(self):
        # Frame for CVE controls
        cve_control_frame = tk.Frame(self.cve_tab, bg='#1e1e1e')
        cve_control_frame.pack(fill=tk.X, padx=5, pady=5)

        # CVE refresh button
        cve_refresh_btn = tk.Button(cve_control_frame,
                                    text="🔄 Refresh CVEs",
                                    command=self.load_cves,
                                    bg='#333',
                                    fg='#ffffff',
                                    font=("Arial", 9, "bold"))
        cve_refresh_btn.pack(side=tk.LEFT, padx=(0, 10))

        # CVE count filter
        tk.Label(cve_control_frame,
                 text="Show:",
                 bg='#1e1e1e',
                 fg='#ffffff').pack(side=tk.LEFT, padx=(10, 5))

        self.cve_count_var = tk.StringVar(value="10")
        cve_count_menu = ttk.Combobox(cve_control_frame,
                                      textvariable=self.cve_count_var,
                                      values=["5", "10", "15", "20", "50"],
                                      state="readonly",
                                      width=5)
        cve_count_menu.pack(side=tk.LEFT)
        cve_count_menu.bind('<<ComboboxSelected>>', lambda e: self.load_cves())

        # CVE display
        self.cve_text = scrolledtext.ScrolledText(self.cve_tab,
                                                  wrap=tk.WORD,
                                                  bg='#2d2d2d',
                                                  fg='#ffffff',
                                                  font=("Monospace", 10))
        self.cve_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Configure CVE severity tags
        self.cve_text.tag_config('critical', foreground='#ff0000', font=("Monospace", 11, "bold"))
        self.cve_text.tag_config('high', foreground='#ff6600', font=("Monospace", 10, "bold"))
        self.cve_text.tag_config('medium', foreground='#ffff00')
        self.cve_text.tag_config('low', foreground='#00ff00')
        self.cve_text.tag_config('unknown', foreground='#cccccc')
        self.cve_text.tag_config('cve_id', foreground='#00ffff')
        self.cve_text.tag_config('info', foreground='#888888', font=("Monospace", 9))

    def setup_tools_tab(self):
        tools_frame = tk.Frame(self.tools_tab, bg='#1e1e1e')
        tools_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # CVE Tools Section
        cve_section = tk.LabelFrame(tools_frame, text="🔍 CVE Tools", bg='#2d2d2d', fg='#00ff00',
                                    font=("Arial", 12, "bold"))
        cve_section.pack(fill=tk.X, pady=(0, 10))

        cve_tools = [
            ("searchsploit", "searchsploit apache 2.4", "Search Exploit-DB for vulnerabilities"),
            ("cve_searchsploit", "cve_searchsploit CVE-2024-1234", "Search for specific CVE"),
            ("nmap NSE", "nmap --script vuln <target>", "Scan for vulnerabilities"),
            ("metasploit", "msfconsole -x 'search cve:2024'", "Search Metasploit modules"),
        ]

        for tool, cmd, desc in cve_tools:
            frame = tk.Frame(cve_section, bg='#3d3d3d', relief=tk.RAISED, bd=1)
            frame.pack(fill=tk.X, pady=2, padx=5)

            tk.Label(frame, text=tool, bg='#3d3d3d', fg='#00ff00',
                     font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=5, pady=(2, 0))
            tk.Label(frame, text=cmd, bg='#3d3d3d', fg='#ffffff',
                     font=("Courier", 9)).pack(anchor=tk.W, padx=5)
            tk.Label(frame, text=desc, bg='#3d3d3d', fg='#cccccc',
                     font=("Arial", 8)).pack(anchor=tk.W, padx=5, pady=(0, 2))

        # RSS Tools Section
        rss_section = tk.LabelFrame(tools_frame, text="📰 RSS Tools", bg='#2d2d2d', fg='#00ff00',
                                    font=("Arial", 12, "bold"))
        rss_section.pack(fill=tk.X, pady=(10, 0))

        rss_tools = [
            ("newsboat", "newsboat", "Terminal RSS reader"),
            ("feedreader", "feedreader", "GUI RSS reader"),
            ("twint", "twint -u TheHackersNews --limit 10", "Twitter intelligence"),
            ("rss2email", "r2e", "RSS to email"),
        ]

        for tool, cmd, desc in rss_tools:
            frame = tk.Frame(rss_section, bg='#3d3d3d', relief=tk.RAISED, bd=1)
            frame.pack(fill=tk.X, pady=2, padx=5)

            tk.Label(frame, text=tool, bg='#3d3d3d', fg='#00ff00',
                     font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=5, pady=(2, 0))
            tk.Label(frame, text=cmd, bg='#3d3d3d', fg='#ffffff',
                     font=("Courier", 9)).pack(anchor=tk.W, padx=5)
            tk.Label(frame, text=desc, bg='#3d3d3d', fg='#cccccc',
                     font=("Arial", 8)).pack(anchor=tk.W, padx=5, pady=(0, 2))

    def setup_status_tab(self):
        status_frame = tk.Frame(self.status_tab, bg='#1e1e1e')
        status_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Status indicators
        self.status_text = scrolledtext.ScrolledText(status_frame,
                                                     wrap=tk.WORD,
                                                     bg='#2d2d2d',
                                                     fg='#ffffff',
                                                     font=("Monospace", 10))
        self.status_text.pack(fill=tk.BOTH, expand=True)

        self.status_text.tag_config('success', foreground='#00ff00')
        self.status_text.tag_config('error', foreground='#ff0000')
        self.status_text.tag_config('warning', foreground='#ffff00')
        self.status_text.tag_config('info', foreground='#3399ff')

        # Check status button
        check_btn = tk.Button(status_frame,
                              text="🔄 Check All Sources",
                              command=self.check_status,
                              bg='#333',
                              fg='#ffffff',
                              font=("Arial", 10, "bold"))
        check_btn.pack(pady=10)

    def load_news(self):
        def fetch():
            self.news_text.delete(1.0, tk.END)
            self.news_text.insert(tk.END, "Fetching cybersecurity news...\n\n", 'title')

            selected_source = self.source_var.get()
            sources_to_fetch = self.feeds.items() if selected_source == "All Sources" else \
                [(selected_source, self.feeds[selected_source])]

            for source, url in sources_to_fetch:
                self.news_text.insert(tk.END, f"\n【 {source} 】\n", 'source')

                try:
                    feed = feedparser.parse(url)
                    if len(feed.entries) > 0:
                        for i, entry in enumerate(feed.entries[:5]):
                            title = entry.get('title', 'No title')
                            title = title[:100] + "..." if len(title) > 100 else title
                            date = entry.get('published', entry.get('updated', 'No date'))
                            link = entry.get('link', '#')

                            self.news_text.insert(tk.END, f"\n{i + 1}. {title}\n", 'title')
                            self.news_text.insert(tk.END, f"   📅 {date}\n", 'date')
                            self.news_text.insert(tk.END, f"   🔗 {link}\n", 'link')
                            self.news_text.insert(tk.END, "\n")
                    else:
                        self.news_text.insert(tk.END, "  No articles found\n", 'info')
                except Exception as e:
                    self.news_text.insert(tk.END, f"  Error: {str(e)}\n", 'error')

            # Load CVEs in background
            self.load_cves()

        threading.Thread(target=fetch, daemon=True).start()

    def load_cves(self):
        self.cve_text.delete(1.0, tk.END)
        self.cve_text.insert(tk.END, "Fetching CVE data...\n\n", 'title')

        try:
            cve_count = int(self.cve_count_var.get())
            source = self.cve_source_var.get()

            if source == "Multiple Sources":
                self.get_cves_multiple_sources(cve_count)
            elif source == "NVD RSS":
                self.get_cves_nvd_rss(cve_count)
            elif source == "CIRCL API":
                self.get_cves_circl(cve_count)
            elif source == "MITRE":
                self.get_cves_mitre(cve_count)

        except Exception as e:
            self.cve_text.insert(tk.END, f"Error loading CVEs: {str(e)}\n", 'error')

    def get_cves_nvd_rss(self, count=10):
        """Get CVEs from NVD RSS feed"""
        try:
            self.cve_text.insert(tk.END, "=== NVD RSS Feed ===\n\n", 'title')

            # Try multiple NVD RSS feeds
            rss_urls = [
                "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
                "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-recent.xml",
                "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"
            ]

            for rss_url in rss_urls:
                try:
                    feed = feedparser.parse(rss_url)
                    if feed.entries:
                        for i, entry in enumerate(feed.entries[:count]):
                            title = entry.get('title', '')
                            summary = entry.get('summary', '')
                            link = entry.get('link', '')
                            published = entry.get('published', '')

                            # Extract CVE ID
                            cve_match = re.search(r'(CVE-\d{4}-\d+)', title)
                            cve_id = cve_match.group(1) if cve_match else "Unknown"

                            # Determine severity
                            severity_tag = 'unknown'
                            severity = "UNKNOWN"

                            if 'CRITICAL' in title.upper():
                                severity_tag = 'critical'
                                severity = "CRITICAL"
                            elif 'HIGH' in title.upper():
                                severity_tag = 'high'
                                severity = "HIGH"
                            elif 'MEDIUM' in title.upper():
                                severity_tag = 'medium'
                                severity = "MEDIUM"
                            elif 'LOW' in title.upper():
                                severity_tag = 'low'
                                severity = "LOW"

                            self.cve_text.insert(tk.END, f"{cve_id}\n", severity_tag)
                            self.cve_text.insert(tk.END, f"  Severity: {severity}\n", 'cve_id')
                            self.cve_text.insert(tk.END, f"  Published: {published}\n", 'info')

                            # Clean up description
                            desc = re.sub('<[^<]+?>', '', summary)
                            desc = desc.replace('\n', ' ').strip()
                            if desc:
                                self.cve_text.insert(tk.END, f"  {desc[:150]}...\n", 'info')

                            self.cve_text.insert(tk.END, f"  Link: {link}\n\n", 'info')

                        if i > 0:  # If we got data, break
                            return True

                except Exception as e:
                    continue

            self.cve_text.insert(tk.END, "No CVEs found in RSS feeds\n", 'warning')
            return False

        except Exception as e:
            self.cve_text.insert(tk.END, f"Error with NVD RSS: {str(e)}\n", 'error')
            return False

    def get_cves_circl(self, count=10):
        """Get CVEs from CIRCL API"""
        try:
            self.cve_text.insert(tk.END, "=== CIRCL CVE Database ===\n\n", 'title')

            response = requests.get(f"https://cve.circl.lu/api/last/{count}", timeout=15)

            if response.status_code == 200:
                data = response.json()

                if data:
                    for cve in data:
                        cve_id = cve.get('id', 'Unknown')
                        summary = cve.get('summary', 'No description')
                        published = cve.get('Published', 'Unknown')
                        cvss = cve.get('cvss', 'N/A')

                        # Determine severity from CVSS score
                        try:
                            cvss_num = float(cvss) if cvss != 'N/A' else 0
                            if cvss_num >= 9.0:
                                severity_tag = 'critical'
                            elif cvss_num >= 7.0:
                                severity_tag = 'high'
                            elif cvss_num >= 4.0:
                                severity_tag = 'medium'
                            elif cvss_num > 0:
                                severity_tag = 'low'
                            else:
                                severity_tag = 'unknown'
                        except:
                            severity_tag = 'unknown'

                        self.cve_text.insert(tk.END, f"{cve_id}\n", severity_tag)
                        self.cve_text.insert(tk.END, f"  CVSS: {cvss} | Published: {published}\n", 'cve_id')
                        self.cve_text.insert(tk.END, f"  {summary[:150]}...\n\n", 'info')

                    return True
                else:
                    self.cve_text.insert(tk.END, "No CVEs found in CIRCL database\n", 'warning')
                    return False
            else:
                self.cve_text.insert(tk.END, f"API Error: {response.status_code}\n", 'error')
                return False

        except Exception as e:
            self.cve_text.insert(tk.END, f"Error with CIRCL API: {str(e)}\n", 'error')
            return False

    def get_cves_mitre(self, count=10):
        """Get CVEs from MITRE"""
        try:
            self.cve_text.insert(tk.END, "=== MITRE CVE List ===\n\n", 'title')

            # MITRE CSV feed
            response = requests.get("https://cve.mitre.org/data/downloads/allitems.csv", timeout=15)

            if response.status_code == 200:
                lines = response.text.split('\n')
                cve_count = 0

                for line in lines[1:]:  # Skip header
                    if cve_count >= count:
                        break

                    parts = line.split(',')
                    if len(parts) >= 2:
                        cve_id = parts[0].strip('"')
                        description = parts[1].strip('"')

                        if cve_id.startswith('CVE-'):
                            self.cve_text.insert(tk.END, f"{cve_id}\n", 'cve_id')
                            self.cve_text.insert(tk.END, f"  {description[:150]}...\n\n", 'info')
                            cve_count += 1

                if cve_count > 0:
                    return True
                else:
                    self.cve_text.insert(tk.END, "No CVEs found in MITRE database\n", 'warning')
                    return False
            else:
                self.cve_text.insert(tk.END, f"Error fetching MITRE data: {response.status_code}\n", 'error')
                return False

        except Exception as e:
            self.cve_text.insert(tk.END, f"Error with MITRE: {str(e)}\n", 'error')
            return False

    def get_cves_multiple_sources(self, count=10):
        """Try multiple sources to get CVEs"""
        self.cve_text.insert(tk.END, "=== Trying Multiple Sources ===\n\n", 'title')

        sources = [
            ("NVD RSS", self.get_cves_nvd_rss),
            ("CIRCL API", self.get_cves_circl),
            ("MITRE", self.get_cves_mitre)
        ]

        success = False
        for source_name, source_func in sources:
            try:
                self.cve_text.insert(tk.END, f"\nTrying {source_name}...\n", 'info')
                if source_func(min(5, count)):
                    success = True
                    break
            except:
                continue

        if not success:
            self.cve_text.insert(tk.END, "\n⚠️ All CVE sources failed. Try:\n", 'warning')
            self.cve_text.insert(tk.END, "1. Check internet connection\n", 'info')
            self.cve_text.insert(tk.END, "2. Use local tools: searchsploit --update\n", 'info')
            self.cve_text.insert(tk.END, "3. Visit: https://nvd.nist.gov/vuln/search\n", 'info')

    def filter_news(self, event):
        self.load_news()

    def change_cve_source(self, event):
        self.load_cves()

    def check_status(self):
        def check():
            self.status_text.delete(1.0, tk.END)
            self.status_text.insert(tk.END, "Checking source status...\n\n", 'title')

            # Check RSS feeds
            self.status_text.insert(tk.END, "📰 RSS Feeds:\n", 'info')
            for source, url in self.feeds.items():
                try:
                    feed = feedparser.parse(url)
                    if hasattr(feed, 'entries'):
                        status = f"  ✓ {source}: {len(feed.entries)} articles\n"
                        self.status_text.insert(tk.END, status, 'success')
                    else:
                        self.status_text.insert(tk.END, f"  ✗ {source}: No entries\n", 'error')
                except Exception as e:
                    self.status_text.insert(tk.END, f"  ✗ {source}: Error - {str(e)[:50]}...\n", 'error')

            # Check CVE sources
            self.status_text.insert(tk.END, "\n⚠️ CVE Sources:\n", 'info')

            # Check NVD
            try:
                response = requests.get("https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml", timeout=10)
                if response.status_code == 200:
                    self.status_text.insert(tk.END, "  ✓ NVD RSS: Accessible\n", 'success')
                else:
                    self.status_text.insert(tk.END, f"  ✗ NVD RSS: HTTP {response.status_code}\n", 'error')
            except Exception as e:
                self.status_text.insert(tk.END, f"  ✗ NVD RSS: Error\n", 'error')

            # Check CIRCL
            try:
                response = requests.get("https://cve.circl.lu/api/last/1", timeout=10)
                if response.status_code == 200:
                    self.status_text.insert(tk.END, "  ✓ CIRCL API: Accessible\n", 'success')
                else:
                    self.status_text.insert(tk.END, f"  ✗ CIRCL API: HTTP {response.status_code}\n", 'error')
            except Exception as e:
                self.status_text.insert(tk.END, "  ✗ CIRCL API: Error\n", 'error')

            # Local tools check
            self.status_text.insert(tk.END, "\n🛠️ Local Tools:\n", 'info')

            import subprocess
            tools_to_check = [
                ("python3", "--version"),
                ("curl", "--version"),
                ("jq", "--version"),
                ("xmlstarlet", "--version"),
            ]

            for tool, arg in tools_to_check:
                try:
                    result = subprocess.run([tool, arg], capture_output=True, text=True)
                    if result.returncode == 0:
                        version = result.stdout.split('\n')[0] if result.stdout else "Installed"
                        self.status_text.insert(tk.END, f"  ✓ {tool}: {version[:30]}...\n", 'success')
                    else:
                        self.status_text.insert(tk.END, f"  ✗ {tool}: Not installed\n", 'warning')
                except:
                    self.status_text.insert(tk.END, f"  ✗ {tool}: Not installed\n", 'warning')

        threading.Thread(target=check, daemon=True).start()

    def open_link(self, event):
        # Get the click position
        index = self.news_text.index(f"@{event.x},{event.y}")

        # Check if click is on a link
        tags = self.news_text.tag_names(index)
        if 'link' in tags:
            # Get the link text
            start = f"{index} linestart"
            end = f"{index} lineend"
            line = self.news_text.get(start, end)

            # Extract URL
            url_match = re.search(r'https?://[^\s]+', line)
            if url_match:
                webbrowser.open(url_match.group(0))


def main():
    root = tk.Tk()
    app = CyberSecNewsViewer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
