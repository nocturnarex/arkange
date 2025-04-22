#!/usr/bin/env python3
"""
ARKANGE - Nocturnarex
Version : 1.3
"""
import argparse, re, sys, os, gzip, zipfile, json, logging, signal, threading
from queue import Queue
from abc import ABC, abstractmethod
from pathlib import Path

import requests
from bs4 import BeautifulSoup

# --- CONFIGURATION ---
class Config:
    MAX_IDENT_LENGTH = 128
    REQUEST_TIMEOUT = 15
    MAX_THREADS = 8
    DUMP_EXTS = {'.txt', '.csv', '.json', '.gz', '.zip'}
    DEBUG = False
    MOCK_CRED = {'login': None, 'password': 'P@ssw0rd!', 'source': '[mock]'}

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='[ARKANGE] %(levelname)s: %(message)s')
logger = logging.getLogger()

# --- VALIDATION ---
class InputValidator:
    EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
    USER_RE  = re.compile(r'^[A-Za-z0-9_\-]{3,32}$')
    PHONE_RE = re.compile(r'^\+?[0-9]{7,15}$')
    @staticmethod
    def validate(ident, mode):
        if len(ident) > Config.MAX_IDENT_LENGTH:
            raise ValueError("Identifiant trop long")
        if mode == 'email' and not InputValidator.EMAIL_RE.match(ident):
            raise ValueError("Email invalide")
        if mode == 'user' and not InputValidator.USER_RE.match(ident):
            raise ValueError("Nom utilisateur invalide")
        if mode == 'phone' and not InputValidator.PHONE_RE.match(ident):
            raise ValueError("Numéro invalide")
        return ident

# --- SESSION FACTORY ---
def make_session():
    return requests.Session()

# --- SCRAPER BASE ---
class ScraperBase(ABC):
    @abstractmethod
    def search_urls(self, ident, session): ...
    @abstractmethod
    def extract_credentials(self, html): ...

CRED_PATTERN = re.compile(r'(?P<login>[\w.@+\-]+):(?P<password>[\w!@#$%^&*()\-_+=]+)')

# --- WEB SCRAPERS PUBLIC ÉTENDUS ---
class PastebinScraper(ScraperBase):
    URL = 'https://pastebin.com/search?q={}'
    def search_urls(self, i, s):
        r = s.get(self.URL.format(i), timeout=Config.REQUEST_TIMEOUT)
        soup = BeautifulSoup(r.text, 'html.parser')
        return [a['href'] for a in soup.select('div.search-result a')]
    def extract_credentials(self, html):
        return [m.groupdict() for m in CRED_PATTERN.finditer(html)]

class GhostbinScraper(PastebinScraper):
    URL = 'https://ghostbin.co/search?p={}'

class PasteeeScraper(PastebinScraper):
    URL = 'https://paste.ee/search?q={}'
    def search_urls(self, i, s):
        r = s.get(self.URL.format(i), timeout=Config.REQUEST_TIMEOUT)
        soup = BeautifulSoup(r.text, 'html.parser')
        return [a['href'] for a in soup.select('a.list-group-item')]

class HastebinScraper(PastebinScraper):
    URL = 'https://hastebin.com/search?q={}'

class WriteasScraper(PastebinScraper):
    URL = 'https://write.as/search?q={}'
    def search_urls(self, i, s):
        r = s.get(self.URL.format(i), timeout=Config.REQUEST_TIMEOUT)
        soup = BeautifulSoup(r.text, 'html.parser')
        return [a['href'] for a in soup.select('h2.title a')]

class GistScraper(ScraperBase):
    URL = 'https://gist.github.com/search?p=1&q={}'
    def search_urls(self, i, s):
        r = s.get(self.URL.format(i), timeout=Config.REQUEST_TIMEOUT)
        soup = BeautifulSoup(r.text, 'html.parser')
        return ['https://gist.github.com' + a['href'] for a in soup.select('a.link-overlay')]
    def extract_credentials(self, html):
        return [m.groupdict() for m in CRED_PATTERN.finditer(html)]

class PublicWWWScraper(PastebinScraper):
    URL = 'https://publicwww.com/websites/{}/'
    def search_urls(self, i, s):
        r = s.get(self.URL.format(i), timeout=Config.REQUEST_TIMEOUT)
        soup = BeautifulSoup(r.text, 'html.parser')
        return [a['href'] for a in soup.select('li.website a')]

class SnusbaseScraper(PastebinScraper):
    URL = 'https://snusbase.com/search?q={}'
    def search_urls(self, i, s):
        r = s.get(self.URL.format(i), timeout=Config.REQUEST_TIMEOUT)
        soup = BeautifulSoup(r.text, 'html.parser')
        return [a['href'] for a in soup.select('td a')]

class RedditScraper(ScraperBase):
    URL = 'https://api.pushshift.io/reddit/search/comment/?q={}&size=50'
    def search_urls(self, i, s):
        return []  # we use API response directly
    def extract_credentials(self, html):
        # html is JSON here
        data = json.loads(html)
        results = []
        for c in data.get('data', []):
            body = c.get('body', '')
            for m in CRED_PATTERN.finditer(body):
                cred = m.groupdict()
                cred['source'] = f"reddit://{c.get('link_id')}"
                results.append(cred)
        return results

class AnonPasteScraper(PastebinScraper):
    URL = 'https://anonpaste.org/search.php?query={}'
    def search_urls(self, i, s):
        r = s.post(self.URL.format(i), timeout=Config.REQUEST_TIMEOUT)
        soup = BeautifulSoup(r.text, 'html.parser')
        return [a['href'] for a in soup.select('a.paste-link')]

WEB_SCRAPERS = [
    PastebinScraper(), GhostbinScraper(), PasteeeScraper(),
    HastebinScraper(), WriteasScraper(), GistScraper(),
    PublicWWWScraper(), SnusbaseScraper(),
    RedditScraper(), AnonPasteScraper()
]

# --- DUMP SCANNER ---
class DumpScanner:
    def __init__(self, folder, ident):
        self.folder = Path(folder)
        self.ident = re.escape(ident)
        self.results = []
    def scan(self):
        for f in self.folder.rglob('*'):
            if f.suffix.lower() not in Config.DUMP_EXTS: continue
            try:
                if f.suffix == '.gz':
                    lines = gzip.open(f, 'rt', errors='ignore')
                elif f.suffix == '.zip':
                    with zipfile.ZipFile(f) as z:
                        for name in z.namelist():
                            txt = z.read(name).decode('utf-8', errors='ignore').splitlines()
                            self._scan(f, name, txt)
                    continue
                elif f.suffix in ('.txt','.csv'):
                    lines = open(f, 'r', errors='ignore')
                elif f.suffix == '.json':
                    data = json.load(open(f, 'r', errors='ignore'))
                    lines = json.dumps(data).splitlines()
                else:
                    continue
                self._scan(f, f.name, lines)
            except Exception as e:
                logger.warning(f"Erreur dump {f}: {e}")
    def _scan(self, fpath, name, lines):
        for idx, line in enumerate(lines, 1):
            if re.search(self.ident, line):
                self.results.append({
                    'login': re.sub(r':.*','',line.strip()),
                    'password': None,
                    'source': f"{fpath}:{name}:{idx}"
                })

# --- ORCHESTRATOR ---
class LeakSearcher:
    def __init__(self, ident, dump_folder, mock):
        self.ident = ident
        self.dump_folder = dump_folder
        self.mock = mock
        self.web_results = []
        self.dump_results = []

    def run(self):
        if self.dump_folder:
            ds = DumpScanner(self.dump_folder, self.ident)
            ds.scan()
            self.dump_results = ds.results
        if self.mock:
            logger.warning("[MOCK] simulation activée")
            self.web_results = [{**Config.MOCK_CRED, 'login': self.ident}]
        else:
            sess = make_session()
            q = Queue()
            for sc in WEB_SCRAPERS: q.put(sc)
            threads = []
            for _ in range(min(Config.MAX_THREADS, q.qsize())):
                t = threading.Thread(target=self._worker, args=(q, sess))
                t.daemon = True; t.start(); threads.append(t)
            q.join()
        self.print_summary()

    def _worker(self, q, session):
        while not q.empty():
            sc = q.get()
            try:
                urls = sc.search_urls(self.ident, session)
                if Config.DEBUG: print(f"[DEBUG] {sc.__class__.__name__} => {urls}")
                # for RedditScraper, urls list is empty, pass raw JSON text
                if isinstance(sc, RedditScraper):
                    r = session.get(sc.URL.format(self.ident), timeout=Config.REQUEST_TIMEOUT)
                    creds = sc.extract_credentials(r.text)
                    for c in creds:
                        logger.info(f"[LEAK] {c}")
                        self.web_results.append(c)
                else:
                    for u in urls:
                        try:
                            full = u if u.startswith('http') else u
                            r = session.get(full, timeout=Config.REQUEST_TIMEOUT)
                            creds = sc.extract_credentials(r.text)
                            for c in creds:
                                c['source'] = full
                                logger.info(f"[LEAK] {c}")
                                self.web_results.append(c)
                        except Exception as e:
                            logger.warning(f"{sc.__class__.__name__} URL {u} erreur {e}")
            except Exception as e:
                logger.error(f"{sc.__class__.__name__} erreur {e}")
            finally:
                q.task_done()

    def print_summary(self):
        all_results = self.dump_results + self.web_results
        if not all_results:
            print("\n⚠️ Aucune fuite trouvée. Utilisez --mock pour simuler.\n")
            return
        print("\n=== FUITES DÉTECTÉES ===")
        for c in all_results:
            pwd = c.get('password') or '[inconnu]'
            print(f" - {c['login']} : {pwd} (source: {c['source']})")
        print(f"\nTotal: {len(all_results)} fuite(s)\n")

# --- CLI & SIGNAL ---
def parse_args():
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('-e','--email', help='Email')
    g.add_argument('-u','--user',  help='Username')
    g.add_argument('-p','--phone', help='Phone')
    p.add_argument('--dump-folder', help='Dossier dumps locaux')
    p.add_argument('--mock', action='store_true', help='Mode démonstration')
    p.add_argument('--debug', action='store_true', help='Mode debug')
    return p.parse_args()

def setup_signal():
    def handler(sig, frame):
        print("\n[ARKANGE] Interrupt, exit.")
        sys.exit(0)
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

if __name__ == '__main__':
    args = parse_args()
    Config.DEBUG = args.debug
    mode = 'email' if args.email else 'user' if args.user else 'phone'
    ident = args.email or args.user or args.phone
    try:
        InputValidator.validate(ident, mode)
        setup_signal()
        searcher = LeakSearcher(ident,
                                dump_folder=args.dump_folder,
                                mock=args.mock)
        searcher.run()
    except Exception as exc:
        logger.error(f"[FATAL] {exc}")
        sys.exit(1)