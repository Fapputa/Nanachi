#!/usr/bin/env python3
"""
prushka.py - Analyseur de chaînes multiformat avec scoring de lisibilité
"""

import sys
import string
import binascii
import base64
import hashlib
import re
import math
import itertools
import concurrent.futures
from math import gcd

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[31m"
    RED2   = "\033[91m"
    GREEN  = "\033[32m"
    GREEN2 = "\033[92m"
    WHITE  = "\033[97m"
    GREY   = "\033[90m"
    YELLOW = "\033[33m"
    CYAN   = "\033[36m"

def c(color, text):
    return f"{color}{text}{C.RESET}"

import threading
import time as _time

class Progress:
    def __init__(self):
        self.ops_done   = 0
        self.ops_total  = 0
        self.start_time = None
        self.collector  = None
        self._lock      = threading.Lock()
        self._stop      = threading.Event()
        self._thread    = None
        self._quit_flag = False
        self._old_term  = None

    def start(self, ops_total, collector):
        self.ops_total  = ops_total
        self.collector  = collector
        self.start_time = _time.monotonic()
        self._stop.clear()
        self._thread = threading.Thread(target=self._keyboard_listener, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def should_quit(self):
        return self._quit_flag

    def tick(self, n=1):
        with self._lock:
            self.ops_done += n

    def _keyboard_listener(self):
        try:
            import tty, termios, select
            fd  = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            self._old_term = (fd, old)
            tty.setcbreak(fd)
            try:
                while not self._stop.is_set():
                    if select.select([sys.stdin], [], [], 0.1)[0]:
                        ch = sys.stdin.read(1)
                        if ch.lower() == 's':
                            self._print_status()
                        elif ch.lower() == 'q':
                            sys.stderr.write(
                                "\n" + C.RED + "  ⛔ Arrêt demandé — affichage des résultats..." + C.RESET + "\n\n"
                            )
                            sys.stderr.flush()
                            self._quit_flag = True
                            self._stop.set()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
                self._old_term = None
        except Exception:
            pass

    def restore_terminal(self):
        try:
            import termios
            if self._old_term is not None:
                fd, old = self._old_term
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
                self._old_term = None
                return
            fd = sys.stdin.fileno()
            attrs = termios.tcgetattr(fd)
            attrs[3] |= termios.ECHO | termios.ICANON
            termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
        except Exception:
            pass

    def _print_status(self):
        now     = _time.monotonic()
        elapsed = now - self.start_time if self.start_time else 0
        done    = self.ops_done
        total   = self.ops_total
        hits    = len(self.collector.results) if self.collector else 0
        pct     = (done / total * 100) if total > 0 else 0
        if done > 0 and total > 0 and pct < 100:
            eta = elapsed / done * (total - done)
            eta_str = f"{int(eta//60)}m{int(eta%60):02d}s"
        else:
            eta_str = "—"
        elapsed_str = f"{int(elapsed//60)}m{int(elapsed%60):02d}s"
        ops_per_sec = done / elapsed if elapsed > 0.5 else 0
        if ops_per_sec >= 1000:
            ops_str = f"{ops_per_sec/1000:.1f}k ops/s"
        else:
            ops_str = f"{ops_per_sec:.0f} ops/s"
        top5 = sorted(self.collector.results, key=lambda x: -x[0])[:5] if self.collector else []
        best_score = top5[0][0] if top5 else 0
        GY = C.GREY
        bar_w  = 20
        filled = int(pct / 100 * bar_w)
        bar    = c(C.RED, "█" * filled) + c(C.GREY, "░" * (bar_w - filled))

        def _clean(s, maxlen):
            """Nettoie une string pour l'affichage sur une seule ligne."""
            s = re.sub(r'[\n\r\t]', ' ', s)          # \n → espace
            s = re.sub(r' {2,}', ' ', s).strip()      # espaces multiples
            s = re.sub(r'[\x00-\x1f\x7f]', '', s)    # caractères de contrôle
            return s[:maxlen]

        lines = [
            f"",
            f"  {c(C.RED,'─'*60)}",
            f"  {c(C.BOLD+C.WHITE,'⏱  STATUS')}",
            f"  {c(C.RED,'─'*60)}",
            f"  Progression : {bar} {c(C.WHITE, f'{pct:.1f}%')}  {c(GY,f'({done:,}/{total:,} ops)')}",
            f"  Écoulé      : {c(C.WHITE, elapsed_str):<30}  ETA : {c(C.WHITE, eta_str)}",
            f"  Hits        : {c(C.RED2, str(hits))}   Meilleur score : {c(C.GREEN2, f'{best_score:.1f}')}   {c(C.CYAN, ops_str)}",
        ]
        if top5:
            lines.append(f"  {c(GY,'─'*40)}")
            lines.append(f"  {c(C.WHITE,'Top 5 hits :')}")
            for i, entry in enumerate(top5, 1):
                score, depth, path, _, result_str, words, _, has_haiti, ctf_tags = entry
                # Chemin : max 2 dernières étapes, labels nettoyés, 32 chars max
                path_parts = [re.sub(r'[\n\r\t\x00-\x1f]','',label)[:16] for _, label in path[-2:]]
                path_short = (" → ".join(path_parts))[:32]
                # Résultat : nettoyé, max 38 chars
                clean_res  = _clean(result_str, 38)
                # Tags CTF
                ctf_str = f" [{','.join(ctf_tags[:2])}]" if ctf_tags else ""
                # Padding manuel sans codes ANSI (pour aligner correctement)
                path_padded = path_short.ljust(33)
                lines.append(
                    f"  {c(C.RED2, f'#{i}')}  {c(C.WHITE, f'{score:>7.1f}')}  "
                    f"{c(GY, path_padded)}  {c(C.GREEN2, clean_res)}"
                    f"{c(C.RED2, ctf_str) if ctf_str else ''}"
                )
        lines.append(f"  {c(C.RED,'─'*60)}")
        lines.append("")
        sys.stderr.write("\n".join(lines) + "\n")
        sys.stderr.flush()

PROGRESS = Progress()

def _load_words():
    import zlib, base64
    _D = (
        "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"
    )
    raw = zlib.decompress(base64.b64decode(''.join(_D))).decode('utf-8')
    out = {}
    for line in raw.strip().split('\n'):
        p = line.strip().split()
        if len(p) >= 2:
            try: out[p[0]] = int(p[1])
            except: out[p[0]] = 200
        elif len(p) == 1:
            out[p[0]] = 200
    return out
WORD_INDEX = _load_words()

CTF_KEYWORDS  = [
    "flag","password","passwd","secret","token","admin","root","access",
    "login","pass","key","cipher","hidden","crack","ctf","htb","thm","picoctf",
    "user","hash","encode","decode","exploit","shell","sudo","test",
    # Mots CTF populaires (aussi couverts via leet-norm : MrR0b07, Fl4g, etc.)
    "robot","mrrobot","level","welcome","hello","world","linux","windows",
    "nmap","hack","pwn","reverse","binary","crypto","web","misc","forensic",
    "challenge","answer","solution","input","output","result","debug","system",
    "network","server","client","data","file","read","write","open","close",
    "remote","local","private","public","master","super","ultra","mega",
    # Termes techniques courants en CTF/crypto
    "leet","speak","leet-speak","l33t","base","encode","encoded","encoded",
    "cipher","plain","plaintext","ciphertext","decrypt","encrypt",
    "xor","rot","hex","binary","octal","morse","ascii","unicode",
    "salt","pepper","iv","nonce","padding","block","stream",
    "dolphin","monkey","tiger","dragon","phoenix","cobra",
]
CTF_HIGH_SCORE = {'flag','password','passwd','token','secret','key','admin','root','login','pass','robot','mrrobot'}
CTF_MED_SCORE  = {'ctf','htb','thm','picoctf','hash','encode','decode','exploit','shell','user','hack','pwn','reverse','crypto'}

# Pré-compilation des patterns regex pour find_words/detect_ctf.
# Fait UNE FOIS au chargement — évite de recompiler à chaque appel (×50k résultats).
_WORD_PATTERNS: dict = {}   # rempli après _rebuild_word_patterns()

def _rebuild_word_patterns():
    """(Re)construit _WORD_PATTERNS depuis WORD_INDEX + CTF_KEYWORDS."""
    global _WORD_PATTERNS
    _WORD_PATTERNS = {
        w: re.compile(r'\b' + re.escape(w) + r'\b', re.IGNORECASE)
        for w in WORD_INDEX
    }
    for kw in CTF_KEYWORDS:
        if kw not in _WORD_PATTERNS:
            _WORD_PATTERNS[kw] = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)

_rebuild_word_patterns()  # compile les regex une seule fois au démarrage

def load_external_wordlist(path):
    words = {}
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 500_000:
                    break
                w = line.strip().lower()
                if 3 <= len(w) <= 20 and w.isalpha():
                    words[w] = max(words.get(w, 0), max(1, 500_000 - i))
    except FileNotFoundError:
        print(c(C.RED, f"❌ Wordlist introuvable : {path}"))
        sys.exit(1)
    return words

# ─── Fréquences de lettres (Lewand + corpus FR) ──────────────────────────────
EN_FREQ = {
    'a':0.08167,'b':0.01492,'c':0.02782,'d':0.04253,'e':0.12702,'f':0.02228,
    'g':0.02015,'h':0.06094,'i':0.06966,'j':0.00153,'k':0.00772,'l':0.04025,
    'm':0.02406,'n':0.06749,'o':0.07507,'p':0.01929,'q':0.00095,'r':0.05987,
    's':0.06327,'t':0.09056,'u':0.02758,'v':0.00978,'w':0.02360,'x':0.00150,
    'y':0.01974,'z':0.00074,
}
FR_FREQ = {
    'a':0.07636,'b':0.00901,'c':0.03260,'d':0.03669,'e':0.14715,'f':0.01066,
    'g':0.00866,'h':0.00737,'i':0.07529,'j':0.00613,'k':0.00049,'l':0.05456,
    'm':0.02968,'n':0.07095,'o':0.05796,'p':0.02521,'q':0.01362,'r':0.06553,
    's':0.07948,'t':0.07244,'u':0.06311,'v':0.01838,'w':0.00049,'x':0.00427,
    'y':0.00128,'z':0.00326,
}

HASH_PATTERNS = [
    (r'^[0-9a-fA-F]{32}$',  'MD5'),
    (r'^[0-9a-fA-F]{40}$',  'SHA1'),
    (r'^[0-9a-fA-F]{56}$',  'SHA224'),
    (r'^[0-9a-fA-F]{64}$',  'SHA256'),
    (r'^[0-9a-fA-F]{96}$',  'SHA384'),
    (r'^[0-9a-fA-F]{128}$', 'SHA512'),
]

def looks_like_hash(s):
    for pat, name in HASH_PATTERNS:
        if re.match(pat, s.strip()):
            return name
    return None

def is_hex_string(s):
    clean = s.replace(' ', '').strip()
    return bool(clean) and all(c in '0123456789abcdefABCDEF' for c in clean)

STRUCTURAL_OPS = {28,29,30,31,55,56,58,64,67,68,69,70,71,80,81,82,87,88}
BIT_OPS        = set(range(110, 129))   # ops bits : utiles depth=1, exclues depth=2+
HASH_OPS       = {75, 76, 77}
ENCODING_OPS   = {32, 34, 36, 38, 40, 43, 53, 59, 61, 79}
CAESAR_OPS     = set(range(1, 26)) | {26, 27}
DECODE_OPS     = {33, 35, 37, 39, 41, 42, 44, 54, 60}

# Mots NATO à détecter pour pénalisation
NATO_SET = {
    'alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel',
    'india','juliet','kilo','lima','mike','november','oscar','papa',
    'quebec','romeo','sierra','tango','uniform','victor','whiskey',
    'xray','yankee','zulu'
}




# ── Bigram log-probabilities anglais (215 bigrams, meilleure couverture) ──
def _load_bigrams():
    import zlib, base64
    _raw = zlib.decompress(base64.b64decode("eNpV1luSqzgMBuB3rWJWMOX7ZTkOAUI1AQZI6JzVj7rlU/X78SuBjWXJ5nz8o/5VRkedc6BH/yOdQnQ20LT8KpiQs6N+/5UzIRhPRWImKxsd7fKeScYGRf0hcsakQKs8yYPqZKmvskrFTOX8lXI5W0PrS2RtVob6+48UR5LJ9Cgib6P3dK4iGyN/y7qLjA68hukUaRuSpukQKR8Cr2/6VcoxeEPLKEq8RJ6voM76ZOQFRSoyQwreZ0tFxkw++pjokPmS094lKrNIZZcy3fsq7aKn5UQ9JRazdZyz7iGKnHlFtxoL2ilNz4J615i3lrM7VzlOjKYiOYs2Wh+pl2+Jhqcw1PWo5a+0NZGORvNHpLzJvD7JRMjR8P6tA+qU90LKJiSaJ9SyVmnjHZVOxHk3jroVtdf3fDQq07Si9iqXdfZ0SOaDtTp4mnbULlni4tRe0Vzf4zowmuYa48JTgY4VtR+ou8R4m/lNGmVXfPK8M3TKKD5GnoWmDvWo74WsXKSr0bZXcWlzZTUaZO3eW247OjaRDTkl6grqmlCbZN4brmVLY52PM+Y5Zy8Rd6dztNVRuMm4j5YJNUm9uByydrReqEHGdCllpeg5VXGDcOZn1CXf4rgkInf/E7XVUYJL3LdLQR2SXecDNw8dBbU+UeUm4o8xgbo6u1NJa9oarSfqXr+aq5pPhpvkxRkXE/f7N6rU+XSIIdJrQa0z6qrfyWcDnyG3GfVcUcOOKmPVT3vS62gk+26zicbS9UAdL9Qs89nkokr03FB9hxpldhtD+DmzPqjuSxT4pOcn+ypuSK6XDfWSfFpvuAVp3VClyrlgHZ0v1PpGTbJ/1oag+VR8oXqpOst3hfLU96hbXYPhhlQ0DKh1Rc131C77Z/no4ZP21aGWRufRPCn1Yn/qjmv3hXrtqEm+0+TgHd85b1R3ovpGs4xpuG8s12dB9WujN2raqrit+U49UN3exG6oexO7JC9cSZ5vkm5C3WdUv6HOuobAHcjV2qMeTaxcqOWridX5fODDgW4FNTaxvX6LS47vsWtHzSdq/a7iljf0X82u5X+PRN8TajlQaxNbpSb4MnKaO+6GGmbUWKWD5btxGVBHh9p31PPWvCcdblSyfIuOI2p5o/oJdfsrbk8+yxfUV6PzQq0F9WyePOTk09lYvqfHgtrfjZon5wF1XKjhRD1kPp0c/9nR+EGVB2oqqH1EPWWndQy8ZzQsqC/Jrg7JakWPA3XeUWVALX9j3J6ePgeqfDWxGTU3T24n6mpiUx2Ff3QSn1Jv1J9Pox71aVVQXzPof8EGgCQ=")).decode()
    _d = {}
    for line in _raw.strip().split('\n'):
        p = line.split()
        if len(p)==2: _d[p[0]] = float(p[1])
    return _d

_BIGRAMS     = _load_bigrams()
# Floor moins sévère (-3.52) pour les bigrams rares mais valides (qu, ox, br...)
_BIGRAM_FLOOR = math.log10(0.0003)
_BIGRAM_LOGP  = {k: math.log10(v) for k,v in _BIGRAMS.items()}

def bigram_score(s):
    """Score basé sur les bigrams anglais.
    100 = anglais parfait (hello world), 0 = aléatoire total (XQZKVPJM).
    Seuls les caractères alphabétiques sont considérés.
    """
    letters = re.sub(r'[^a-z]', '', s.lower())
    if len(letters) < 4:
        return 0.0
    total = 0.0; count = 0
    for i in range(len(letters)-1):
        bg = letters[i:i+2]
        total += _BIGRAM_LOGP.get(bg, _BIGRAM_FLOOR)
        count += 1
    if count == 0: return 0.0
    avg = total / count
    # -1.6 = anglais excellent, -3.5 = aléatoire/garbage
    return max(0.0, (avg - (-3.5)) / ((-1.6) - (-3.5))) * 100.0


# ── Leet-speak normalisation ─────────────────────────────────────────────
_LEET_TABLE = str.maketrans({
    '0':'o','1':'i','3':'e','4':'a','5':'s',
    '6':'b','7':'t','8':'b','9':'g',
    '@':'a','!':'i','$':'s','+':'t',
})

def _normalize_leet(s):
    """MrR0b07 → mrrobot, Fl4g → flag, p@ssw0rd → password."""
    return s.translate(_LEET_TABLE).lower()


def _rebuild_word_sets():
    """Construit les sets de mots pour find_words."""
    global _WORDS_4UP, _WORDS_3CHAR, _PRESCREEN_4GRAMS, _CTF_3CHAR
    # Tous les mots ≥4 chars : wordlist + CTF_KEYWORDS fusionnés
    _WORDS_4UP = {w for w in WORD_INDEX if w != 'haiti' and w != 'pass' and len(w) >= 4}
    _WORDS_4UP |= {w for w in CTF_KEYWORDS if w != 'pass' and len(w) >= 4}
    # Mots de 3 chars (CTF : ctf, htb, thm, web, pwn, key...)
    _CTF_3CHAR = {w for w in CTF_KEYWORDS if len(w) == 3}
    _WORDS_3CHAR = {w for w in WORD_INDEX if len(w) == 3} | _CTF_3CHAR
    # Prescreen : 4-grams de tous les mots connus (rejet rapide du bruit)
    _PRESCREEN_4GRAMS = set()
    for _w in list(WORD_INDEX) + list(CTF_KEYWORDS):
        for _i in range(len(_w) - 3):
            _PRESCREEN_4GRAMS.add(_w[_i:_i+4])
    for _w in _CTF_3CHAR:
        _PRESCREEN_4GRAMS.add(_w)

_CTF_3CHAR   = set()  # init avant le premier appel
_WORDS_3CHAR = set()
_rebuild_word_sets()  # initialise les sets au démarrage

# Patterns regex précompilés pour "pass" (word boundary) et "haiti"
_PASS_PAT  = re.compile(r'(?<![a-zA-Z])pass(?![a-zA-Z])', re.IGNORECASE)
_HAITI_PAT = re.compile(r'(?<![a-zA-Z])haiti(?![a-zA-Z])', re.IGNORECASE)


def prescreen(s):
    """Filtre ultra-rapide (set lookup) — rejette les chaînes sans aucun 4-gram connu.
    Doit être appelé AVANT find_words pour économiser 99% des appels dans les boucles XOR.
    Retourne True si la chaîne POURRAIT contenir un mot connu (peut avoir faux positifs).
    """
    lower = s.lower()
    leet  = lower.translate(_LEET_TABLE)
    for i in range(len(lower) - 3):
        g = lower[i:i+4]
        if g in _PRESCREEN_4GRAMS:
            return True
        g2 = leet[i:i+4]
        if g2 in _PRESCREEN_4GRAMS:
            return True
    for kw in _CTF_3CHAR:
        if kw in lower or kw in leet:
            return True
    return False

def find_words(s, search_haiti=False):
    """Matching complet — appeler APRÈS prescreen() pour les perfs.
    - "pass" seul : seulement si NON entouré de lettres
    - Mots 4+ chars : substring direct (rapide + attrape flagveryeasy etc.)
    - Mots 3 chars  : substring direct sans regex (plus rapide, assez précis)
    - Aussi testé sur la version leet-normalisée (MrR0b07→mrrobot, Fl4g→flag)
    """
    lower      = s.lower()
    # Normalisation leet uniquement si la chaîne contient ASSEZ de lettres
    # (évite 7777→tttt ou 0000→oooo de trouver ttt/ooo)
    _alpha_count = sum(1 for c in s if c.isalpha())
    _total = max(1, len(s))
    _use_leet = (_alpha_count / _total) >= 0.30   # au moins 30% de lettres
    leet_lower = _normalize_leet(s) if _use_leet else lower
    hits  = []
    if _PASS_PAT.search(s) or (_use_leet and _PASS_PAT.search(leet_lower)):
        hits.append('pass')
    # Mots ≥4 chars (wordlist + CTF_KEYWORDS) — substring direct
    for w in _WORDS_4UP:
        if w in lower or (_use_leet and w in leet_lower):
            hits.append(w)
    # Mots 3 chars (CTF : ctf, htb, thm, web, pwn, key...) — substring
    for w in _WORDS_3CHAR:
        if w in lower or (_use_leet and w in leet_lower):
            hits.append(w)
    if search_haiti and (_HAITI_PAT.search(lower) or (_use_leet and _HAITI_PAT.search(leet_lower))):
        hits.append('haiti')
    return hits


def detect_ctf_keywords(s):
    """Même logique hybride que find_words — teste aussi la version leet-normalisée."""
    lower      = s.lower()
    _alpha_r2 = sum(1 for c in s if c.isalpha()) / max(1, len(s))
    leet_lower = _normalize_leet(s) if _alpha_r2 >= 0.30 else s.lower()
    found = []
    for kw in CTF_KEYWORDS:
        if kw == 'pass':
            if (re.search(r'(?<![a-zA-Z])pass(?![a-zA-Z])', s, re.IGNORECASE) or
                re.search(r'(?<![a-zA-Z])pass(?![a-zA-Z])', leet_lower, re.IGNORECASE)):
                found.append(kw)
        elif len(kw) == 3:
            pat = _WORD_PATTERNS.get(kw)
            if pat and (pat.search(lower) or pat.search(leet_lower)):
                found.append(kw)
        else:
            if kw in lower or kw in leet_lower:
                found.append(kw)
    return found


# Précalcul des tables chi2 — fait UNE FOIS, évite les multiplications dans la boucle chaude
_CHI2_TRANS = str.maketrans('', '', ''.join(chr(i) for i in range(256) if not chr(i).isalpha()))
_EN_FREQ_LIST = sorted(EN_FREQ.items())   # liste stable pour chi2
_FR_FREQ_LIST = sorted(FR_FREQ.items())

def chi2_lang_fast(letters_lower, freq_list, n):
    """letters_lower doit déjà être filtré (seulement a-z) et en lowercase."""
    f = [0] * 26
    for ch in letters_lower:
        f[ord(ch) - 97] += 1
    total = 0.0
    for i, (l, p) in enumerate(freq_list):
        expected = p * n
        obs = f[ord(l) - 97]
        diff = obs - expected
        total += diff * diff / expected
    return total

def chi2_lang(s, freq):
    letters = re.sub(r'[^a-z]', '', s.lower())
    n = len(letters)
    if n < 4:
        return 9999.0
    # compatibilité avec l'ancienne signature (freq dict) — non utilisé en interne
    freq_list = sorted(freq.items())
    return chi2_lang_fast(letters, freq_list, n)

def index_coincidence(s):
    text = re.sub(r'[^a-z]', '', s.lower())
    n = len(text)
    if n < 6:
        return 0.038
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    return sum(v * (v - 1) for v in freq.values()) / (n * (n - 1))

def compute_score(result_str, words, has_haiti):
    """
    Scoring basé sur la recherche académique (practicalcryptography.com) :

    1. BIGRAM FITNESS  — log-probability sur le corpus anglais (primary pour texte long)
    2. IC SCORE        — index de coïncidence (distingue mono vs poly)
    3. WORD BONUS      — additif pur : chaque mot trouvé = +pts proportionnels à sa longueur
       - Mots longs (≥6 chars) : signal fort même seuls (dolphin88, password, mrrobot)
       - Mots courts (4-5 chars) : nécessitent contexte (séparateur = : { () pour valoir qqch)
       - Aucun mot ≤3 chars dans le dictionnaire

    Formule finale :
        score = base_fitness + word_bonus

    word_bonus est ADDITIF (pas un ×) : un seul mot long = déjà ~30-50pts
    """
    if not result_str:
        return 0.0

    total_len = len(result_str)
    n_printable = sum(1 for ch in result_str if ch.isprintable())
    if n_printable / max(1, total_len) < 0.70:
        return 0.01

    lower_str = result_str.lower()
    alpha_chars = [ch for ch in lower_str if 'a' <= ch <= 'z']
    n = len(alpha_chars)

    # ── 1. Bigram fitness (0–80) ─────────────────────────────────────────
    bg = bigram_score(result_str)

    # ── 2. Index de coïncidence (0–20) ───────────────────────────────────
    ic = 0.038
    if n >= 6:
        freq26 = [0]*26
        for ch in alpha_chars: freq26[ord(ch)-97] += 1
        ic = sum(v*(v-1) for v in freq26) / (n*(n-1))
    dist_natural = min(abs(ic-0.065), abs(ic-0.074))
    ic_score = max(0.0, 1.0 - dist_natural/0.040) * 20.0

    # ── 3. Base fitness ───────────────────────────────────────────────────
    base_fitness = bg * 0.70 + ic_score

    # Pénalité texte trop court (< 15 chars alpha → signal moins fiable)
    length_conf = min(1.0, (n + 3) / 18.0)
    base_fitness *= length_conf

    # Ratio alpha (récompense le texte majoritairement alphabétique)
    alpha_ratio = n / max(1, len(result_str.replace(' ','').replace('\n','')))
    base_fitness *= (0.30 + 0.70 * min(1.0, alpha_ratio * 1.4))

    # ── 4. Entropie ───────────────────────────────────────────────────────
    _chars = [c for c in result_str if c.isprintable()]
    if len(_chars) >= 8:
        _fq = {}
        for _c in _chars: _fq[_c] = _fq.get(_c,0)+1
        _nn = len(_chars)
        _ent = -sum((v/_nn)*math.log2(v/_nn) for v in _fq.values())
        if _ent > 5.5:
            base_fitness *= max(0.10, 1.0 - (_ent-5.5)/3.0)
        elif _ent < 1.5:
            base_fitness *= max(0.2, _ent/1.5)

    # ── 5. Pénalité NATO ──────────────────────────────────────────────────
    tokens = re.findall(r'[A-Za-z]+', result_str)
    if len(tokens) >= 4:
        nato_count = sum(1 for t in tokens if t.lower() in NATO_SET)
        nato_ratio = nato_count / len(tokens)
        if nato_ratio > 0.30:
            base_fitness *= max(0.07, 1.0 - nato_ratio*1.4)

    # ── 6. WORD BONUS (additif pur) ───────────────────────────────────────
    # Principe : chaque mot trouvé ajoute des points DIRECTEMENT au score,
    # proportionnellement à sa longueur. Un password de 8 chars = ~50pts seul.
    # Les mots courts (4-5 chars) pénalisés s'ils sont sans contexte.
    tl      = result_str.lower()
    _alpha_r = sum(1 for c in result_str if c.isalpha()) / max(1, len(result_str))
    leet_tl  = _normalize_leet(result_str) if _alpha_r >= 0.30 else tl

    _SEP_SET  = set('=:{([_/ \t\n\r\\@!|,;')

    def _has_sep(fi, k):
        kl = len(k)
        for pat in (k+':', k+'=', k+'{', '{'+k, '('+k, k+'(',
                    k+']', k+' ', ' '+k, k+'_', '_'+k, k+'[', '['+k):
            if pat in fi: return True
        i2 = fi.find(k)
        if i2 > 0 and fi[i2-1] in _SEP_SET: return True
        if i2>=0 and i2+kl < len(fi) and fi[i2+kl] in _SEP_SET: return True
        return False

    def _case_mult(fi, k):
        i2 = fi.find(k)
        if i2 < 0: return 1.0
        raw = result_str[i2:i2+len(k)]
        if raw == raw.lower() or raw == raw.upper(): return 1.0
        if raw[0].isupper() and raw[1:].islower(): return 0.90
        return 0.35   # PaSsWoRd = chaos = bruit probable

    word_bonus  = 0.0
    _found_kws  = []
    _checked    = set()

    # Combine WORD_INDEX (avec scores) + CTF_KEYWORDS (score fixe selon catégorie)
    _all_kw = list(WORD_INDEX.items())
    for _kw in CTF_KEYWORDS:
        if _kw not in WORD_INDEX:
            # Score fixe selon longueur/catégorie CTF
            _s = 900 if _kw in CTF_HIGH_SCORE else (800 if _kw in CTF_MED_SCORE else 700)
            _all_kw.append((_kw, _s))

    for k, wscore in _all_kw:
        if wscore < 200: continue
        if k in _checked: continue
        fi = tl if k in tl else (leet_tl if k in leet_tl else None)
        if fi is None: continue
        i2 = fi.find(k)
        if i2 < 0: continue
        _checked.add(k)
        klen = len(k)

        # ── Valeur de base du mot ─────────────────────────────────────────
        # Formule : score ∝ longueur² × catégorie
        # dolphin (7,700) → 7²×0.7 = 34.3  | password (8,900) → 8²×0.9 = 57.6
        # flag    (4,900) → 4²×0.9 = 14.4  | token    (5,850) → 5²×0.85= 21.3
        cat_mult = min(1.0, wscore / 900.0)
        kw_pts   = (klen ** 2) * cat_mult

        # ── Mots courts (4 chars) : pénalité sans séparateur ─────────────
        # flag/pass/user/root seuls (exactement 4 chars) = faux positif fréquent
        # tiger/admin/login (5 chars) : score normal mais pas de bonus sep
        if klen == 4 and not _has_sep(fi, k):
            kw_pts *= 0.08   # ~92% de réduction

        # ── Bonus séparateur (tous les mots) ─────────────────────────────
        if _has_sep(fi, k):
            kw_pts += klen * 1.5   # bonus linéaire

        # ── Casse ─────────────────────────────────────────────────────────
        kw_pts *= _case_mult(fi, k)

        _found_kws.append((k, i2, klen, kw_pts))
        word_bonus += kw_pts

    # ── Bonus adjacence : deux mots côte à côte (gap ≤1 char) ────────────
    # flagveryeasy → flag+very collés → bonus fort
    if len(_found_kws) >= 2:
        _found_kws.sort(key=lambda x: x[1])
        for i in range(len(_found_kws)-1):
            k1,i1,l1,s1 = _found_kws[i]
            k2,i2,l2,s2 = _found_kws[i+1]
            gap = i2 - (i1+l1)
            if 0 <= gap <= 1:   word_bonus += (l1+l2) * 2.0
            elif gap <= 3:      word_bonus += (l1+l2) * 0.5

    score = base_fitness + word_bonus
    if has_haiti: score += 500
    return round(score, 3)


def _suppress_hash_detection(path, parent_str, result_str):
    if not path:
        return False
    last_num = path[-1][0]
    if last_num in HASH_OPS:
        return True
    if any(isinstance(p[0], int) and p[0] in HASH_OPS for p in path):
        return True
    if last_num in ENCODING_OPS:
        return True
    if parent_str and looks_like_hash(parent_str) and isinstance(last_num, int) and last_num in STRUCTURAL_OPS:
        return True
    if result_str.strip().isdigit():
        return True
    if is_hex_string(result_str) and len(path) >= 2:
        if all(isinstance(p[0], int) and p[0] in STRUCTURAL_OPS for p in path):
            return True
    if is_hex_string(result_str) and len(path) >= 2:
        path_nums = [p[0] for p in path]
        if not any(isinstance(n, int) and n in DECODE_OPS for n in path_nums):
            return True
    return False

class ResultCollector:
    def __init__(self):
        self.results   = []
        self._seen_res = {}   # result_str_normalized → index dans self.results
                              # garde seulement le chemin le plus court

    def add(self, depth, path, parent_str, result_str, search_haiti):
        # ── Prescreen ultra-rapide : rejette 99% des chaînes bruit avant tout traitement ──
        _search_str = re.sub(r"^\[clé='[^']*'\]\s*", '', result_str)
        _check_hash = not _suppress_hash_detection(path, parent_str, result_str)
        h_candidate = looks_like_hash(result_str) if _check_hash else None
        # Si pas de hash ET pas de prescreen → sortie immédiate (chemin chaud)
        if h_candidate is None and not prescreen(_search_str):
            return False
        # ── Déduplification par résultat normalisé ────────────────────────────
        # Même résultat via des chemins XOR différents (XOR est commutatif/associatif)
        # → on garde seulement le chemin le plus court
        norm = result_str.strip().lower()
        if norm in self._seen_res:
            idx = self._seen_res[norm]
            # Remplacer si chemin plus court
            if len(path) < len(self.results[idx][2]):
                old = self.results[idx]
                self.results[idx] = (old[0], old[1], path, old[3], old[4], old[5], old[6], old[7], old[8])
            return False   # pas un nouveau hit
        # ── Matching complet uniquement si le prescreen a passé ──────────────
        words     = find_words(_search_str, search_haiti=search_haiti)
        has_haiti = search_haiti and 'haiti' in _search_str.lower()
        ctf_tags  = detect_ctf_keywords(_search_str)
        interesting = bool(words) or bool(h_candidate) or has_haiti or bool(ctf_tags)
        if not interesting:
            return False
        score = compute_score(result_str, words, has_haiti)
        if h_candidate and not words and not ctf_tags:
            score = max(score, 1.0)
        self._seen_res[norm] = len(self.results)
        self.results.append((score, depth, path, parent_str, result_str, words, h_candidate, has_haiti, ctf_tags))
        return True

    def display_top(self, top_n):
        if not self.results:
            print(c(C.RED, "  Aucun résultat intéressant trouvé."))
            return
        sorted_results = sorted(self.results, key=lambda x: -x[0])
        total = len(sorted_results)
        shown = min(top_n, total)
        sep = c(C.RED, "  " + "═"*68)
        print(f"\n{sep}")
        print(c(C.WHITE, f"  TOP {shown}/{total} résultats") + c(C.GREY, " (triés par score de lisibilité)"))
        print(sep)

        for rank, (score, depth, path, parent_str, result_str, words, h, has_haiti, ctf_tags) in enumerate(sorted_results[:top_n], 1):
            parts = []
            for num, label in path:
                tag = f"[{num}]" if not str(num).startswith("XF") and not str(num).startswith("XR") else ""
                if tag:
                    parts.append(c(C.RED, tag) + c(C.WHITE, f" {label}"))
                else:
                    parts.append(c(C.WHITE, label))
            path_str = c(C.GREY, " → ").join(parts)

            bar      = score_bar(score, sorted_results[0][0])
            rank_str = c(C.RED2, f"#{rank:>3}")
            sc_str   = c(C.WHITE, f"score={score:>8.1f}")
            bar_str  = c(C.RED, bar)

            ctf_badge = ""
            if ctf_tags:
                tags_str = " ".join(c(C.RED2, f"[{t}]") for t in ctf_tags[:4])
                ctf_badge = f" {tags_str}"

            print(f"\n  {rank_str}  {sc_str}  {bar_str}{ctf_badge}")
            print(f"       🔗 {path_str}")

            # ── Affichage du résultat : max 90 chars, une seule ligne ──────
            res_color = C.YELLOW if ctf_tags else C.GREEN2
            clean_res = result_str.replace('\n', ' ').replace('\r', ' ')
            clean_res = re.sub(r' {2,}', ' ', clean_res).strip()
            MAX_DISP  = 90
            if len(clean_res) > MAX_DISP:
                display_res = clean_res[:MAX_DISP] + c(C.GREY, '…')
            else:
                display_res = clean_res
            print(f"       {c(C.GREY, '→')} {c(res_color, display_res)}")

            if words or has_haiti:
                unique = sorted(set(words))
                words_colored = ", ".join(c(C.GREEN, w) for w in unique[:20])
                line = f"💬 {c(C.WHITE, 'Mots')} : {words_colored}"
                if has_haiti:
                    line += f"  {c(C.RED2+C.BOLD, '⭐ HAITI ⭐')}"
                print(f"       {line}")
            if h:
                print(f"       🔑 {c(C.YELLOW, f'Ressemble à un hash : {h}')}")

def score_bar(score, max_score, width=12):
    if max_score <= 0:
        return "░" * width
    ratio = min(1.0, score / max_score)
    filled = int(ratio * width)
    return "█" * filled + "░" * (width - filled)

# ─── Opérations ──────────────────────────────────────────────────────────────

def caesar(s, shift):
    result = []
    for ch in s:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def rot13(s):  return caesar(s, 13)

def atbash(s):
    result = []
    for ch in s:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr(base + 25 - (ord(ch) - base)))
        else:
            result.append(ch)
    return ''.join(result)

def to_ascii_codes(s):   return ' '.join(str(ord(ch)) for ch in s)
def from_ascii_codes(s):
    try:
        nums = re.findall(r'\d+', s)
        return ''.join(chr(int(n)) for n in nums if 0 < int(n) < 128)
    except: return None
def to_hex(s):    return s.encode().hex()
def from_hex(s):
    try:
        clean = s.replace(' ', '').replace('0x', '')
        return bytes.fromhex(clean).decode('utf-8', errors='replace')
    except: return None
def to_binary(s):   return ' '.join(format(ord(ch), '08b') for ch in s)
def from_binary(s):
    try:
        bits = s.replace(' ', '')
        if len(bits) % 8 != 0: return None
        raw = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
        try:    return raw.decode('utf-8')
        except: return raw.decode('latin-1')
    except: return None
def to_octal(s):    return ' '.join(oct(ord(ch))[2:] for ch in s)
def from_octal(s):
    try:  return ''.join(chr(int(p, 8)) for p in s.split())
    except: return None
def to_base64(s):   return base64.b64encode(s.encode()).decode()
def from_base64(s):
    try:
        missing = len(s) % 4
        padded  = s + '=' * (missing if missing else 0)
        return base64.b64decode(padded).decode('utf-8', errors='replace')
    except: return None
def from_base32(s):
    try:
        missing = len(s) % 8
        padded  = s.upper() + '=' * (missing if missing else 0)
        return base64.b32decode(padded).decode('utf-8', errors='replace')
    except: return None
def xor_op(s, key=42):     return ''.join(chr(ord(ch) ^ key) for ch in s)
def and_op(s, key=0xFF):   return ''.join(chr(ord(ch) & key) for ch in s)
def or_op(s, key=0x20):    return ''.join(chr(ord(ch) | key) for ch in s)
def reverse(s):             return s[::-1]
def swap_case(s):           return s.swapcase()
def to_upper(s):            return s.upper()
def to_lower(s):            return s.lower()
def numbers_to_letters(s):
    result = []
    for ch in s:
        if ch.isdigit() and 1 <= int(ch) <= 9:
            result.append(chr(ord('A') + int(ch) - 1))
        else:
            result.append(ch)
    return ''.join(result)
def letters_to_numbers(s):
    result = []
    for ch in s:
        if ch.isalpha():
            result.append(str(ord(ch.lower()) - ord('a') + 1))
        else:
            result.append(ch)
    return ''.join(result)
def phone_keypad(s):
    mapping = {'2':'ABC','3':'DEF','4':'GHI','5':'JKL','6':'MNO','7':'PQRS','8':'TUV','9':'WXYZ'}
    return ''.join(f"[{mapping[ch]}]" if ch in mapping else ch for ch in s)
def morse_encode(s):
    MORSE = {
        'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---',
        'K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-',
        'U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',
        '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.',
        ' ':'/'
    }
    return ' '.join(MORSE.get(ch.upper(), '?') for ch in s)
def morse_decode(s):
    MORSE_REV = {
        '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J',
        '-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T',
        '..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
        '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9',
        '/':' '
    }
    return ''.join(MORSE_REV.get(t, '?') for t in s.split(' '))
def unicode_escape(s):  return ' '.join(f'U+{ord(ch):04X}' for ch in s)
def from_unicode_escape(s):
    try:
        parts = re.findall(r'U\+([0-9A-Fa-f]{4,6})', s)
        if parts: return ''.join(chr(int(p, 16)) for p in parts)
    except: pass
    return None
def vigenere_decode(s, key):
    result = []
    ki = 0
    for ch in s:
        if ch.isalpha():
            shift = ord(key[ki % len(key)].lower()) - ord('a')
            base  = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)
def remove_vowels(s):       return re.sub(r'[aeiouAEIOU]', '', s)
def only_vowels(s):         return re.sub(r'[^aeiouAEIOU\s]', '', s)
def character_frequency(s):
    freq = {}
    for ch in s: freq[ch] = freq.get(ch, 0) + 1
    sorted_freq = sorted(freq.items(), key=lambda x: -x[1])
    return ' | '.join(f"'{k}':{v}" for k, v in sorted_freq[:15])
def md5_hash(s):    return hashlib.md5(s.encode()).hexdigest()
def sha1_hash(s):   return hashlib.sha1(s.encode()).hexdigest()
def sha256_hash(s): return hashlib.sha256(s.encode()).hexdigest()
def url_encode(s):
    from urllib.parse import quote
    return quote(s)
def url_decode(s):
    from urllib.parse import unquote
    return unquote(s)
def html_entities(s):
    return ''.join(f'&#{ord(ch)};' if (ord(ch) > 127 or ch in '<>&"\'') else ch for ch in s)
def remove_spaces(s):   return s.replace(' ', '')
def reverse_words(s):   return ' '.join(s.split()[::-1])
def alternate_case(s):  return ''.join(ch.upper() if i % 2 == 0 else ch.lower() for i, ch in enumerate(s))
def interleave_reverse(s):
    half = len(s) // 2
    return s[:half][::-1] + s[half:][::-1]
def extract_numbers(s):
    nums = re.findall(r'\d+', s)
    return ' '.join(nums) if nums else None
def extract_letters(s): return re.sub(r'[^a-zA-Z]', '', s)
def shift_one(s):       return ''.join(chr(ord(ch) + 1) for ch in s if ord(ch) + 1 < 128)
def shift_minus_one(s): return ''.join(chr(ord(ch) - 1) for ch in s if ord(ch) - 1 > 0)
def double_letters(s):  return ''.join(ch * 2 for ch in s)
def every_other(s):     return s[::2]
def every_other_reversed(s): return s[1::2]
def leet_speak(s):
    LEET = {'a':'4','e':'3','i':'1','o':'0','t':'7','s':'5','l':'1','b':'8'}
    return ''.join(LEET.get(ch.lower(), ch) for ch in s)
def unleet_speak(s):
    UNLEET = {'4':'a','3':'e','1':'i','0':'o','7':'t','5':'s','8':'b'}
    return ''.join(UNLEET.get(ch, ch) for ch in s)
def pigpen_numbers(s):  return ' '.join(str(ord(ch.lower()) - 96) if ch.isalpha() else ch for ch in s)
def chunks(s, n=4):     return ' '.join(s[i:i+n] for i in range(0, len(s), n))
def spaceless(s):       return s.replace(' ', '').replace('-', '').replace('_', '')
def nato_alphabet(s):
    NATO = {
        'A':'Alpha','B':'Bravo','C':'Charlie','D':'Delta','E':'Echo','F':'Foxtrot',
        'G':'Golf','H':'Hotel','I':'India','J':'Juliet','K':'Kilo','L':'Lima',
        'M':'Mike','N':'November','O':'Oscar','P':'Papa','Q':'Quebec','R':'Romeo',
        'S':'Sierra','T':'Tango','U':'Uniform','V':'Victor','W':'Whiskey','X':'Xray',
        'Y':'Yankee','Z':'Zulu'
    }
    return ' '.join(NATO.get(ch.upper(), ch) for ch in s)
def to_hex_with_prefix(s): return ' '.join(f'0x{ord(ch):02X}' for ch in s)
def column_transpose(s, cols=2):
    s_clean = s.replace(' ', '')
    rows    = [s_clean[i:i+cols] for i in range(0, len(s_clean), cols)]
    result  = []
    for col in range(cols):
        for row in rows:
            if col < len(row):
                result.append(row[col])
    return ''.join(result)
def bacon_cipher(s):
    BACON = {}
    for i, ch in enumerate(string.ascii_uppercase):
        code = format(i, '05b').replace('0', 'A').replace('1', 'B')
        BACON[ch] = code
    return ' '.join(BACON.get(ch.upper(), ch) for ch in s if ch.isalpha() or ch == ' ')
def rot47(s):
    result = []
    for ch in s:
        o = ord(ch)
        if 33 <= o <= 126:
            result.append(chr(33 + (o - 33 + 47) % 94))
        else:
            result.append(ch)
    return ''.join(result)
def caesar_variable_by_word(s):
    shift = 25
    result = []
    token = ''
    def flush(tok):
        nonlocal shift
        dec = ''.join(
            chr((ord(ch) - (ord('A') if ch.isupper() else ord('a')) - shift) % 26
                + (ord('A') if ch.isupper() else ord('a')))
            if ch.isalpha() else ch
            for ch in tok
        )
        shift -= 1
        return dec
    for ch in s:
        if ch in (' ', "'", '\n', '\r'):
            if token:
                result.append(flush(token))
                token = ''
            result.append(ch)
        else:
            token += ch
    if token:
        result.append(flush(token))
    return ''.join(result)
def vigenere_brute_common(s):
    COMMON_KEYS = [
        'key','abc','secret','flag','haiti','password','pass',
        'cesar','caesar','rome','julius','brutus','gaule','gallia',
        'guerre','soldat','armee','legion','victor','rubicon',
        'crypto','cipher','hack','ctf','root','admin',
        'loup','bois','foret','fleur','amour',
    ]
    best_score = -1
    best_out   = None
    best_key   = None
    for key in COMMON_KEYS:
        try:
            dec   = vigenere_decode(s, key)
            words = find_words(dec)
            sc    = compute_score(dec, words, False)
            if sc > best_score:
                best_score = sc
                best_out   = dec
                best_key   = key
        except Exception:
            pass
    if best_out and best_score > 1:
        return f"[clé='{best_key}'] {best_out}"
    return None
def rail_fence_decode(s, rails=2):
    n = len(s)
    if n == 0 or rails < 2: return None
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    cycle   = len(pattern)
    indices = [[] for _ in range(rails)]
    for i in range(n):
        indices[pattern[i % cycle]].append(i)
    result = [''] * n
    pos = 0
    for rail in range(rails):
        for idx in indices[rail]:
            result[idx] = s[pos]
            pos += 1
    return ''.join(result)
def rail_fence_2(s): return rail_fence_decode(s, 2)
def rail_fence_3(s): return rail_fence_decode(s, 3)
def rail_fence_4(s): return rail_fence_decode(s, 4)

# ─── Opérations sur les bits ──────────────────────────────────────────────────

def bit_not(s):
    """NOT bit : inverse tous les bits de chaque octet (masqué sur 7 bits pour rester ASCII)."""
    result = []
    for ch in s:
        o = ord(ch)
        n = (~o) & 0x7F  # NOT masqué 7 bits → reste dans plage ASCII imprimable
        if 32 <= n < 127:
            result.append(chr(n))
        else:
            result.append(ch)  # garde le char original si résultat non imprimable
    return ''.join(result)

def bit_not_full(s):
    """NOT bit complet sur 8 bits → retourne représentation hex."""
    return ' '.join(f'{(~ord(ch)) & 0xFF:02X}' for ch in s)

def _safe_byte_op(s, transform):
    """Applique transform(byte) a chaque octet ; renvoie None si trop peu imprimable.
    Optimisé : encode latin-1, applique transform sur bytearray, décode.
    """
    try:
        raw = s.encode('latin-1')
    except Exception:
        raw = s.encode('utf-8', errors='replace')
    result = []
    non_print = 0
    for b in raw:
        nb = transform(b) & 0xFF
        if 32 <= nb < 127:
            result.append(chr(nb))
        else:
            non_print += 1
            result.append('[x' + format(nb, '02x') + ']')
    if non_print > len(raw) * 0.4:
        return None
    return ''.join(result)

def circular_left_shift(s, n=1):
    """Decalage circulaire gauche de n bits sur chaque octet (8 bits)."""
    n = n % 8
    return _safe_byte_op(s, lambda b: ((b << n) | (b >> (8 - n))) & 0xFF)

def circular_right_shift(s, n=1):
    """Decalage circulaire droit de n bits sur chaque octet (8 bits)."""
    n = n % 8
    return _safe_byte_op(s, lambda b: ((b >> n) | (b << (8 - n))) & 0xFF)

def circular_left_shift_2(s): return circular_left_shift(s, 2)
def circular_left_shift_3(s): return circular_left_shift(s, 3)
def circular_left_shift_4(s): return circular_left_shift(s, 4)
def circular_right_shift_2(s): return circular_right_shift(s, 2)
def circular_right_shift_3(s): return circular_right_shift(s, 3)
def circular_right_shift_4(s): return circular_right_shift(s, 4)

def nibble_swap(s):
    """Echange les 4 bits hauts et bas (nibble swap) de chaque octet."""
    return _safe_byte_op(s, lambda b: ((b & 0x0F) << 4) | ((b & 0xF0) >> 4))

def reverse_bits_per_byte(s):
    """Inverse l'ordre des bits dans chaque octet."""
    return _safe_byte_op(s, lambda b: int(f'{b:08b}'[::-1], 2))

def xor_halves(s):
    """XOR entre la premiere moitie et la seconde moitie de la chaine."""
    if len(s) < 2:
        return None
    mid = len(s) // 2
    first, second = s[:mid], s[mid:mid + len(s[:mid])]
    result = []
    non_print = 0
    for a, b in zip(first, second):
        v = ord(a) ^ ord(b)
        if 32 <= v < 127:
            result.append(chr(v))
        else:
            non_print += 1
            result.append(f'\\x{v:02x}')
    if non_print > mid * 0.4:
        return None
    return ''.join(result)

def nand_op(s, key=0xFF):
    """NAND : NOT(AND) avec masque 0xFF."""
    return _safe_byte_op(s, lambda b: (~(b & key)) & 0xFF)

def nor_op(s, key=0x00):
    """NOR : NOT(OR) avec masque 0x00."""
    return _safe_byte_op(s, lambda b: (~(b | key)) & 0xFF)

def popcount(s):
    """Compte le nombre de bits a 1 (popcount) pour chaque octet."""
    return ' '.join(str(bin(ord(ch)).count('1')) for ch in s)

def bits_to_binary(s):
    """Representation binaire de chaque octet (8 bits) sans separateur."""
    return ''.join(format(ord(ch), '08b') for ch in s)

def logical_shift_left(s, n=1):
    """Decalage logique gauche (LSL) de n bits sur chaque octet — sans rotation."""
    return _safe_byte_op(s, lambda b: (b << n) & 0xFF)

def logical_shift_right(s, n=1):
    """Decalage logique droit (LSR) de n bits sur chaque octet — sans rotation."""
    return _safe_byte_op(s, lambda b: (b & 0xFF) >> n)


# ─── Détection automatique du format d'entrée ─────────────────────────────────

def detect_input_format(s):
    """Détecte le format de la chaîne d'entrée UNIQUEMENT quand c'est certain à ~100%.

    Règle : si le format est ambigu (hex, base64, ascii décimaux), on NE détecte PAS.
    Exemples d'ambiguïtés :
      - "baffe" est du hex valide ET un mot français
      - "test" décode en base64
      - "65 68 72 101" sont des codes ASCII ET des nombres quelconques

    Formats retenus (quasi-certitude) :
      - Binaire  : uniquement 0/1 + longueur multiple de 8 (aucun autre sens possible)
      - Octal    : chiffres 0-7 séparés espaces, tous < 256, au moins 3 tokens
      - Morse    : uniquement . - / espaces, tokens valides
      - URL enc. : contient %XX au moins 2 fois

    Formats SUPPRIMÉS (ambigus) : hex, base64, ascii_codes
    """
    tags = []
    stripped = s.strip()

    # ── Binaire pur (~100% certain) ───────────────────────────────────────────
    # Critères : uniquement 0 et 1 (+ espaces), longueur multiple de 8 après strip
    bits_only = re.sub(r'\s+', '', stripped)
    if (bits_only
            and all(c in '01' for c in bits_only)
            and len(bits_only) % 8 == 0
            and len(bits_only) >= 8):
        tags.append('binary')
        return tags  # exclusif

    # ── Morse (~100% certain) ─────────────────────────────────────────────────
    # Critères : uniquement . - / et espaces, tokens valides morse
    morse_clean = re.sub(r'\s+', ' ', stripped).strip()
    if len(morse_clean) >= 3:
        tokens = morse_clean.split()
        if (all(re.match(r'^[\.\-]+$', t) or t == '/' for t in tokens)
                and any(re.match(r'^[\.\-]+$', t) for t in tokens)):
            tags.append('morse')
            return tags

    # ── URL encodé (très certain si ≥2 séquences %XX) ────────────────────────
    if len(re.findall(r'%[0-9A-Fa-f]{2}', stripped)) >= 2:
        tags.append('url_encoded')
        return tags

    return []  # indéterminé — on ne touche PAS à l'ordre des ops


def reorder_ops_for_format(ops, format_tags):
    """Réordonne les ops selon le format détecté.
    Uniquement pour les formats certains : binary, octal, morse, url_encoded.
    """
    if not format_tags:
        return ops

    tag = format_tags[0]

    PRIORITY = {
        'binary':      {37},   # ← Binaire vers texte EN PREMIER
        'morse':       {54},   # ← Morse vers texte EN PREMIER
        'url_encoded': {60},   # URL decode EN PREMIER
    }

    priority_nums = PRIORITY.get(tag, set())
    if not priority_nums:
        return ops  # format non géré → ne pas toucher

    # Sur du binaire pur : César/ROT/Atbash n'ont aucun sens, les pousser en dernier
    if tag == 'binary':
        USELESS = (set(range(1, 28)) | {51, 52, 55, 56, 67, 68}
                   | {29, 30, 31, 64, 69, 70, 80, 81, 82, 83, 84, 85, 86, 87, 88})
        first  = [op for op in ops if op[0] in priority_nums]
        middle = [op for op in ops if op[0] not in priority_nums
                  and not (isinstance(op[0], int) and op[0] in USELESS)]
        last   = [op for op in ops if isinstance(op[0], int) and op[0] in USELESS]
        return first + middle + last

    # Autres formats : juste remonter les ops prioritaires en tête
    first  = [op for op in ops if op[0] in priority_nums]
    rest   = [op for op in ops if op[0] not in priority_nums]
    return first + rest

def build_operations(s, include_hash_ops=False):
    """
    Ordre INTENTIONNEL des opérations — crucial pour le mode auto :
    1. DECODE : les opérations de décodage passif (base64, hex, binaire...)
       → testées en PREMIER car ce sont les plus susceptibles de trouver
         directement le résultat en depth=1
    2. CIPHERS SIMPLES : César, ROT13, Atbash, XOR fixes
    3. TRANSFORMATIONS : case, reverse, leet, URL, morse...
    4. STRUCTURELLES : transposition, rail fence, vigenère brute...
    """
    ops = []

    # ── Groupe 1 : DECODERS — testés en premier ────────────────────────────────
    ops.append((41, "← Base64 vers texte",               from_base64))
    ops.append((42, "← Base32 vers texte",               from_base32))
    ops.append((35, "← Hexadécimal vers texte",          from_hex))
    ops.append((37, "← Binaire vers texte",              from_binary))
    ops.append((39, "← Octal vers texte",                from_octal))
    ops.append((33, "← Codes ASCII vers texte",          from_ascii_codes))
    ops.append((44, "← Unicode (U+XXXX) vers texte",     from_unicode_escape))
    ops.append((54, "← Morse vers texte",                morse_decode))
    ops.append((60, "URL decode",                        url_decode))

    # ── Groupe 2 : CIPHERS SIMPLES ─────────────────────────────────────────────
    ops.append((26, "ROT13",                             rot13))
    ops.append((101, "ROT47 (ASCII 33-126)",             rot47))
    ops.append((27, "Atbash",                            atbash))
    for shift in range(1, 26):
        ops.append((shift, f"César +{shift}", lambda x, sh=shift: caesar(x, sh)))
    for key in [1, 7, 13, 42, 85, 127]:
        ops.append((45 + [1,7,13,42,85,127].index(key),
                    f"XOR key={key}",
                    lambda x, k=key: xor_op(x, k)))
    ops.append((51, "AND 0xFF",                          lambda x: and_op(x, 0xFF)))
    ops.append((52, "OR 0x20 (lowercase trick)",         lambda x: or_op(x, 0x20)))
    ops.append((56, "Un-L33t speak",                     unleet_speak))
    ops.append((67, "Décalage ASCII +1",                 shift_one))
    ops.append((68, "Décalage ASCII -1",                 shift_minus_one))

    # ── Groupe 3 : TRANSFORMATIONS ─────────────────────────────────────────────
    ops.append((28, "Inversion (reverse)",               reverse))
    ops.append((29, "Swap case",                         swap_case))
    ops.append((30, "Tout en majuscules",                to_upper))
    ops.append((31, "Tout en minuscules",                to_lower))
    ops.append((57, "Chiffres → Lettres (1=A)",          numbers_to_letters))
    ops.append((58, "Lettres → Chiffres (A=1)",          letters_to_numbers))
    ops.append((62, "Supprimer espaces",                 remove_spaces))
    ops.append((72, "Supprimer espaces/tirets/_",        spaceless))
    ops.append((63, "Inverser l'ordre des mots",        reverse_words))
    ops.append((65, "Extraire les chiffres",             extract_numbers))
    ops.append((66, "Extraire les lettres",              extract_letters))
    ops.append((69, "Caractères pairs (0,2,4...)",       every_other))
    ops.append((70, "Caractères impairs (1,3,5...)",     every_other_reversed))
    ops.append((55, "L33t speak",                        leet_speak))
    ops.append((64, "AlTeRnAtE CaSe",                   alternate_case))
    ops.append((88, "Inverser deux moitiés",             interleave_reverse))
    ops.append((87, "Doubler chaque lettre",             double_letters))
    ops.append((85, "Supprimer voyelles",                remove_vowels))
    ops.append((86, "Garder voyelles seulement",         only_vowels))

    # ── Groupe 4 : ENCODERS (utiles pour depth=2+) ─────────────────────────────
    ops.append((34, "→ Hexadécimal",                     to_hex))
    ops.append((40, "→ Base64",                          to_base64))
    ops.append((32, "→ Codes ASCII",                     to_ascii_codes))
    ops.append((36, "→ Binaire",                         to_binary))
    ops.append((38, "→ Octal",                           to_octal))
    ops.append((43, "→ Unicode (U+XXXX)",                unicode_escape))
    ops.append((79, "→ Hex avec préfixe 0x",             to_hex_with_prefix))
    ops.append((53, "→ Morse",                           morse_encode))
    ops.append((59, "URL encode",                        url_encode))
    ops.append((61, "HTML entities",                     html_entities))

    # ── Groupe 5 : STRUCTURELLES / LENTES ──────────────────────────────────────
    for key in ["key", "abc", "secret", "haiti", "flag"]:
        ops.append((89 + ["key","abc","secret","haiti","flag"].index(key),
                    f"Vigenère decode (clé='{key}')",
                    lambda x, k=key: vigenere_decode(x, k)))
    ops.append((102, "César variable/mot",               caesar_variable_by_word))
    ops.append((103, "Vigenère brute (clés communes)",   vigenere_brute_common))
    ops.append((80, "Transposition colonnes (n=2)",      lambda x: column_transpose(x, 2)))
    ops.append((81, "Transposition colonnes (n=3)",      lambda x: column_transpose(x, 3)))
    ops.append((82, "Transposition colonnes (n=4)",      lambda x: column_transpose(x, 4)))
    ops.append((104, "Rail Fence décode (2 rails)",      rail_fence_2))
    ops.append((105, "Rail Fence décode (3 rails)",      rail_fence_3))
    ops.append((106, "Rail Fence décode (4 rails)",      rail_fence_4))
    ops.append((71, "Découpe en blocs de 4",             lambda x: chunks(x, 4)))
    ops.append((73, "Fréquence des caractères",          character_frequency))
    ops.append((74, "Position alphabet (A=1,B=2...)",    pigpen_numbers))
    ops.append((83, "Chiffre de Bacon",                  bacon_cipher))
    ops.append((84, "Clavier téléphone (T9)",            phone_keypad))

    # ── Groupe 6 : OPÉRATIONS SUR LES BITS ────────────────────────────────────
    ops.append((110, "NOT bit (7 bits, ASCII)",            bit_not))
    ops.append((111, "NOT bit complet (8 bits → hex)",     bit_not_full))
    ops.append((112, "Circular Left Shift (ROL) ×1",       circular_left_shift))
    ops.append((113, "Circular Left Shift (ROL) ×2",       circular_left_shift_2))
    ops.append((114, "Circular Left Shift (ROL) ×3",       circular_left_shift_3))
    ops.append((115, "Circular Left Shift (ROL) ×4",       circular_left_shift_4))
    ops.append((116, "Circular Right Shift (ROR) ×1",      circular_right_shift))
    ops.append((117, "Circular Right Shift (ROR) ×2",      circular_right_shift_2))
    ops.append((118, "Circular Right Shift (ROR) ×3",      circular_right_shift_3))
    ops.append((119, "Circular Right Shift (ROR) ×4",      circular_right_shift_4))
    ops.append((120, "Nibble Swap (échange 4 bits H/B)",   nibble_swap))
    ops.append((121, "Reverse bits par octet",             reverse_bits_per_byte))
    ops.append((122, "XOR moitié1 ⊕ moitié2",             xor_halves))
    ops.append((123, "NAND 0xFF",                          nand_op))
    ops.append((124, "NOR 0x00",                           nor_op))
    ops.append((125, "Popcount (nb bits à 1 par octet)",   popcount))
    ops.append((126, "Représentation binaire brute",       bits_to_binary))
    ops.append((127, "Décalage logique gauche (LSL) ×1",   logical_shift_left))
    ops.append((128, "Décalage logique droit  (LSR) ×1",   logical_shift_right))

    if include_hash_ops:
        ops.append((75, "Hash MD5",    md5_hash))
        ops.append((76, "Hash SHA1",   sha1_hash))
        ops.append((77, "Hash SHA256", sha256_hash))

    return ops

def xor_bruteforce(s, collector, search_haiti, depth=0, path=None,
                   max_depth=0, seen=None, ops=None, skip_repeated=False):
    """
    skip_repeated=True : ne teste que les 255 clés simples (pas les 9000 clés répétées).
    Utilisé au depth=2+ pour éviter une explosion combinatoire.
    """
    path = path or []
    seen = seen or set()

    def _try_recurse(r, cur_path):
        if not r or len(r) > 2000: return
        collector.add(depth, cur_path, s, r, search_haiti)
        if ops is not None and depth < max_depth:
            fp = r[:120]
            if fp not in seen:
                seen.add(fp)
                run_recursive(r, ops, depth + 1, max_depth,
                              search_haiti, cur_path, seen, collector)
                seen.discard(fp)

    def _try_terminal(r, cur_path):
        if not r or len(r) > 2000: return
        collector.add(depth, cur_path, s, r, search_haiti)

    # XOR simple : bytearray est ~5× plus rapide que join(chr(...) for ...)
    try:
        sb = s.encode('latin-1')
    except Exception:
        try:    sb = s.encode('utf-8')
        except: sb = None
    if sb:
        for k in range(1, 256):
            if PROGRESS.should_quit(): return
            try:
                rb = bytes(b ^ k for b in sb)
                r  = rb.decode('latin-1')
                PROGRESS.tick()
                _try_recurse(r, path + [(f"XF{k}", f"XOR brute key={k}")])
            except: pass
    else:
        for k in range(1, 256):
            if PROGRESS.should_quit(): return
            try:
                r = ''.join(chr(ord(ch) ^ k) for ch in s)
                PROGRESS.tick()
                _try_recurse(r, path + [(f"XF{k}", f"XOR brute key={k}")])
            except: pass

    if skip_repeated:
        return  # depth=2+ : on saute les clés répétées (trop lent ×N résultats)

    # XOR répété 2 chars — numpy quand disponible (38x plus rapide)
    # Stratégie : calculer le XOR en vectorisé, puis prescreen avant decode/add
    _NP = None
    try:
        import numpy as _np_mod
        _NP = _np_mod
    except ImportError:
        pass

    if sb and _NP is not None:
        sba = _NP.frombuffer(sb, dtype=_NP.uint8)
        slen = len(sb)
        # Pré-construire les indices pair/impair
        idx_even = _NP.arange(0, slen, 2)
        idx_odd  = _NP.arange(1, slen, 2)
        for k0 in range(32, 127):
            if PROGRESS.should_quit(): return
            for k1 in range(32, 127):
                if k0 == k1: continue
                try:
                    rb = sba.copy()
                    rb[idx_even] ^= k0
                    rb[idx_odd]  ^= k1
                    r = rb.tobytes().decode('latin-1')
                    # Prescreen avant add pour économiser find_words
                    if prescreen(r):
                        key_str = chr(k0) + chr(k1)
                        _try_terminal(r, path + [(f"XR{k0}_{k1}", f"XOR répété clé='{key_str}'")])
                except: pass
    elif sb:
        # Fallback sans numpy — même algo mais bytearray
        ba = bytearray(sb)
        slen = len(ba)
        for k0 in range(32, 127):
            if PROGRESS.should_quit(): return
            for k1 in range(32, 127):
                if k0 == k1: continue
                try:
                    rb = bytearray(ba[i] ^ (k0 if i % 2 == 0 else k1) for i in range(slen))
                    r  = rb.decode('latin-1')
                    if prescreen(r):
                        key_str = chr(k0) + chr(k1)
                        _try_terminal(r, path + [(f"XR{k0}_{k1}", f"XOR répété clé='{key_str}'")])
                except: pass
    else:
        for k0, k1 in itertools.product(range(32, 127), repeat=2):
            if PROGRESS.should_quit(): return
            if k0 == k1: continue
            try:
                r = ''.join(chr(ord(s[i]) ^ (k0 if i % 2 == 0 else k1)) for i in range(len(s)))
                if prescreen(r):
                    key_str = chr(k0) + chr(k1)
                    _try_terminal(r, path + [(f"XR{k0}_{k1}", f"XOR répété clé='{key_str}'")])
            except: pass

def _effective_caesar_shift(path):
    total = 0
    for (num, _) in path:
        if isinstance(num, int):
            if 1 <= num <= 25:   total += num
            elif num == 26:      total += 13
            elif num == 27:      return None
    return total % 26

def run_recursive(s, ops, depth, max_depth, search_haiti, path, seen, collector):
    if depth > max_depth: return
    current_caesar = _effective_caesar_shift(path)
    for (num, label, func) in ops:
        if PROGRESS.should_quit(): return
        # Ops bits : utiles seulement en depth=1 (décodage direct), exclues en depth>1
        if depth > 1 and isinstance(num, int) and num in BIT_OPS:
            continue
        try:
            if num in CAESAR_OPS and current_caesar is not None and depth > 1:
                new_shift = None
                if 1 <= num <= 25:  new_shift = (current_caesar + num) % 26
                elif num == 26:     new_shift = (current_caesar + 13) % 26
                if new_shift is not None:
                    fp_caesar = f"__caesar_{new_shift}_{s[:60]}"
                    if fp_caesar in seen: continue
                    seen.add(fp_caesar)
            result = func(s)
            PROGRESS.tick()
            if result is None: continue
            result_str = str(result)
            if len(result_str) < 1 or len(result_str) > 2000: continue
            if result_str == s: continue
            cur_path = path + [(num, label)]
            collector.add(depth, cur_path, s, result_str, search_haiti)
            if depth < max_depth:
                fp = result_str[:120]
                if fp not in seen:
                    seen.add(fp)
                    run_recursive(result_str, ops, depth + 1, max_depth,
                                  search_haiti, cur_path, seen, collector)
                    seen.discard(fp)
        except Exception: pass
    if depth <= max_depth:
        xor_bruteforce(s, collector, search_haiti,
                       depth=depth, path=path,
                       max_depth=max_depth, seen=seen, ops=ops)

def print_help():
    print("""Usage: python3 prushka.py <chaine> [code] [-h] [-v [N]] [-r N] [-w FILE]
  code 0 = toutes les opérations (défaut)
  -h     = cherche 'haiti'
  -v [N] = top N résultats triés (défaut 25)
  -r N   = récursif N niveaux
  -w F   = wordlist externe""")

def parse_flag_with_optional_int(args, flag, default_val):
    for i, a in enumerate(args):
        if a == flag:
            if i + 1 < len(args):
                try:
                    return True, int(args[i + 1])
                except ValueError:
                    pass
            return True, default_val
    return False, default_val

def parse_flag_with_required_int(args, flag, default_val):
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            try:
                val = int(args[i + 1])
                if val < 1:
                    print(f"❌ {flag} doit être >= 1"); sys.exit(1)
                return val
            except ValueError:
                print(f"❌ {flag} doit être suivi d'un entier."); sys.exit(1)
    return default_val

def main():
    args = sys.argv[1:]
    if '--help' in args or len(args) < 1:
        print_help(); sys.exit(0)

    search_haiti    = '-h' in args
    verbose, top_n  = parse_flag_with_optional_int(args, '-v', 25)
    recursive_depth = parse_flag_with_required_int(args, '-r', 0)
    wordlist_path   = None
    file_input      = None
    for i, a in enumerate(args):
        if a == '-w' and i + 1 < len(args): wordlist_path = args[i + 1]
        if a == '-f' and i + 1 < len(args): file_input    = args[i + 1]

    clean_args = []
    skip_next  = False
    for i, a in enumerate(args):
        if skip_next:       skip_next = False; continue
        if a in ('-r','-v'):
            if i + 1 < len(args):
                try: int(args[i + 1]); skip_next = True
                except ValueError: pass
            continue
        if a in ('-w', '-f'): skip_next = True; continue
        if a.startswith('-'): continue
        clean_args.append(a)

    if file_input is not None:
        try:
            with open(file_input, 'r', encoding='utf-8', errors='replace') as fh:
                s = fh.read().strip()
            if not s:
                print(c(C.RED, f"❌ Fichier vide : {file_input}")); sys.exit(1)
        except FileNotFoundError:
            print(c(C.RED, f"❌ Fichier introuvable : {file_input}")); sys.exit(1)
        code = 0
        for a in clean_args:
            try: code = int(a)
            except ValueError: pass
    else:
        if len(clean_args) < 1:
            print("❌ Usage: python3 prushka.py <chaine> [code] [-h] [-v [N]] [-r N]"); sys.exit(1)
        # Premier arg positionnel = chaîne, deuxième (optionnel) = code
        # On ne parse JAMAIS le premier arg comme entier même s'il est numérique
        if len(clean_args) == 0:
            print("❌ Usage: python3 prushka.py <chaine> [code] [-h] [-v [N]] [-r N]"); sys.exit(1)
        s    = clean_args[0]
        code = 0
        if len(clean_args) >= 2:
            try: code = int(clean_args[1])
            except ValueError:
                print(f"❌ Le code doit être un entier. Reçu: '{clean_args[1]}'"); sys.exit(1)

    R  = C.RED; W = C.WHITE; RS = C.RESET
    BOX_W = 72
    def row(label, val, highlight=False):
        col = C.RED2 if highlight else C.GREEN2
        label_w = 9
        val_clean = str(val).replace('\r','').replace('\n',' ')
        val_trunc = val_clean[:BOX_W - label_w - 4]
        pad = BOX_W - label_w - 4 - len(val_trunc)
        return f"{R}║{RS}  {W}{label:<{label_w}}{RS}: {col}{val_trunc}{RS}{' '*pad}{R}║{RS}"

    lines_in = s.splitlines()
    if len(lines_in) > 1:
        entree_display = f"{lines_in[0][:40]}… ({len(lines_in)} lignes)"
    else:
        entree_display = s
    rec_info = f"Oui ({recursive_depth} niveau{'x' if recursive_depth > 1 else ''})" if recursive_depth > 0 else "Non"
    v_info   = f"Top {top_n}" if verbose else "Hits uniquement"

    title = "PRUSHKA.PY - Analyse de chaîne"
    title_pad = BOX_W - len(title) - 2
    print(f"{R}╔{'═'*BOX_W}╗{RS}")
    print(f"{R}║{RS}  {C.BOLD}{W}{title}{RS}{' '*title_pad}{R}║{RS}")
    print(f"{R}╠{'═'*BOX_W}╣{RS}")
    print(row("Entrée",   entree_display))
    print(row("Code",     str(code)))
    print(row("Verbose",  v_info))
    print(row("Haiti",    "Oui (recherche active)" if search_haiti else "Non", highlight=search_haiti))
    print(row("Récursif", rec_info))
    if wordlist_path: print(row("Wordlist", wordlist_path))
    print(f"{R}╚{'═'*BOX_W}╝{RS}")
    print()

    global WORD_INDEX
    if wordlist_path:
        ext = load_external_wordlist(wordlist_path)
        merged = dict(WORD_INDEX)
        for w, sc in ext.items():
            merged[w] = max(merged.get(w, 0), sc // 1000)
        WORD_INDEX = merged
        _rebuild_word_patterns()   # recompile avec les nouveaux mots
        _rebuild_word_sets()       # recompile les sets 3/4+ chars
        print(c(C.GREEN2, f"  📖 Wordlist : {len(ext):,} mots chargés ({wordlist_path})"))

    ops      = build_operations(s, include_hash_ops=search_haiti)
    ops_dict = {op[0]: op for op in ops}
    run_all  = (code == 0)
    collector = ResultCollector()

    # ── Détection automatique du format d'entrée ────────────────────────────
    fmt_tags = detect_input_format(s)
    if fmt_tags and run_all:
        ops = reorder_ops_for_format(ops, fmt_tags)
        ops_dict = {op[0]: op for op in ops}
        fmt_name = {'binary':'Binaire','hex':'Hexadécimal','base64':'Base64',
                    'octal':'Octal','ascii_codes':'Codes ASCII',
                    'morse':'Morse','url_encoded':'URL encodé'}.get(fmt_tags[0], fmt_tags[0])
        print(f"  🔍 {c(C.CYAN,'Format détecté')} : {c(C.WHITE+C.BOLD, fmt_name)} "
              f"{c(C.GREY,'— opérations correspondantes prioritaires')}")

    if not run_all and code == 94:
        xor_bruteforce(s, collector, search_haiti)
        collector.display_top(top_n if verbose else len(collector.results))
        return
    if not run_all and code == 95:
        for keylen in range(2, 4):
            for key_bytes in itertools.product(range(32, 128), repeat=keylen):
                try:
                    r = ''.join(chr(ord(s[i]) ^ key_bytes[i % keylen]) for i in range(len(s)))
                    key_str = ''.join(chr(k) for k in key_bytes)
                    collector.add(0, [(95, f"XOR répété clé='{key_str}'")], s, r, search_haiti)
                except: pass
        collector.display_top(top_n if verbose else len(collector.results))
        return

    if run_all:      selected = ops
    elif code in ops_dict: selected = [ops_dict[code]]
    else:
        print(f"❌ Code {code} non reconnu."); sys.exit(1)

    seen = {s[:120]}
    n_normal = len(selected)
    n_xor    = 255 + (95 * 94)
    if recursive_depth > 0:
        ops_estimate = (n_normal + n_xor) * (n_normal ** max(0, recursive_depth - 1))
    else:
        ops_estimate = n_normal + n_xor
    PROGRESS.start(ops_estimate, collector)

    if recursive_depth > 0:
        print(f"  🔁 {c(C.RED,'Mode récursif')} — {c(C.WHITE,str(recursive_depth))} niveau{'x' if recursive_depth>1 else ''} {c(C.GREY,'(analyse en cours...)')}")
        run_recursive(s, selected, depth=1, max_depth=recursive_depth,
                      search_haiti=search_haiti, path=[],
                      seen=seen, collector=collector)
        if run_all:
            # XOR brute sur l'entrée directe
            xor_bruteforce(s, collector, search_haiti, depth=0, path=[],
                           max_depth=recursive_depth, seen=seen, ops=selected)
    else:
        # ── Mode auto : depth=1 strict (chaque op seule), puis 2, puis 3
        #
        # depth=1 : on teste chaque opération sur s, on collecte les hits.
        #           XOR brute (255 clés) aussi.
        #           Si on a au moins 1 hit avec score >= GOOD_SCORE → on s'arrête.
        #
        # depth=2 : on reprend chaque résultat de depth=1 et on reteste toutes les ops.
        #           (combinaisons op1 → op2)
        #
        # depth=3 : pareil depuis les résultats de depth=2.
        #
        # On s'arrête dès qu'un bon résultat est trouvé.
        # Le XOR répété est fait uniquement au depth=1 (trop lent sinon).
        GOOD_SCORE = 15.0   # score à partir duquel on considère avoir trouvé quelque chose

        print(f"  🔍 {c(C.RED,'Mode auto')} {c(C.GREY,'(depth 1 → 2 → 3, stop si résultat clair)')}")

        # ── depth 1 : chaque op seule — parallélisé ────────────────────────────
        depth1_results = []   # (result_str, path)

        def _run_one(args):
            num, label, func, s = args
            try:
                r = func(s)
                if r is None: return None
                r = str(r)
                if not r or r == s or len(r) > 2000: return None
                return (num, label, r)
            except Exception:
                return None

        n_workers = min(8, len(selected))
        tasks = [(num, label, func, s) for (num, label, func) in selected]
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
            futures = {pool.submit(_run_one, t): t for t in tasks}
            for fut in concurrent.futures.as_completed(futures):
                if PROGRESS.should_quit(): break
                res = fut.result()
                if res is None: continue
                num, label, r = res
                PROGRESS.tick()
                collector.add(1, [(num, label)], s, r, search_haiti)
                depth1_results.append((r, [(num, label)]))

        # XOR brute depth=1
        if run_all and not PROGRESS.should_quit():
            xor_bruteforce(s, collector, search_haiti, depth=0, path=[],
                           max_depth=0, seen=seen, ops=None)
            xor_set = {r for r, _ in depth1_results}
            for entry in collector.results:
                _, _, path, _, result_str, _, _, _, _ = entry
                if len(path) == 1 and str(path[0][0]).startswith('X'):
                    if result_str not in xor_set:
                        depth1_results.append((result_str, path))
                        xor_set.add(result_str)

        best1 = max((r[0] for r in collector.results), default=0)
        n1    = len(collector.results)
        print(f"  {c(C.GREY, f'  depth=1 : {n1} hits, meilleur score={best1:.1f}')}")
        if best1 >= GOOD_SCORE or PROGRESS.should_quit():
            pass  # on affichera en bas
        else:
            # ── depth 2 : op1 → op2 — parallélisé ───────────────────────────────
            seen_d2 = set()
            depth2_results = []

            # Dédupliquer les r1 (même résultat peut venir de chemins différents)
            unique_r1 = []
            seen_r1   = set()
            for (r1, path1) in depth1_results:
                fp = r1[:120]
                if fp not in seen_r1:
                    seen_r1.add(fp)
                    unique_r1.append((r1, path1))

            def _run_d2(args):
                r1, path1, num, label, func = args
                try:
                    r2 = func(r1)
                    if r2 is None: return None
                    r2 = str(r2)
                    if not r2 or r2 == r1 or r2 == s or len(r2) > 2000: return None
                    return (r1, path1, num, label, r2)
                except Exception:
                    return None

            tasks2 = [
                (r1, path1, num, label, func)
                for (r1, path1) in unique_r1
                for (num, label, func) in selected
            ]
            with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
                futures2 = {pool.submit(_run_d2, t): t for t in tasks2}
                for fut in concurrent.futures.as_completed(futures2):
                    if PROGRESS.should_quit(): break
                    res = fut.result()
                    if res is None: continue
                    r1, path1, num, label, r2 = res
                    PROGRESS.tick()
                    path2 = path1 + [(num, label)]
                    collector.add(2, path2, r1, r2, search_haiti)
                    depth2_results.append((r2, path2))

            # XOR brute sur chaque r1 unique
            # - clés simples (255) : toujours
            # - clés répétées (9000) : seulement si r1 vient d'un décodeur
            #   (hex, base64, etc.) — pas sur les 20+ résultats César
            DECODE_NUMS = {41, 42, 35, 37, 39, 33, 44, 54, 60}  # ops decode
            if run_all and not PROGRESS.should_quit():
                for (r1, path1) in unique_r1:
                    if PROGRESS.should_quit(): break
                    from_decoder = path1 and isinstance(path1[0][0], int) and path1[0][0] in DECODE_NUMS
                    xor_bruteforce(r1, collector, search_haiti, depth=1, path=path1,
                                   max_depth=0, seen=seen_d2, ops=None,
                                   skip_repeated=not from_decoder)

            best2 = max((r[0] for r in collector.results), default=0)
            n2    = len(collector.results) - n1
            print(f"  {c(C.GREY, f'  depth=2 : {n2} hits, meilleur score={best2:.1f}')}")
            if best2 >= GOOD_SCORE or PROGRESS.should_quit():
                pass
            else:
                # ── depth 3 : op1 → op2 → op3 ───────────────────────────────
                seen_d3 = set()
                for (r2, path2) in depth2_results:
                    if PROGRESS.should_quit(): break
                    fp = r2[:120]
                    if fp in seen_d3: continue
                    seen_d3.add(fp)
                    for (num, label, func) in selected:
                        if PROGRESS.should_quit(): break
                        try:
                            r3 = func(r2)
                            PROGRESS.tick()
                            if r3 is None: continue
                            r3 = str(r3)
                            if not r3 or r3 == r2 or len(r3) > 2000: continue
                            path3 = path2 + [(num, label)]
                            collector.add(3, path3, r2, r3, search_haiti)
                        except Exception: pass

                best3 = max((r[0] for r in collector.results), default=0)
                n3    = len(collector.results) - n1 - n2
                print(f"  {c(C.GREY, f'  depth=3 : {n3} hits, meilleur score={best3:.1f}')}")

    PROGRESS.stop()
    PROGRESS.restore_terminal()
    display_n = top_n if verbose else len(collector.results)
    collector.display_top(display_n)

    total    = len(collector.results)
    mode_str = f"récursif {recursive_depth} niveau{'x' if recursive_depth>1 else ''}" if recursive_depth > 0 else "plat"
    sep      = c(C.RED, "═" * 72)
    print(f"\n{sep}")
    print(f"  {c(C.WHITE,'Analyse terminée')} {c(C.GREY,f'[{mode_str}]')}. {c(C.RED2,str(total))} {c(C.WHITE,'hit(s) notable(s).')}")
    print(f"{sep}\n")

if __name__ == '__main__':
    main()