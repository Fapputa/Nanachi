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
                # Ligne status : tronquée à 110 chars ANSI-stripped
                line_raw = f"#{i} {score:>7.1f}  {path_short}  {clean_res}{ctf_str}"
                line_raw = line_raw[:108]  # limite stricte
                lines.append(
                    f"  {c(C.RED2, f'#{i}')}  {c(C.WHITE, f'{score:>7.1f}')}  "
                    f"{c(GY, path_padded[:30].ljust(30))}  "
                    f"{c(C.GREEN2, clean_res[:32])}"
                    f"{c(C.RED2, ctf_str[:12]) if ctf_str else ''}"
                )
        lines.append(f"  {c(C.RED,'─'*60)}")
        lines.append("")
        sys.stderr.write("\n".join(lines) + "\n")
        sys.stderr.flush()

PROGRESS = Progress()

# ── Garbage Memoization ───────────────────────────────────────────────────────
_SEEN_GARBAGE: set = set()

# ── Flag Fast-Path ────────────────────────────────────────────────────────────
FLAG_FOUND        = threading.Event()
FLAG_FOUND_RESULT: list = []
_FLAG_REGEX = re.compile(
    r'(?i)'
    # Formats délimités : CTF{...} flag{...} HTB{...}
    r'(ctf|flag|htb|thm|picoctf|root\.?me|hackthebox)\s*[\{(]\s*.{2,80}'
    # Formats avec séparateur : flag=xxx, flag:xxx, flag_xxx
    r'|(flag|ctf)\s*[=:_\-][a-zA-Z0-9_\-\.]{2,}'
    # Mot "flag" dans contexte propre (testflag, flagvalue, myflag123)
    r'|(test|my|the|your|this|a)?flag[a-zA-Z0-9_]{0,20}'
)

def fast_entropy(s: str) -> float:
    """Entropie de Shannon rapide sur les chars imprimables."""
    chars = [ch for ch in s if ch.isprintable()]
    n = len(chars)
    if n < 4: return 0.0
    fq: dict = {}
    for ch in chars: fq[ch] = fq.get(ch, 0) + 1
    return -sum((v / n) * math.log2(v / n) for v in fq.values())

def _load_words():
    import zlib, base64
    _D = (
        "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"
        "YEPmy/wwAsbqH70krF39oTr1B0GR/wMd3cdG"
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
    # Mots français fréquents dans les CTF francophones
    "bravo","valider","valide","avec","peux","vous","bien","pass",
    "code","clef","cle","secret","solution","reponse","gagner","trouve",
    "felicitations","bienvenue","bonjour","correct","niveau","etape",
]
CTF_HIGH_SCORE = {'flag','password','passwd','token','secret','admin','root','login','robot','mrrobot','valider','valide','bravo','felicitations','gagner','solution','reponse','trouve'}
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
DECODE_OPS     = {33, 35, 37, 39, 41, 42, 44, 54, 60, 140}

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


_B64_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')

def looks_like_b64_intermediate(s):
    """Détecte si une chaîne ressemble à du Base64 (encodé ou renversé).
    Critères cumulatifs :
      - Au moins 8 chars, majorité de charset Base64
      - Entropie de Shannon entre 3.0 et 6.5 (plage typique Base64, seuil bas pour courtes chaînes)
      - Commence par '==' OU finit par '=' → très fort indicateur (court-circuit)
    Retourne True pour laisser passer dans prescreen même sans 4-gram connu.
    """
    stripped = s.strip()
    if len(stripped) < 8:
        return False
    # Ratio de chars Base64
    b64_count = sum(1 for c in stripped if c in _B64_CHARS)
    if b64_count / len(stripped) < 0.90:
        return False
    # Indicateurs forts : padding '=' visible → court-circuit avant calcul entropie
    if stripped.startswith('==') or stripped.endswith('='):
        return True
    # Entropie Shannon (seuil bas à 3.0 pour couvrir les courtes chaînes Base64)
    fq = {}
    for c in stripped: fq[c] = fq.get(c, 0) + 1
    n = len(stripped)
    ent = -sum((v/n)*math.log2(v/n) for v in fq.values())
    return 3.0 <= ent <= 6.5


def is_garbage_branch(s: str) -> bool:
    """Retourne True si la chaîne est une branche morte.
    Ordre : memoization O(1) → printable ratio → char dominant → entropie.
    N.B. : ne rejette PAS les Base64 valides (entropie ~5–6 mais décodables).
    """
    fp = s[:80]
    if fp in _SEEN_GARBAGE:
        return True
    printable = [ch for ch in s if ch.isprintable()]
    n_print = len(printable)
    n_total = max(1, len(s))
    if n_print / n_total < 0.70:
        _SEEN_GARBAGE.add(fp); return True
    if n_print >= 4:
        fq: dict = {}
        for ch in printable: fq[ch] = fq.get(ch, 0) + 1
        if max(fq.values()) / n_print > 0.50:
            _SEEN_GARBAGE.add(fp); return True
    if n_print >= 8:
        ent = fast_entropy(s)
        if ent > 4.8 and not looks_like_b64_intermediate(s):
            _SEEN_GARBAGE.add(fp); return True
    return False


def prescreen(s):
    """Filtre ultra-rapide (set lookup) — rejette les chaînes sans aucun 4-gram connu.
    Doit être appelé AVANT find_words pour économiser 99% des appels dans les boucles XOR.
    Retourne True si la chaîne POURRAIT contenir un mot connu (peut avoir faux positifs).
    Également True si la chaîne ressemble à un intermédiaire Base64 (pour permettre
    la récursion depth+1 même sans mot du dictionnaire).
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
    # Laisse passer les intermédiaires qui ressemblent à du Base64 encapsulé
    if looks_like_b64_intermediate(s):
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
    # Mots 3 chars : ignorés pour le scoring (trop de faux positifs)
    # Le prescreen les utilise toujours pour ne pas les rater complètement
    # mais ils ne génèrent pas de hits dans find_words
    if search_haiti and (_HAITI_PAT.search(lower) or (_use_leet and _HAITI_PAT.search(leet_lower))):
        hits.append('haiti')
    return hits


def detect_ctf_keywords(s):
    """Détecte les mots CTF — uniquement mots >= 4 chars (pas de iv, key, xor, etc.)"""
    lower      = s.lower()
    _alpha_r2 = sum(1 for c in s if c.isalpha()) / max(1, len(s))
    leet_lower = _normalize_leet(s) if _alpha_r2 >= 0.30 else s.lower()
    found = []
    for kw in CTF_KEYWORDS:
        if len(kw) < 4:
            continue  # jamais de badge pour les mots <= 3 chars
        if kw == 'pass':
            continue  # 'pass' = 4 chars mais trop générique sans contexte
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

def detect_repetition_ratio(s):
    """Détecte si une chaîne est majoritairement un motif répété.
    Ex : 'lEnFoGmlEnFoGmlEnFo' → period=7, ratio≈0.95
    Retourne le ratio de répétition [0.0, 1.0]. 0.0 = pas de répétition.
    Teste les périodes de 2 à len//3. Cutoff rapide à 3 répétitions minimum.
    """
    n = len(s)
    if n < 8:
        return 0.0
    # Limite la période max à min(40, n//3) pour les longues chaînes
    max_period = min(40, n // 3)
    best = 0.0
    for period in range(2, max_period + 1):
        pattern = s[:period]
        matched = 0
        for i in range(0, n - period + 1, period):
            if s[i:i+period] == pattern:
                matched += 1
            else:
                break  # rupture → stop pour cette période
        if matched >= 3:
            ratio = (matched * period) / n
            if ratio > best:
                best = ratio
    return best


def get_structure_bonus(text):
    """Bonus de score pour les structures reconnues comme pivots utiles ou flags CTF.

    Trois catégories :
    A. Flag CTF explicite : CTF{...}, flag{...}, FLAG_...  → +50 (très fort signal)
    B. Keyword CTF dans token propre : testflag, flag123, ctf_pass  → +20
       Distinct du word_bonus normal qui pénalise les mots sans séparateur (×0.08)
       Ici on récompense la présence de mots CTF dans un contexte PROPRE (≥85% alnum)
    C. Pivot encodage : Base64-like ou hex pur décodable → +12
       Permet au mode récursif de garder ces intermédiaires dans le top même sans mots

    Retourne un float (0.0 si rien trouvé).
    """
    bonus = 0.0
    t = text.strip()
    tl = t.lower()

    # ── A. Patterns flag CTF explicites ──────────────────────────────────────
    # flag{...} CTF{...} HTB{...} → certitude maximale
    if re.search(r'(?i)(ctf|flag|htb|thm|picoctf|root.?me)\s*[{(]\s*.{2,60}\s*[})]', t):
        bonus += 80.0
    # flag=xxx  flag:xxx  FLAG=xxx
    elif re.search(r'(?i)(flag|ctf)\s*[=:]\s*[a-zA-Z0-9_\-.]{2,}', t):
        bonus += 60.0
    # flag_xxx  FLAG-xxx
    elif re.search(r'(?i)(flag|ctf)[_\-][a-zA-Z0-9_\-]{2,}', t):
        bonus += 50.0

    # ── B. Keyword CTF dans un token majoritairement propre ──────────────────
    # "testflag", "flagvalue", "myflag123" → contexte propre (alnum + underscore)
    if bonus == 0.0:
        _alnum_ratio = sum(1 for c in t if c.isalnum() or c in '_-') / max(1, len(t))
        if _alnum_ratio >= 0.85:
            CTF_EMBEDDED = {'flag', 'pass', 'key', 'root', 'hash', 'code', 'user',
                            'token', 'secret', 'admin', 'login', 'crack', 'decode'}
            for kw in CTF_EMBEDDED:
                if kw in tl:
                    bonus += 40.0   # contexte propre + mot CTF → boost fort
                    break
    # ── C. Pivot encodage : intermédiaire Base64 ou hex pur ──────────────────
    # Ces chaînes ne contiennent pas de mots du dico mais sont décodables
    # → bonus pour les maintenir dans les résultats et déclencher la récursion
    if looks_like_b64_intermediate(t):
        bonus += 12.0
    elif is_pure_hex_string(t):
        bonus += 8.0

    return bonus


def compute_score(result_str, words, has_haiti, search_str=None):
    """
    Scoring basé sur la recherche académique (practicalcryptography.com) :

    1. BIGRAM FITNESS  — log-probability sur le corpus anglais (primary pour texte long)
    2. IC SCORE        — index de coïncidence (distingue mono vs poly)
    3. BASE FITNESS    = bg×0.70 + ic_score, modulé par longueur + ratio alpha
    4. ENTROPIE        — pénalise entropie > 5.5 (bruit) et < 1.5 (répétitions)
                         EXCEPTION : intermédiaires Base64 exemptés de pénalité
    5. PÉNALITÉ NATO   — résultats où >30% des tokens sont des mots OTAN
    6. WORD BONUS      — additif pur : chaque mot trouvé = +pts proportionnels à sa longueur
       - Mots longs (≥6 chars) : signal fort même seuls (dolphin88, password, mrrobot)
       - Mots courts (4 chars) : pénalisés s'ils sont isolés sans contexte ;
                                 pénalité douce s'ils sont collés à d'autres lettres
                                 (ex: "testflag" → flag reçoit ×0.45 au lieu de ×0.08)
    7. PÉNALITÉ RÉPÉTITION — détecte les sous-motifs répétés ≥3× ("lEnFoGmlEnFoGm...")
                             et réduit le base_fitness en conséquence
    8. BONUS STRUCTURE — récompense les résultats qui contiennent un pivot décodable :
       - Pattern CTF explicite (CTF{...}, FLAG:, htb{...}) → +35 pts
       - "flag" collé dans une chaîne longue (testflag, flagveryeasy) → +12 pts
       - Résultat pur Base64 décodable en texte lisible → +20 pts (pivot récursif)
       - Hex pur ≥10 chars dans le résultat → +12 pts

    Formule finale :
        score = base_fitness × rep_penalty + word_bonus + structure_bonus
    """
    if not result_str:
        return 0.0

    total_len = len(result_str)
    n_printable = sum(1 for ch in result_str if ch.isprintable())
    if n_printable / max(1, total_len) < 0.70:
        return 0.01

    # ── Pénalité "charabia" : trop de symboles bizarres = résultat de cipher sur bruit ──
    # Caractères typiques du bruit XOR/César appliqué sur du hex ou du base64 :
    # @, :, [, ], {, }, ^, ~, |, \, `, <, >, ?, #, $, %, &, *, +, ;
    # NOTE : '!' retiré — ponctuation normale dans "Bravo !", "Well done!", etc.
    _JUNK_CHARS = set('@:[]{}^~|\\`<>?#$%&*+;')
    _nonspace   = [ch for ch in result_str if ch not in (' ', '\n', '\t')]
    _junk_ratio = 0.0
    if _nonspace:
        _junk_ratio = sum(1 for ch in _nonspace if ch in _JUNK_CHARS) / len(_nonspace)
    if _junk_ratio > 0.20:
        # Réduction agressive : 20% junk → ×0.3 ; 40%+ junk → ×0.05
        _junk_mult = max(0.05, 1.0 - (_junk_ratio - 0.20) * 4.75)
        return round(0.01 + _junk_mult * 0.5, 3)  # retour précoce, score ≤ 0.5

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
        # Si la chaîne ressemble à un intermédiaire Base64 (entropie typique ~5-6),
        # ne PAS pénaliser — elle sera décodée à l'étape suivante
        _is_b64_like = looks_like_b64_intermediate(result_str)
        if _ent > 5.5 and not _is_b64_like:
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

    # ── 6. Pénalité répétition ────────────────────────────────────────────
    # Une chaîne répétitive (lEnFoGmlEnFo...) peut avoir un bon IC/bigram
    # mais c'est du bruit de cipher — on l'écrase si répétition > 60%
    _rep_ratio = detect_repetition_ratio(result_str)
    if _rep_ratio >= 0.60:
        # 60% répétition → ×0.25 ; 85%+ → ×0.05
        _rep_mult = max(0.05, 1.0 - (_rep_ratio - 0.60) * 4.0)
        base_fitness *= _rep_mult

    # ── 7. WORD BONUS (additif pur) ───────────────────────────────────────
    # Principe : chaque mot trouvé ajoute des points DIRECTEMENT au score,
    # proportionnellement à sa longueur. Un password de 8 chars = ~50pts seul.
    # Les mots courts (4-5 chars) pénalisés s'ils sont sans contexte.
    _wstr   = search_str if search_str is not None else result_str
    tl      = _wstr.lower()
    _alpha_r = sum(1 for c in _wstr if c.isalpha()) / max(1, len(_wstr))
    leet_tl  = _normalize_leet(_wstr) if _alpha_r >= 0.30 else tl

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
        # EXCEPTION : si le mot 4-chars est collé à d'autres lettres (ex: "testflag",
        # "flagveryeasy", "flag123"), c'est probablement un vrai terme CTF.
        # On ne pénalise QUE si le mot est isolé dans du bruit sans voisins alpha.
        if klen == 4 and not _has_sep(fi, k):
            i2_k = fi.find(k)
            # Vérifier si le mot est entouré d'autres lettres (= partie d'un mot composé)
            left_alpha  = i2_k > 0 and fi[i2_k-1].isalpha()
            right_alpha = (i2_k + klen < len(fi)) and fi[i2_k + klen].isalpha()
            if left_alpha or right_alpha:
                # Collé à d'autres lettres : mot composé → pénalité douce seulement
                kw_pts *= 0.45
            else:
                kw_pts *= 0.08   # isolé sans contexte → ~92% de réduction

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

    # ── 7. Pénalité répétition : chaînes qui répètent le même motif ───────
    # "lEnFoGmlEnFoGmlEnFoGm..." → bigram score élevé par artefact de répétition
    # Méthode : chercher le plus court sous-motif répété ≥3 fois
    _rep_penalty = 1.0
    _s_clean = re.sub(r'\s+', '', result_str.lower())
    if len(_s_clean) >= 6:
        for _plen in range(2, len(_s_clean) // 3 + 1):
            _pat = _s_clean[:_plen]
            _count = 0
            _pos = 0
            while _pos <= len(_s_clean) - _plen:
                if _s_clean[_pos:_pos+_plen] == _pat:
                    _count += 1
                    _pos += _plen
                else:
                    break
            if _count >= 3:
                # La chaîne commence par un motif répété ≥3× → pénalité proportionnelle
                _rep_ratio = (_count * _plen) / max(1, len(_s_clean))
                _rep_penalty = max(0.08, 1.0 - _rep_ratio * 0.9)
                break
    base_fitness *= _rep_penalty

    # ── 8. Bonus structure : résultat qui ressemble à un format pivot ────────
    # Cas A : contient un pattern type flag (CTF{...}, FLAG:..., flag_...)
    # Cas B : le résultat entier ressemble à du Base64 décodable → pivot récursif
    # Cas C : contient un hex continu décodable ≥10 chars → pivot hex
    structure_bonus = 0.0
    _wstr_stripped = _wstr.strip()

    # Cas A — pattern flag explicite (fort signal CTF)
    if re.search(r'(?i)(ctf|flag|htb|thm|root|picoctf)\s*[\{:_\-]', _wstr_stripped):
        structure_bonus += 35.0
    elif re.search(r'(?i)flag', _wstr_stripped) and len(_wstr_stripped) >= 5:
        # "flag" dans une chaîne longue (testflag, flagveryeasy) → bonus modéré
        structure_bonus += 12.0

    # Cas B — résultat intermédiaire : pure Base64 décodable (pivot récursif)
    if looks_like_b64_intermediate(_wstr_stripped):
        try:
            _test_decode = from_base64(_wstr_stripped)
            if _test_decode and len(_test_decode) >= 3:
                # Vérifier que le décodage donne quelque chose de lisible
                _print_ratio = sum(1 for c in _test_decode if c.isprintable()) / len(_test_decode)
                if _print_ratio > 0.85:
                    structure_bonus += 20.0  # pivot Base64 → valeur pour la récursion
        except Exception:
            pass

    # Cas C — pur hex continu ≥10 chars dans le résultat → pivot hex
    if is_pure_hex_string(_wstr_stripped) and len(_wstr_stripped) >= 10:
        structure_bonus += 12.0

    score = base_fitness + word_bonus + structure_bonus
    # ── Pénalité finale : mots trouvés dans un contexte de symboles ──────────
    if word_bonus > 0 and _nonspace:
        _junk_in_ctx = sum(1 for ch in _nonspace if ch in _JUNK_CHARS) / len(_nonspace)
        if _junk_in_ctx > 0.10:
            _ctx_penalty = max(0.15, 1.0 - _junk_in_ctx * 3.0)
            score = base_fitness + word_bonus * _ctx_penalty

    # ── Bonus de structure ────────────────────────────────────────────────────
    # Ajouté APRÈS le word_bonus pour ne pas interférer avec ses pénalités
    # Récompense : flags CTF explicites, pivots Base64/hex, keywords dans contexte propre
    _struct_bonus = get_structure_bonus(result_str)
    score += _struct_bonus

    # ── Bonus "espaces naturels" ──────────────────────────────────────────────
    # Si le résultat contient des espaces (César ASCII sur une phrase), le scoring
    # bigram/IC sous-évalue car il travaille sur les alpha uniquement.
    # On récompense les résultats où les espaces découpent des mots lisibles.
    _words_in_result = result_str.split()
    if len(_words_in_result) >= 3:
        _alpha_word_ratio = sum(1 for w in _words_in_result if w.isalpha()) / len(_words_in_result)
        if _alpha_word_ratio >= 0.50:
            # Phrase avec majorité de mots purement alpha = très probablement du texte clair
            _space_bonus = min(25.0, len(_words_in_result) * 2.5 * _alpha_word_ratio)
            score += _space_bonus

    # ── Bonus mots français ─────────────────────────────────────────────────
    # WORD_INDEX est anglais — ces mots ne reçoivent pas de word_bonus normal.
    _FR_HIGH = {"valider","valide","alider","alide","felicitations","bravo","brao",
                "gagner","solution","reponse","trouve","bienvenue","correct"}
    _FR_MED  = {"avec","aec","peux","vous","bien","code","clef","solaire","merci",
                "bonjour","niveau","etape","correct","mdp","motdepasse"}
    _rl = result_str.lower()
    for _fw in _FR_HIGH:
        if _fw in _rl:
            score += len(_fw) * 6.0
    for _fw in _FR_MED:
        if _fw in _rl:
            score += len(_fw) * 2.5

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
        # ── Fast-exit si un flag a déjà été trouvé ───────────────────────────

        # ── Garbage branch filter (depth > 1 seulement) ──────────────────────
        if depth > 1 and is_garbage_branch(result_str):
            return False
        # ── Prescreen ultra-rapide : rejette 99% des chaînes bruit avant tout traitement ──
        _search_str = re.sub(r"^\[clé='[^']*'\]\s*", '', result_str)
        _check_hash = not _suppress_hash_detection(path, parent_str, result_str)
        h_candidate = looks_like_hash(result_str) if _check_hash else None
        # Si pas de hash ET pas de prescreen → sortie immédiate (chemin chaud)
        if h_candidate is None and not prescreen(_search_str):
            return False
        # ── Rejet si le parent contient trop de bytes de contrôle ────────────
        # Un vrai encodage CTF part de texte lisible, pas de bytes binaires
        # Si le parent (résultat intermédiaire) a >15% de chars non-printables
        # le résultat final est du bruit XOR sur données binaires → rejeter
        if parent_str and len(parent_str) > 3:
            ctrl = sum(1 for c in parent_str
                       if (ord(c) < 32 and c not in '\t\n\r') or ord(c) > 126)
            if ctrl / len(parent_str) > 0.15:
                return False
        # ── Déduplification par résultat normalisé ────────────────────────────
        norm = result_str.strip().lower()
        if norm in self._seen_res:
            idx = self._seen_res[norm]
            if len(path) < len(self.results[idx][2]):
                old = self.results[idx]
                self.results[idx] = (old[0], old[1], path, old[3], old[4], old[5], old[6], old[7], old[8])
            return False
        # ── Matching complet uniquement si le prescreen a passé ──────────────
        words     = find_words(_search_str, search_haiti=search_haiti)
        has_haiti = search_haiti and 'haiti' in _search_str.lower()
        ctf_tags  = detect_ctf_keywords(_search_str)
        _is_pivot = looks_like_b64_intermediate(_search_str) or is_pure_hex_string(_search_str)
        interesting = bool(words) or bool(h_candidate) or has_haiti or bool(ctf_tags) or _is_pivot
        if not interesting:
            return False
        score = compute_score(result_str, words, has_haiti, search_str=_search_str)
        if h_candidate and not words and not ctf_tags:
            score = max(score, 1.0)
        if _is_pivot and not words and not ctf_tags and score < 5.0:
            score = 5.0
        self._seen_res[norm] = len(self.results)
        self.results.append((score, depth, path, parent_str, result_str, words, h_candidate, has_haiti, ctf_tags))
        # FLAG : signal visuel uniquement, JAMAIS d'arrêt
        if score >= 110.0 and _FLAG_REGEX.search(result_str):
            FLAG_FOUND.set()
            FLAG_FOUND_RESULT.clear()
            path_str = " → ".join(lbl for _, lbl in path[-3:])
            FLAG_FOUND_RESULT.append((score, path_str, result_str))
            sys.stderr.write(
                f"\n{C.GREEN2}{C.BOLD}  🚩 FLAG probable (score={score:.1f}) — analyse continue...{C.RESET}\n"
                f"  Chemin : {path_str}\n"
                f"  Résultat : {result_str[:120]}\n\n"
            )
            sys.stderr.flush()
            # PAS DE STOP. L'analyse continue jusqu'au bout.
        return True

    def display_top(self, top_n):
        if not self.results:
            print(c(C.RED, "  Aucun résultat intéressant trouvé."))
            return
        sorted_results = sorted(self.results, key=lambda x: -x[0])
        total = len(sorted_results)
        shown = min(top_n, total)

        _ANSI = re.compile(r'\033\[[0-9;]*m')
        def _vis(s):
            return len(_ANSI.sub('', s))
        def _cell(text, width, color=None, rjust=False):
            """Cellule à largeur visible fixe, tronquée si besoin."""
            plain = _ANSI.sub('', text)
            if len(plain) > width:
                plain = plain[:width-1] + '…'
            if rjust:
                plain = plain.rjust(width)
            else:
                plain = plain.ljust(width)
            return c(color, plain) if color else plain
        def _clean_val(s):
            s = _ANSI.sub('', s)
            s = re.sub(r'[\n\r\t]', ' ', s)
            s = re.sub(r'[\x00-\x1f\x7f]', '', s)
            return re.sub(r' {2,}', ' ', s).strip()

        # Largeurs des colonnes — autoscale selon la taille du terminal
        try:
            import os as _os
            term_w = _os.get_terminal_size().columns
        except Exception:
            term_w = 120
        # Overhead fixe : 2 (indent) + 7 séparateurs × 3 (│ + 2 espaces) + colonnes fixes
        _fixed = 2 + 7 * 3 + 3 + 7 + 12   # indent + pipes/spaces + RK + SC + BR
        _flex  = max(30, term_w - _fixed)
        W_RK = 3
        W_SC = 7
        W_BR = 12
        W_PT = max(12, int(_flex * 0.30))
        W_VL = max(16, int(_flex * 0.45))
        W_TG = max(8,  _flex - W_PT - W_VL)

        # Caractères de bordure Unicode
        TL, TR, BL, BR = '╭', '╮', '╰', '╯'
        LM, RM          = '├', '┤'
        VB              = '│'
        HB, HC          = '─', '┬'
        HM              = '┼'
        BH              = '┴'

        def _hline(left, mid, right, sep):
            parts = [HB*(W_RK+2), HB*(W_SC+2), HB*(W_BR+2), HB*(W_PT+2), HB*(W_VL+2), HB*(W_TG+2)]
            return left + sep.join(parts) + right

        sep_top = _hline(TL, HC, TR, HC)
        sep_mid = _hline(LM, HM, RM, HM)
        sep_hdr = _hline(LM, HM, RM, HM)
        sep_bot = _hline(BL, BH, BR, BH)

        # Titre
        _sep_w = max(20, term_w - 4)
        print(f"\n  {c(C.RED, '═'*_sep_w)}")
        print(c(C.WHITE, f"  TOP {shown}/{total} résultats") + c(C.GREY, " (triés par score de lisibilité)"))

        # En-tête du tableau
        print(c(C.GREY, '  ' + sep_top))
        hdr = (
            f"  {c(C.GREY,VB)} {_cell('#',W_RK,C.GREY)} "
            f"{c(C.GREY,VB)} {_cell('Score',W_SC,C.GREY)} "
            f"{c(C.GREY,VB)} {_cell('Barre',W_BR,C.GREY)} "
            f"{c(C.GREY,VB)} {_cell('Chemin',W_PT,C.GREY)} "
            f"{c(C.GREY,VB)} {_cell('Résultat',W_VL,C.GREY)} "
            f"{c(C.GREY,VB)} {_cell('Tags',W_TG,C.GREY)} "
            f"{c(C.GREY,VB)}"
        )
        print(hdr)
        print(c(C.GREY, '  ' + sep_hdr))

        for rank, (score, depth, path, parent_str, result_str, words, h, has_haiti, ctf_tags) in enumerate(sorted_results[:top_n], 1):
            # Chemin : 2 dernières étapes
            pparts = []
            for _, lbl in path[-2:]:
                lbl = re.sub(r'[\n\r\t\x00-\x1f]', '', lbl)[:12]
                pparts.append(lbl)
            path_raw = " → ".join(pparts)

            # Valeur nettoyée
            val_raw = _clean_val(result_str)

            # Tags
            tag_parts = []
            if ctf_tags:
                for t in ctf_tags[:2]:
                    if len(t) >= 4: tag_parts.append(c(C.RED2, f'[{t}]'))
            if words:
                uniq = sorted(set(w for w in words if len(w) >= 4))[:2]
                for w in uniq:
                    if w not in ctf_tags: tag_parts.append(c(C.GREEN, f'[{w}]'))
            if has_haiti: tag_parts.append(c(C.RED2+C.BOLD, '⭐'))
            if h and not words and not ctf_tags: tag_parts.append(c(C.YELLOW, '[hash]'))
            tags_raw = ' '.join(tag_parts)

            # Couleur résultat
            res_color = C.YELLOW if ctf_tags else C.GREEN2
            bar_str = score_bar(score, sorted_results[0][0])

            row = (
                f"  {c(C.GREY,VB)} {_cell(str(rank),W_RK,C.RED2)} "
                f"{c(C.GREY,VB)} {_cell(f'{score:.1f}',W_SC,C.WHITE,rjust=True)} "
                f"{c(C.GREY,VB)} {_cell(bar_str,W_BR,C.RED)} "
                f"{c(C.GREY,VB)} {_cell(path_raw,W_PT,C.GREY)} "
                f"{c(C.GREY,VB)} {_cell(val_raw,W_VL,res_color)} "
                f"{c(C.GREY,VB)} {_cell(_ANSI.sub('',tags_raw),W_TG)}{tags_raw[len(_ANSI.sub('',tags_raw)):] if False else ''} "
                f"{c(C.GREY,VB)}"
            )
            # Reconstruction correcte du champ tags avec couleurs + padding
            tags_plain = _ANSI.sub('', tags_raw)
            tags_pad   = tags_plain[:W_TG].ljust(W_TG)
            # Remplacer la dernière cellule tags par version colorée
            tags_cell  = tags_raw[:_vis(tags_raw) and len(tags_raw)] if _vis(tags_raw) <= W_TG else tags_plain[:W_TG-1]+'…'
            row = (
                f"  {c(C.GREY,VB)} {_cell(str(rank),W_RK,C.RED2)} "
                f"{c(C.GREY,VB)} {_cell(f'{score:.1f}',W_SC,C.WHITE,rjust=True)} "
                f"{c(C.GREY,VB)} {_cell(bar_str,W_BR,C.RED)} "
                f"{c(C.GREY,VB)} {_cell(path_raw,W_PT,C.GREY)} "
                f"{c(C.GREY,VB)} {_cell(val_raw,W_VL,res_color)} "
                f"{c(C.GREY,VB)} {tags_cell}{' '*(W_TG - _vis(tags_raw))} "
                f"{c(C.GREY,VB)}"
            )
            print(row)
            if rank < shown:
                print(c(C.GREY, '  ' + sep_mid))

        print(c(C.GREY, '  ' + sep_bot))

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

def from_base64_reversed(s):
    """Inverse la chaîne PUIS décode en Base64.
    Utile quand le résultat d'une étape précédente commence par '==' (Base64 à l'envers).
    Ex : '==QQM0VFM...' → inverser → '...MFV0MQQ==' → décoder Base64.
    """
    return from_base64(s[::-1])
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
def caesar_ascii(s, shift):
    """César étendu sur les 256 valeurs ASCII (printable 32-126, modulo 95).
    Espace (32) et caractères imprimables sont tous décalés uniformément.
    Idéal pour les chiffrements où symboles + espaces sont inclus dans le décalage.
    """
    result = []
    for ch in s:
        o = ord(ch)
        if 32 <= o <= 126:
            result.append(chr(32 + (o - 32 + shift) % 95))
        else:
            result.append(ch)
    return ''.join(result)

def caesar_ascii_total(s, shift):
    """César brut sur les 256 valeurs ASCII sans restriction de plage.
    Contrairement à caesar_ascii (limité printable 32-126), décale TOUS
    les octets y compris non-imprimables. Essentiel pour les fichiers binaires
    où des bytes comme 0x7F/0x80 encodent des lettres ordinaires après décalage.
    """
    return ''.join(chr((ord(c) + shift) % 256) for c in s)

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

    # ── Hex en paires strictes (3d 3d 4d ...) ────────────────────────────────
    # Toutes les tokens sont exactement 2 chars hex → quasi-certitude hex bytes
    if is_strict_hex_pairs(stripped):
        tags.append('hex_pairs')
        return tags

    # ── Hex pur continu (6447567A...) — longueur paire, 100% hexdigits, ≥8 chars ──
    # César/ROT/Vigenère sur ce type de chaîne = bruit pur → hex EN PREMIER, ciphers EN DERNIER
    if is_pure_hex_string(stripped):
        tags.append('pure_hex')
        return tags

    # ── Base64 inversé : commence par '==' → clairement à l'envers ──────────
    if stripped.startswith('==') and len(stripped) >= 8:
        # Vérifier que le reste ressemble à du Base64
        rest = stripped[2:]
        if sum(1 for c in rest if c in _B64_CHARS) / max(1, len(rest)) > 0.90:
            tags.append('reversed_base64')
            return tags

    return []  # indéterminé — on ne touche PAS à l'ordre des ops


def is_strict_hex_pairs(s):
    """Retourne True si la chaîne est exclusivement des paires hex séparées par espaces.
    Ex: '3d 3d 4d 35 55 46 4d' — aucun autre sens possible, ~100% hex.
    Règle stricte : au moins 3 tokens, TOUS exactement 2 chars hex.
    """
    tokens = s.strip().split()
    if len(tokens) < 3:
        return False
    return all(len(t) == 2 and all(c in '0123456789abcdefABCDEF' for c in t) for t in tokens)


def is_pure_hex_string(s):
    """Retourne True si la chaîne est une séquence hex continue (sans espaces).
    Ex: '6447567A64475A735957633D' — longueur paire, uniquement 0-9a-fA-F.
    Règle : ≥8 chars, longueur PAIRE, 100% charset hex.
    Les mots français ambigus (baffe, cafe) sont exclus car ≤6 chars.
    """
    stripped = s.strip()
    if len(stripped) < 8 or len(stripped) % 2 != 0:
        return False
    if not all(c in '0123456789abcdefABCDEF' for c in stripped):
        return False
    # Anti-ambiguïté : si la chaîne est un vrai mot français/anglais courant,
    # ne pas la traiter comme du hex (ex: "baffe", "decade", "facade")
    # Heuristique : si ≤8 chars ET que ça ressemble à un mot (alternance voyelles/consonnes),
    # on laisse passer — mais pour ≥10 chars, la probabilité d'être du texte lisible est infime.
    if len(stripped) <= 8:
        # Pour les courtes chaînes, vérifier que ça contient au moins un chiffre
        # (une vraie valeur hex aura souvent des chiffres ; un mot anglais rarement)
        has_digit = any(c.isdigit() for c in stripped)
        if not has_digit:
            return False  # "baffe", "cafe", "decade" → probablement du texte
    return True


def reorder_ops_for_format(ops, format_tags):
    """Réordonne les ops selon le format détecté.
    Uniquement pour les formats certains : binary, octal, morse, url_encoded.
    """
    if not format_tags:
        return ops

    tag = format_tags[0]

    PRIORITY = {
        'binary':          {37},    # ← Binaire vers texte EN PREMIER
        'morse':           {54},    # ← Morse vers texte EN PREMIER
        'url_encoded':     {60},    # URL decode EN PREMIER
        'hex_pairs':       {35},    # ← Hex vers texte EN PREMIER (paires strictes)
        'pure_hex':        {35},    # ← Hex vers texte EN PREMIER (continu sans espaces)
        'reversed_base64': {140},   # ← Base64 renversé EN PREMIER
    }

    priority_nums = PRIORITY.get(tag, set())
    if not priority_nums:
        return ops  # format non géré → ne pas toucher

    # ── Opérations INUTILES sur du hex pur ou des paires hex ─────────────────
    # César/ROT/Atbash/Vigenère/XOR fixes appliqués sur du texte hex = bruit pur
    # On les pousse EN DERNIER pour ne pas polluer le collector dès depth=1
    # César shifts 1-25, ROT13(26), Atbash(27), ROT47(101), XOR fixes(45-50),
    # AND(51), OR(52), leet(55/56), shift_one(67/68), alternate(64), etc.
    HEX_USELESS = (
        set(range(1, 28))       # César 1-25 + ROT13 + Atbash
        | {101}                 # ROT47
        | set(range(45, 51))    # XOR key=1,7,13,42,85,127
        | {51, 52}              # AND, OR
        | {55, 56}              # leet / unleet
        | {64, 67, 68}          # alternate case, shift+1, shift-1
        | {80, 81, 82}          # transposition colonnes
        | {83, 84}              # Bacon, T9
        | {89, 90, 91, 92, 93}  # Vigenère clés communes
        | {102, 103}            # César variable, Vigenère brute
        | {104, 105, 106}       # Rail Fence
    )

    if tag in ('pure_hex', 'hex_pairs', 'binary'):
        if tag == 'binary':
            USELESS = (set(range(1, 28)) | {51, 52, 55, 56, 67, 68}
                       | {29, 30, 31, 64, 69, 70, 80, 81, 82, 83, 84, 85, 86, 87, 88})
        else:
            USELESS = HEX_USELESS
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
    ops.append((41,  "← Base64 vers texte",               from_base64))
    ops.append((140, "← Base64 inversé vers texte",       from_base64_reversed))
    ops.append((42,  "← Base32 vers texte",               from_base32))
    ops.append((35,  "← Hexadécimal vers texte",          from_hex))
    ops.append((37,  "← Binaire vers texte",              from_binary))
    ops.append((39,  "← Octal vers texte",                from_octal))
    ops.append((33,  "← Codes ASCII vers texte",          from_ascii_codes))
    ops.append((44,  "← Unicode (U+XXXX) vers texte",     from_unicode_escape))
    ops.append((54,  "← Morse vers texte",                morse_decode))
    ops.append((60,  "URL decode",                        url_decode))

    # ── Groupe 2 : CIPHERS SIMPLES ─────────────────────────────────────────────
    ops.append((26, "ROT13",                             rot13))
    ops.append((101, "ROT47 (ASCII 33-126)",             rot47))
    ops.append((27, "Atbash",                            atbash))
    for shift in range(1, 26):
        ops.append((shift, f"César +{shift}", lambda x, sh=shift: caesar(x, sh)))
    # ── César ASCII étendu (plage 32-126, espace inclus) ──
    # Couvre les cas où * = espace, + = !, etc. (décalage hors a-z classique)
    for shift in range(1, 95):
        ops.append((shift, f"César ASCII +{shift}", lambda x, sh=shift: caesar_ascii(x, sh)))
    # ── César ASCII total (256 valeurs, bijection complète) ──
    # Indispensable pour les fichiers binaires : shifts -1 à -32 (les plus courants en CTF)
    for _neg in range(1, 33):
        _sh = (256 - _neg)
        ops.append((_sh, f"César 256 ({-_neg:+d})", lambda x, sh=_sh: caesar_ascii_total(x, sh)))
    # Shifts positifs courants aussi
    for _pos in [1, 3, 5, 7, 10, 13, 16, 32, 47]:
        ops.append((_pos, f"César 256 (+{_pos})", lambda x, sh=_pos: caesar_ascii_total(x, sh)))
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
                    if prescreen(r):
                        key_str = chr(k0) + chr(k1)
                        _try_terminal(r, path + [(f"XR{k0}_{k1}", f"XOR répété clé='{key_str}'")])
                except: pass
    elif sb:
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
    global _SEEN_GARBAGE
    _SEEN_GARBAGE = set()
    FLAG_FOUND.clear()
    FLAG_FOUND_RESULT.clear()

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
            # LECTURE BINAIRE : latin-1 = bijection parfaite 0x00-0xFF
            # UTF-8 mangerait les bytes 0x7F-0x80+ qui encodent v, u, x après décalage CTF
            with open(file_input, 'rb') as fh:
                raw = fh.read()
            s = raw.decode('latin-1').rstrip('\n\r')
            if not s:
                print(c(C.RED, f"❌ Fichier vide : {file_input}")); sys.exit(1)
            _nonprint = sum(1 for b in raw if b > 126 or (b < 32 and b not in (9,10,13)))
            if _nonprint > 0:
                print(c(C.YELLOW, f"  ⚠ Fichier binaire : {_nonprint} octet(s) hors ASCII standard "
                                  f"— lecture latin-1 (tous les bytes préservés)"))
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

    # ── Space Discovery : détection automatique délimiteur = espace ────────────
    # Si un char non-alnum domine (>= 8%), on teste l'hypothèse qu'il est l'espace.
    # CRITIQUE pour les fichiers binaires : utilise caesar_ascii_total (256) et non
    # caesar_ascii (32-126) pour ne pas perdre les bytes 0x7F-0x80+.
    _space_disc_result = None
    if run_all and len(s) >= 8:
        from collections import Counter as _Ctr
        _specials = [c for c in s if not c.isalnum() and c not in (' ', '\n', '\t', '\r')]
        if _specials:
            _dom_char, _dom_count = _Ctr(_specials).most_common(1)[0]
            _dom_ratio = _dom_count / max(1, len(s))
            if _dom_ratio >= 0.08:
                _shift = ord(_dom_char) - 32
                if _shift != 0:
                    try:
                        # Utilise caesar_ascii_total pour préserver tous les bytes
                        _decoded = caesar_ascii_total(s, -_shift)
                        _words_d = find_words(_decoded, search_haiti=search_haiti)
                        _score_d = compute_score(_decoded, _words_d, False)
                        _lbl = f"César ASCII ('{_dom_char}'=espace, shift={-_shift:+d})"
                        if _dom_ratio >= 0.10 or _score_d >= 20.0 or _words_d:
                            print(
                                f"  ⚡ {c(C.GREEN2+C.BOLD,'Space Discovery')} : "
                                f"{c(C.WHITE, repr(_dom_char))} → espace "
                                f"(ratio {_dom_ratio:.0%}, shift {-_shift:+d}) → "
                                f"{c(C.GREEN2, _decoded[:70])}"
                            )
                        collector.add(0, [(0, _lbl)], s, _decoded, search_haiti)
                        if _dom_ratio >= 0.10:
                            _space_disc_result = (_decoded, [(0, _lbl)])
                    except Exception:
                        pass

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
        # GOOD_SCORE : seuil pour l'early-exit. Fixé haut (65) pour ne s'arrêter
        # que si un résultat contient de vrais mots du dico (word_bonus élevé).
        # Les faux-positifs garbage atteignent rarement 65+ sans mots connus.
        GOOD_SCORE = 65.0

        print(f"  🔍 {c(C.RED,'Mode auto')} {c(C.GREY,'(depth 1 → 2 → 3, stop si résultat clair)')}")

        # ── depth 1 : chaque op seule — parallélisé ────────────────────────────
        depth1_results = []   # (result_str, path)
        # Space Discovery injecté EN TÊTE si ratio >= 10%
        if _space_disc_result is not None:
            depth1_results.append(_space_disc_result)

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
            # ── depth 2 : Beam Search diversifié ─────────────────────────────
            # On sélectionne max 20 candidats du depth=1 :
            # 1 meilleur par famille d'op + top scores, sans branches garbage
            BEAM_WIDTH = 20
            seen_d2 = set()
            depth2_results = []

            def _op_family(p1):
                if not p1: return 'other'
                num = p1[0][0]
                if isinstance(num, str):
                    if num.startswith('XF'): return 'xor_simple'
                    if num.startswith('XR'): return 'xor_repeat'
                    return 'xor_other'
                if isinstance(num, int):
                    if 1 <= num <= 26:   return 'caesar'
                    if num == 27:        return 'rot47'
                    if num in {33,35,37,39,41,42,44,54,60,140}: return 'decode'
                    if 50 <= num <= 70:  return 'transform'
                    if 80 <= num <= 90:  return 'vigenere'
                return 'other'

            # Scores des résultats depth=1 depuis le collector
            d1_scored = {}
            for entry in collector.results:
                sc, dep, p, _, rstr, _, _, _, _ = entry
                if dep <= 1:
                    fp = rstr[:120]
                    if fp not in d1_scored or sc > d1_scored[fp][0]:
                        d1_scored[fp] = (sc, p)

            d1_with_scores = []
            for (r1, path1) in depth1_results:
                fp = r1[:120]
                sc = d1_scored.get(fp, (0.0, path1))[0]
                d1_with_scores.append((sc, r1, path1))
            d1_with_scores.sort(key=lambda x: -x[0])

            seen_families: dict = {}
            beam_set: set = set()
            unique_r1 = []
            seen_r1   = set()

            # Passe 1 : meilleur de chaque famille
            for sc, r1, path1 in d1_with_scores:
                fam = _op_family(path1)
                if fam not in seen_families:
                    seen_families[fam] = True
                    fp = r1[:120]
                    if fp not in seen_r1 and not is_garbage_branch(r1):
                        seen_r1.add(fp); beam_set.add(fp)
                        unique_r1.append((r1, path1))

            # Passe 2 : compléter jusqu'à BEAM_WIDTH
            for sc, r1, path1 in d1_with_scores:
                if len(unique_r1) >= BEAM_WIDTH: break
                fp = r1[:120]
                if fp not in seen_r1 and fp not in beam_set and not is_garbage_branch(r1):
                    seen_r1.add(fp)
                    unique_r1.append((r1, path1))

            print(f"  {c(C.GREY, f'  beam depth=2 : {len(unique_r1)} candidats (/{len(depth1_results)} total)')}")

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

            DECODE_NUMS = {41, 42, 35, 37, 39, 33, 44, 54, 60, 140}
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
                # ── depth 3 : garbage filter + FLAG_FOUND ────────────────────
                seen_d3 = set()
                for (r2, path2) in depth2_results:
                    if PROGRESS.should_quit(): break
                    fp = r2[:120]
                    if fp in seen_d3: continue
                    seen_d3.add(fp)
                    if is_garbage_branch(r2): continue
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
    try:
        import os as _os2
        _sw = max(20, _os2.get_terminal_size().columns - 4)
    except Exception:
        _sw = 68
    sep = c(C.RED, "═" * _sw)
    print(f"\n{sep}")
    print(f"  {c(C.WHITE,'Analyse terminée')} {c(C.GREY,f'[{mode_str}]')}. {c(C.RED2,str(total))} {c(C.WHITE,'hit(s) notable(s).')}")
    print(f"{sep}\n")

    # ── Menu interactif : afficher un résultat complet ───────────────────────
    sorted_final = sorted(collector.results, key=lambda x: -x[0])
    shown_n = min(display_n, len(sorted_final))
    if shown_n > 0:
        print(c(C.GREY, f"  Afficher un résultat complet ? (1-{shown_n}, Entrée=quitter) : "), end="", flush=True)
        try:
            _choice = input().strip()
        except (EOFError, KeyboardInterrupt):
            _choice = ""
        while _choice not in ("", "0"):
            try:
                _idx = int(_choice)
                if 1 <= _idx <= shown_n:
                    sc, dep, path, parent_str, result_str, words, h, has_haiti, ctf_tags = sorted_final[_idx - 1]
                    path_str = " → ".join(lbl for _, lbl in path)
                    print(f"\n  {c(C.RED, '─' * _sw)}")
                    print(f"  {c(C.BOLD+C.WHITE, f'Résultat #{_idx}')}  {c(C.GREY, f'score={sc:.1f}')}")
                    print(f"  {c(C.GREY, 'Chemin  :')} {c(C.CYAN, path_str)}")
                    if words:  print(f"  {c(C.GREY, 'Mots    :')} {c(C.GREEN2, str(words))}")
                    if ctf_tags: print(f"  {c(C.GREY, 'Tags CTF:')} {c(C.RED2, str(ctf_tags))}")
                    print(f"  {c(C.RED, '─' * _sw)}\n")
                    print(result_str)
                    print(f"\n  {c(C.RED, '─' * _sw)}\n")
                else:
                    print(c(C.RED, f"  ⚠ Numéro invalide (1-{shown_n})"))
            except ValueError:
                print(c(C.RED, "  ⚠ Entrez un numéro ou Entrée pour quitter"))
            print(c(C.GREY, f"  Afficher un résultat complet ? (1-{shown_n}, Entrée=quitter) : "), end="", flush=True)
            try:
                _choice = input().strip()
            except (EOFError, KeyboardInterrupt):
                _choice = ""

if __name__ == '__main__':
    main()