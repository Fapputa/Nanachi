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
            f"  Hits        : {c(C.RED2, str(hits))}   Meilleur score : {c(C.GREEN2, f'{best_score:.1f}')}",
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
    _WORDLIST_B64 = (
        "eNo1mFua7KgRhLfCEuZcfbwcJCGJLgQaLlWt2YY34Mc53kZ/3pf/SLUfCnRBkGRGRCbVdv/1x0/Xdv/j"
        "y1d13359V/f1q3Vf3LH8cJNv4ed36759te7LT+t+/LLu1w83+vpLDS9q6V++qf3+D+dD+/L1lzqtsoT2"
        "zZ26CrPa2vzXP77/Uv/9j3/+dGvymzt9a69Sl/ticS3MNXTXyyNk55cjZuYu3fl5Dq25VDaeaKx7hMvN"
        "8dxDdXtcFobP1c8PN/fV7X1yfT/cGeei+9E0yrfdhTyXJWCbdeH9TCV29h5Scm0sxfXQusuHP2387Lt7"
        "K3t2+7VU79qfSW+2Mo3WmXKJdXI5PnpxOXQNbsXa3bs9vLspZl8vhw0+ac140Ps2x+hGjmbCjLd8dc+4"
        "hRxqcL5PsvO9VPlRzpIj3ZTKa428mHc/a/bDz+6cHsvqprleZ3cxv4W5x5JdeYa6Mt5NY1218YDNrcs5"
        "tlFb9/RXKn5xm182HF7L6VKcmLPGZ2iz4+eTt/lqYMIWXDv9Kzsz77z6rjdjutwZanJv/sm+asSQbNPv"
        "pz2Ty9xxqeUXO29K61tlS0fJW1kmpl8ikY15vLtXzEt5Kc6svjPSNVZbO9Ho/WyuHVxGxaDPpxsLN/Nx"
        "uiU3G8DklU9mD0Zi3uSslELegntV1h64oaRhm5pLrfiLF5jhQq04vI0bZVjhEptO8hofT4WHK7FMznxd"
        "turP/eJt2Hz+/91aasgtzu3TYTLgxGGvMLkj4tLCIzwN9LLgAuwfwktk2r4T+bxoDudBwTTkx+6uMhxb"
        "cNqRkP7yzZUcXBmVX3eLv5zCB1ZhwcGPnsgfXku8mOPlShKtgmNBvr/cay/OT4kFJ01B++R6FZ795tm6"
        "tbjep8bIxDfNeUULE0uXGT5fwPgBFmY1i+mCmwIknIL8QKftTyLTxFbtTeRBWS6avrup2oARsW72h4hQ"
        "rYEvhE0xm3d7GTtPUmGBuWhcwckLRsxl6HUZuesbXMKQpYCsRS4CR9lB2pdbhq0VIA5NTRdto8HfBCqr"
        "qdbw7N0fJ64JV3Crn63pNNWtATisuBQcEKdY2dlakmi2KhprxcVrLYdbBwHbYBE6USBYDSjCVhm4K8S7"
        "r2p4DS8XNWJoOhVfnsVtJ4Lscy+nGqTL7UPxZNMe7AviPovvcoO6rnmAFt83PUeN3tAnFDKc7iFzH8JB"
        "8hWnJs8biM0VKwvnktW4cs/SvIoPXfaOF5Jinkp5gCdwcXheHYr9AYyOgE1HAHyHfXhooQPLse0QBA7R"
        "9xC4joHnD5mUFekcwkIjr2f7VKhShPI4Jh6ycUTMgKYYnh5OnzIbzUJtigKE6DRodCYFidYueVtEMSSm"
        "RSH8LC8mOav2eNYyAfvLLlI41MNc+jGliPDBhT8HHpQ6/DkkVUQuqWkmgnNQTKtZXAuz15Fd04YaK7d5"
        "LyWJaA81Bw1KpAjBemxsh3jcFNlWmA9lkVR1RYJWYhI1oI9FHlR/SZB2mtNkrcv9JJKHu72lVtdiRt9r"
        "GSCnR+ZHn4J5r5eXwNYHcR5ZnIErMSkdknDA8rNETHtpzpcwxXB+UoIX3OMNsvaKLIFvTK5o4NzLmHfB"
        "tCuYRkka5iqVhC6DjSIPSZ9hkj9PQZxOT/GmIy3EdCuQ2Yd44P+JVw8JX5c6m+jtQflcOKWNuraMWY7T"
        "tKKIqt0UIUvK6bt8p54A0Z/XrQ/IdpCjF9+9GhUA09hoVz9SVx8lGcHmI9/GDe0IHTvpSARkxyUqmWp+"
        "0pVZT2+gW8o8DPaSHEuqIdsAqUtHU8I8uoqN2HRnwVw19YrCIhryNI3cvsZ35YADxVhHvtP5lgBuMvFI"
        "t2gop4tctxjA+DkNkwJhWIIg75kgmIbF/PQpLrB+QsOUD9Ffs9PSrNqHKitR/RTBlfOOAInFcsIoXi/B"
        "mgRZq6qYLJUrk2oOZSKtfOo7QtPUsoQyvVhmORVqMR1hWNSaLOBMbaUGox29KCMNEzOoAgXbJqFsIEBE"
        "IDys1iTcFHTSj6Zk19BfMexM8WbUoFDoRTWPCX+78gxxFJEuDRSVSF49vHN1obLjNEzcXqIdXCuB4/y7"
        "ILnLB9UoythYdwRp6TxuYQqqmrK0ExBJ6Gehz0rKXQK51Wip/eC7PBxTIQ/xL/gVF/y0B9MUWZzC2pUf"
        "O3nE3+H3y6KfaZi3fEMuFqZFLDxBVy2DN0Ot7115bgoqlCcL7cwDpVZkSKRI6SbLcSgdqY/GmZX8bB12"
        "0uMBEcPWoEvlEiP06aJikaKtq5q22jMIa0C7a/BKJbyzZwkKaY+ia1cJctenAiO1PWkJ7yQPxoFilAUJ"
        "dqD7ySQbAihlsGfDYsmxF8sGkvNQNf6UIJxYcg5KRFZb8FkNd0bAWyUZcqpaOaY9IohIyoltTJqhIW2s"
        "Qoln+vlywGXbWIGtxxXl8wzyuckgomdaNd9bpULhsHFfmYZKc/ynBilXzqPeWqH1EBRK48mU5RSQODd8"
        "1urIAYsFZQgdRvSple7rAP6qIKAarpzcNgSA3YLuYmtg9K2oTvUXViSVAEn56fDINOUmdeI8q0q0IwAn"
        "LDHNx2ZZjV3jKdUlIh/GmKO0j0+3nXIi8RCHlMt7HWouBB8xxlsqdqK59p1vrYq6U7kooDj+FWqhcMkA"
        "d1GSGk1oOwi7tt1UBOt5xKdUTaoZOMQlFQcsIA9AbQD4UgblEKXwIKCEfRithiRUxwMb2q2IfymBoI/P"
        "C8QpFKBOq08iNGWYatCkipXkRhCuYGwq1YrNc1SrK0TxqaruwO2XPgP38ul0Z36wqKK7Ew71r7Dk+6rv"
        "FKC6WGG78jk6VO1i2BdvPg8dBtcwVbs4TNQ80sHxaeC2t6EMOTYVSi2cqIRVQ3Mv6jMktwecI+8LBDpL"
        "36x2zyoqFAgrDYpWJEHzwmwrjJULfTo5PE7VP4thOEXLemTFAJBB+TuuhLYlrfJhUBpZopdpESGDtUV0"
        "9UQLEhdOWvDRn17yPoUZ8TtCARScpzzE4oCng65JH/ASh/F909H9Xd69fKZIdX+NNFSIOnlBqWCBdfhN"
        "c/NTeU0amE2rhHAOOX4gd+xLB5jRq2pAVH+K+teAqqYqwdabaFJNkVpP2/2SKa1/UsjYvVJRteRlQ/Fi"
        "1SlCcoNDxtNkJ+tfBMoczQlTm27FR30ipRIRG6HRPXnTrPI2agnSWk1mMx8qUGww5ZgS4OZvflrATE3N"
        "nGd8aqn4Wez830hiKsZCj2geUkeEp081arGalkSlXJ0l8Nka1Ia8+nxDWOqBWzN1LkYdHK17tbpMUzQt"
        "GoZp+MJ6Xbzj/s2b75sckk39i7m31KYUMXingwLWe8tP9ePvpmpPJTm2q59KtoVJoHNUTNLHv90TYSJg"
        "nP8p9lad+9ZVG799mNkaXf34fXL0syNZtOprXaNd+SNaTqyaXVWj/jWa//svncqwepWmlvtwrWpo+fjN"
        "7nnBgSfrkBNdGkf8+FtnlptW0rFn8ENrSzstkijdaYNUdAUTU50L/F2dS8QVULlHfyVJYfrHf9TKMqqK"
        "MCyzNO363T1HuPGM9FdLGzEPwxfmgZiP37OdcpdwozHckNn8lq0zwOBKS5YIiRAqu4QirahRWCEAdSVM"
        "g/Ln889QC6eD80AURMuI7DbfxfS7/e3z8bvJB5ZD5ctIYGSRTldah4BQIxgdPs9SOtxcrX/8fVi8GrW1"
        "/ScGRIPtQK6/l6TgYk6rD4Iqitjbndmb1V2fGLCyWunbWzrEVT1iB5PO6eP3fXQD5vavlea2Q7zXvxxZ"
        "1d1LNdhrZ/hrD9mOMjqusNucrv8B8WXdsg=="
    )
    raw = zlib.decompress(base64.b64decode(_WORDLIST_B64)).decode()
    words = raw.split()
    return {w: len(words) - i for i, w in enumerate(words)}

WORD_INDEX = _load_words()

CTF_KEYWORDS  = [
    "flag","password","passwd","secret","token","admin","root","access",
    "login","pass","key","cipher","hidden","crack","ctf","htb","thm","picoctf",
    "user","hash","encode","decode","exploit","shell","sudo","test",
]
CTF_HIGH_SCORE = {'flag','password','passwd','token','secret','key','admin','root','login','pass'}
CTF_MED_SCORE  = {'ctf','htb','thm','picoctf','hash','encode','decode','exploit','shell','user'}

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

# Sépare les mots par longueur pour éviter de boucler inutilement
_WORDS_3    = None  # set des mots de 3 chars (patterns )
_WORDS_4UP  = None  # set des mots de 4+ chars (substring)
_PASS_PAT   = re.compile(r'(?<![a-zA-Z])pass(?![a-zA-Z])', re.IGNORECASE)
_HAITI_PAT  = re.compile(r'(?<![a-zA-Z])haiti(?![a-zA-Z])', re.IGNORECASE)

def _rebuild_word_sets():
    global _WORDS_3, _WORDS_4UP
    _WORDS_3   = {w for w in WORD_INDEX if w != 'haiti' and w != 'pass' and len(w) == 3}
    _WORDS_4UP = {w for w in WORD_INDEX if w != 'haiti' and w != 'pass' and len(w) >= 4}

_rebuild_word_sets()  # initialise les sets au démarrage

def find_words(s, search_haiti=False):
    """
    Logique de matching :
    - "pass" seul : seulement si NON entouré de lettres (évite bypass/compass/ivmpass)
    - Mots de 3 chars : frontière de mot \b (évite faux positifs massifs)
    - Mots 4+ chars   : substring simple (assez spécifiques, attrape flagveryeasy etc.)
    """
    lower = s.lower()
    hits  = []
    # pass : pattern isolé
    if _PASS_PAT.search(s):
        hits.append('pass')
    # 3 chars : patterns regex pré-compilés
    for w in _WORDS_3:
        pat = _WORD_PATTERNS.get(w)
        if pat and pat.search(lower):
            hits.append(w)
    # 4+ chars : substring direct (O(n) par mot, très rapide)
    for w in _WORDS_4UP:
        if w in lower:
            hits.append(w)
    if search_haiti and _HAITI_PAT.search(lower):
        hits.append('haiti')
    return hits


def detect_ctf_keywords(s):
    """Même logique hybride que find_words pour éviter les faux positifs."""
    lower = s.lower()
    found = []
    for kw in CTF_KEYWORDS:
        if kw == 'pass':
            if re.search(r'(?<![a-zA-Z])pass(?![a-zA-Z])', s, re.IGNORECASE):
                found.append(kw)
        elif len(kw) == 3:
            pat = _WORD_PATTERNS.get(kw)
            if pat and pat.search(lower):
                found.append(kw)
        else:
            if kw in lower:
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
    if not result_str:
        return 0.0

    # Tout calculer en un seul passage sur result_str
    lower_str = result_str.lower()
    alpha_chars = [ch for ch in lower_str if ch.isalpha()]
    n = len(alpha_chars)
    total_len = len(result_str)

    # Printable ratio — court-circuit rapide
    n_printable = sum(1 for ch in result_str if ch.isprintable())
    if n_printable / max(1, total_len) < 0.7:
        return 0.01

    # chi2 — appel direct avec la liste déjà filtrée
    if n >= 4:
        chi2_en = chi2_lang_fast(alpha_chars, _EN_FREQ_LIST, n)
        chi2_fr = chi2_lang_fast(alpha_chars, _FR_FREQ_LIST, n)
        chi2_val = min(chi2_en, chi2_fr)
    else:
        chi2_val = 9999.0
    chi2_comp = max(0.0, 100.0 - chi2_val / 3.0)

    # Index de coïncidence — inline (évite re.sub + appel function)
    ic = 0.038
    if n >= 6:
        freq26 = [0] * 26
        for ch in alpha_chars:
            freq26[ord(ch) - 97] += 1
        ic = sum(v * (v - 1) for v in freq26) / (n * (n - 1))
    dist_natural = min(abs(ic - 0.065), abs(ic - 0.074))
    ic_comp = max(0.0, 1.0 - dist_natural / 0.035) * 50.0

    base = chi2_comp * 0.65 + ic_comp * 0.35

    alpha_ratio = n / max(1, len(result_str.replace(' ', '').replace('\n', '')))
    base *= (0.3 + 0.7 * alpha_ratio)

    if words:
        covered   = sum(len(w) for w in set(words))
        cov_ratio = min(1.0, covered / max(1, n))
        base *= (0.30 + 0.70 * cov_ratio)
    else:
        base *= 0.30

    length_conf = min(1.0, n / 40.0)
    base *= length_conf

    # ── Entropie de Shannon ──────────────────────────────────────────────
    # Texte anglais naturel : ~3.5–4.5 bits/char
    # Aléatoire (Random) : ~7.5–8 bits/char
    # On pénalise si l'entropie est trop haute (chiffré/aléatoire) ou trop basse (répétitif)
    _chars = [c for c in result_str if c.isprintable()]
    if len(_chars) >= 8:
        _freq = {}
        for _c in _chars: _freq[_c] = _freq.get(_c, 0) + 1
        _n = len(_chars)
        _entropy = -sum((v/_n) * math.log2(v/_n) for v in _freq.values())
        # Pénalité si entropie > 5.5 (trop aléatoire)
        if _entropy > 5.5:
            entropy_penalty = max(0.15, 1.0 - (_entropy - 5.5) / 3.0)
            base *= entropy_penalty
        # Pénalité si entropie < 1.5 (trop répétitif / inutile)
        elif _entropy < 1.5:
            base *= max(0.2, _entropy / 1.5)

    # ── Pénalité NATO ─────────────────────────────────────────────────────
    # "Whiskey Papa Tango Echo…" est un encodage lisible mais pas utile :
    # le score de chi2 le perçoit comme "bon anglais" alors que c'est du bruit.
    tokens = re.findall(r'[A-Za-z]+', result_str)
    if len(tokens) >= 4:
        nato_count = sum(1 for t in tokens if t.lower() in NATO_SET)
        nato_ratio = nato_count / len(tokens)
        if nato_ratio > 0.30:
            # Facteur de pénalité : 100% NATO → ×0.07, 30% NATO → ×0.91
            nato_penalty = max(0.07, 1.0 - nato_ratio * 1.4)
            base *= nato_penalty

    # ── Bonus CTF + contexte ──────────────────────────────────────────────
    # Règle : mot trouvé = score de base
    # Séparateurs contextuels (: = { } [ ] espace après) = +2 pts chacun
    # Case pure (tout lower ou tout upper ou Title) = +1 pt
    # Case mixte aléatoire (PaSs) = pénalité -0.3×score_mot
    tl = result_str.lower()
    ctf_bonus = 0.0
    for k in CTF_HIGH_SCORE:
        if k not in tl:
            continue
        base_kw = 25.0
        # Bonus séparateurs : le mot est suivi/précédé de : = { } [ ] espace
        for pat in (k + ':', k + '=', k + '{', '{' + k, '[' + k, k + ']',
                    k + ' ', ' ' + k):
            if pat in tl:
                base_kw += 2.0
                break
        # Bonus case : vérifier dans result_str (pas lower)
        idx = tl.find(k)
        raw = result_str[idx:idx+len(k)]
        if raw == raw.lower() or raw == raw.upper() or raw == raw.title():
            base_kw += 1.0   # case uniforme = intentionnel
        else:
            base_kw *= 0.7   # case chaotique = probablement bruit
        ctf_bonus += base_kw
    for k in CTF_MED_SCORE:
        if k not in tl:
            continue
        base_kw = 8.0
        for pat in (k + ':', k + '=', k + '{', ' ' + k, k + ' '):
            if pat in tl:
                base_kw += 1.5
                break
        idx = tl.find(k)
        raw = result_str[idx:idx+len(k)]
        if raw != raw.lower() and raw != raw.upper() and raw != raw.title():
            base_kw *= 0.7
        ctf_bonus += base_kw
    base += ctf_bonus

    if has_haiti:
        base += 500

    return round(base, 3)

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
        self.results = []

    def add(self, depth, path, parent_str, result_str, search_haiti):
        # Strip le préfixe [clé='xxx'] avant la détection de mots
        # sinon "key", "pass", "word" etc. sont trouvés dans le nom de la clé
        _search_str = re.sub(r"^\[clé='[^']*'\]\s*", '', result_str)
        words     = find_words(_search_str, search_haiti=search_haiti)
        has_haiti = search_haiti and 'haiti' in _search_str.lower()
        ctf_tags  = detect_ctf_keywords(_search_str)
        h = None if _suppress_hash_detection(path, parent_str, result_str) else looks_like_hash(result_str)
        interesting = bool(words) or bool(h) or has_haiti or bool(ctf_tags)
        if not interesting:
            return False
        score = compute_score(result_str, words, has_haiti)
        if h and not words and not ctf_tags:
            score = max(score, 1.0)
        self.results.append((score, depth, path, parent_str, result_str, words, h, has_haiti, ctf_tags))
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
        return ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
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

    # XOR répété 2 chars : même optimisation bytearray
    if sb:
        for k0 in range(32, 127):
            if PROGRESS.should_quit(): return
            for k1 in range(32, 127):
                if k0 == k1: continue
                try:
                    rb = bytes(sb[i] ^ (k0 if i % 2 == 0 else k1) for i in range(len(sb)))
                    r  = rb.decode('latin-1')
                    key_str = chr(k0) + chr(k1)
                    _try_terminal(r, path + [(f"XR{k0}_{k1}", f"XOR répété clé='{key_str}'")])
                except: pass
    else:
        for k0, k1 in itertools.product(range(32, 127), repeat=2):
            if PROGRESS.should_quit(): return
            if k0 == k1: continue
            try:
                r = ''.join(chr(ord(s[i]) ^ (k0 if i % 2 == 0 else k1)) for i in range(len(s)))
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
        print(c(C.GREEN2, f"  📖 Wordlist : {len(ext):,} mots depuis {wordlist_path}"))

    ops      = build_operations(s, include_hash_ops=search_haiti)
    ops_dict = {op[0]: op for op in ops}
    run_all  = (code == 0)
    collector = ResultCollector()

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
            xor_bruteforce(s, collector, search_haiti, depth=0, path=[])
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