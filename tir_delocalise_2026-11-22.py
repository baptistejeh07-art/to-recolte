# -*- coding: utf-8 -*-
"""LE TIR DELOCALISE : recolter des e-prints d'arXiv hors du poste, rendre un paquet CHIFFRE, verifier au retour. 22/11/2026 (s3).
Cle : fondations/tir_delocalise_cle_et_prediction_2026-11-22.md (ecrite AVANT ce code) : §2 la forme, §3 [D1]-[D4], §4 le temoin.
UN-FAIT-UN-LIEU: ce fichier est le SEUL code du tir ; le depot public en porte une COPIE octet pour octet (son sha1 est note au
tir). Bibliotheque standard seule (il tourne sur une machine nue). Donnees NON FIABLES : rien n'est ouvert a distance ; au
retour, les archives sont lues comme des octets, jamais executees, et tout chemin absolu ou remontant est refuse.
    python -X utf8 tir_delocalise_2026-11-22.py --temoin
    python tir_delocalise_2026-11-22.py --recolter <liste.json> <dossier_artefact>      (a distance ; phrase dans RECOLTE_PHRASE)
    python -X utf8 tir_delocalise_2026-11-22.py --rapatrier <dossier_artefact> <dossier_donnees>   (sur le poste ; idem)
"""
import gzip, hashlib, http.server, io, json, os, shutil, subprocess, sys, tarfile, tempfile, threading, time, urllib.error, \
    urllib.request

BASE = "https://export.arxiv.org/e-print/"
PAUSE = 3.0
BORNE = 200 * 1024 * 1024
AGENT = "research-client/1.0"


def sha1(b):
    return hashlib.sha1(b).hexdigest()


def nom_sur(aid):
    return aid.replace("/", "_")


# ------------------------------------------------------------------------------------------------------------ a distance
def telecharger(aid, base, pause, dernier):
    """-> (ligne de comptes, octets ou None). Un 429 / 403 leve ArretDebit : la passe s'ARRETE (cle §4 face 6)."""
    time.sleep(max(0.0, pause - (time.time() - dernier[0])))
    req = urllib.request.Request(base + aid, headers={"User-Agent": AGENT})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            taille = int(r.headers.get("Content-Length") or 0)
            if taille > BORNE:
                dernier[0] = time.time()
                return dict(id=aid, statut="trop_gros", code=r.status, taille=taille), None
            b = r.read(BORNE + 1)
            dernier[0] = time.time()
            if len(b) > BORNE:
                return dict(id=aid, statut="trop_gros", code=r.status, taille=len(b)), None
            dispo = r.headers.get("Content-Disposition") or ""
            return dict(id=aid, statut="rendu", code=r.status, taille=len(b), sha1=sha1(b), type=r.headers.get("Content-Type"),
                        nom_servi=dispo.split("filename=")[-1].strip('"; ') if "filename=" in dispo else None,
                        adresse_finale=r.geturl()), b
    except urllib.error.HTTPError as x:
        dernier[0] = time.time()
        if x.code in (403, 429):
            raise ArretDebit("%s : code %d" % (aid, x.code))
        return dict(id=aid, statut="absent" if x.code == 404 else "refuse", code=x.code), None
    except Exception as x:
        dernier[0] = time.time()
        return dict(id=aid, statut="erreur", code=None, erreur=type(x).__name__), None


class ArretDebit(Exception):
    pass


def chiffrer(clair, chiffre, phrase):
    """gpg symetrique AES256 ; la phrase passe par un descripteur, jamais par la ligne de commande ni par un journal [D4]"""
    r, w = os.pipe()
    os.write(w, phrase.encode("utf-8") + b"\n"); os.close(w)
    try:
        if os.name == "nt":
            p = subprocess.run(["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase-fd", "0", "--symmetric",
                                "--cipher-algo", "AES256", "-o", chiffre, clair], input=phrase.encode("utf-8") + b"\n",
                               capture_output=True)
        else:
            p = subprocess.run(["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase-fd", str(r), "--symmetric",
                                "--cipher-algo", "AES256", "-o", chiffre, clair], pass_fds=(r,), capture_output=True)
    finally:
        os.close(r)
    return p.returncode == 0


def dechiffrer(chiffre, clair, phrase):
    p = subprocess.run(["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase-fd", "0", "-o", clair, "-d", chiffre],
                       input=phrase.encode("utf-8") + b"\n", capture_output=True)
    return p.returncode == 0 and os.path.exists(clair)


def garde_D1(dossier):
    """[D1] l'artefact contient exactement paquet.tar.gpg et comptes.json, et le paquet n'est pas une archive lisible"""
    noms = sorted(os.listdir(dossier))
    if noms != ["comptes.json", "paquet.tar.gpg"]:
        return False, "contenu inattendu : %s" % noms
    tete = open(os.path.join(dossier, "paquet.tar.gpg"), "rb").read(600)
    if tarfile.is_tarfile(os.path.join(dossier, "paquet.tar.gpg")) or b"ustar" in tete or tete[:2] == b"\x1f\x8b":
        return False, "le paquet se lit comme une archive en clair"
    return True, "ok"


def recolter(liste, dossier, phrase, base=BASE, pause=PAUSE):
    ids = json.load(open(liste, encoding="utf-8"))
    ids = [x["id_arxiv"] if isinstance(x, dict) else x for x in ids]
    os.makedirs(dossier, exist_ok=True)
    tmp = tempfile.mkdtemp()
    clair = os.path.join(tmp, "paquet.tar")
    lignes, dernier, arret = [], [0.0], None
    t0 = time.time()
    with tarfile.open(clair, "w") as T:
        for aid in ids:
            try:
                l, b = telecharger(aid, base, pause, dernier)
            except ArretDebit as x:
                arret = str(x); break
            lignes.append(l)
            if b is not None:
                info = tarfile.TarInfo(nom_sur(aid) + ".eprint"); info.size = len(b)
                T.addfile(info, io.BytesIO(b))
    faits = {l["id"] for l in lignes}
    lignes += [dict(id=a, statut="non_tente", code=None) for a in ids if a not in faits]            # [D3] une ligne par id
    ok_chiffre = chiffrer(clair, os.path.join(dossier, "paquet.tar.gpg"), phrase)
    shutil.rmtree(tmp, ignore_errors=True)
    comptes = dict(n_liste=len(ids), statuts={s: sum(1 for l in lignes if l["statut"] == s) for s in sorted({l["statut"] for l in lignes})},
                   arret=arret, duree_s=round(time.time() - t0, 1), sha1_code=sha1(open(os.path.abspath(__file__), "rb").read()),
                   sha1_liste=sha1(open(liste, "rb").read()), articles=lignes)
    json.dump(comptes, open(os.path.join(dossier, "comptes.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    d1, pourquoi = garde_D1(dossier) if ok_chiffre else (False, "chiffrement en echec")
    print("recolte : %s | arret : %s | chiffrement : %s | [D1] : %s" % (comptes["statuts"], arret, ok_chiffre, pourquoi))
    return ok_chiffre and d1 and arret is None


# ------------------------------------------------------------------------------------------------------------ sur le poste
def membres_surs(b):
    """-> ('archive', [(chemin, octets)], refuses) | ('fichier', octets_decompresses, 0) | ('brut', octets, 0)"""
    try:
        T = tarfile.open(fileobj=io.BytesIO(b), mode="r:*")
        gardes, refuses = [], 0
        for m in T.getmembers():
            n = m.name.replace("\\", "/")
            if not m.isfile():
                continue
            if n.startswith("/") or (len(n) > 1 and n[1] == ":") or ".." in n.split("/"):
                refuses += 1; continue
            gardes.append((n, T.extractfile(m).read()))
        return "archive", gardes, refuses
    except tarfile.TarError:
        pass
    if b[:2] == b"\x1f\x8b":
        try:
            return "fichier", gzip.decompress(b), 0
        except Exception:
            pass
    return "brut", b, 0


def rapatrier(dossier_artefact, dossier_donnees, phrase):
    d1, pourquoi = garde_D1(dossier_artefact)
    if not d1:
        print("[D1] XX :", pourquoi); return False
    C = json.load(open(os.path.join(dossier_artefact, "comptes.json"), encoding="utf-8"))
    tmp = tempfile.mkdtemp()
    clair = os.path.join(tmp, "paquet.tar")
    try:
        if not dechiffrer(os.path.join(dossier_artefact, "paquet.tar.gpg"), clair, phrase):
            print("dechiffrement en echec : rien n'est range"); return False
        rendus = {l["id"]: l for l in C["articles"] if l["statut"] == "rendu"}
        T = tarfile.open(clair, "r")
        vus, mauvais, journal = set(), [], []
        par_nom = {nom_sur(a) + ".eprint": a for a in rendus}
        for m in T.getmembers():
            aid = par_nom.get(m.name)
            b = T.extractfile(m).read() if aid else b""
            if aid is None or sha1(b) != rendus[aid]["sha1"]:
                mauvais.append(m.name); continue
            vus.add(aid)
        if mauvais or vus != set(rendus):                                                            # [D2] AVANT de ranger
            print("[D2] XX : %d membres fautifs, %d rendus manquants : rien n'est range" % (len(mauvais), len(set(rendus) - vus)))
            return False
        for m in T.getmembers():
            aid = par_nom[m.name]; b = T.extractfile(m).read()
            genre, contenu, refuses = membres_surs(b)
            cible = os.path.join(dossier_donnees, nom_sur(aid)); os.makedirs(cible, exist_ok=True)
            open(os.path.join(cible, "_eprint.bin"), "wb").write(b)
            if genre == "archive":
                for n, o in contenu:
                    f = os.path.join(cible, "source", *n.split("/")); os.makedirs(os.path.dirname(f), exist_ok=True)
                    open(f, "wb").write(o)
            else:
                os.makedirs(os.path.join(cible, "source"), exist_ok=True)
                open(os.path.join(cible, "source", "principal.tex" if genre == "fichier" else "principal.bin"), "wb").write(contenu)
            journal.append(dict(rendus[aid], genre=genre, n_fichiers=len(contenu) if genre == "archive" else 1, membres_refuses=refuses))
        T.close()
        json.dump(dict(comptes=C, ranges=journal), open(os.path.join(dossier_donnees, "_JOURNAL_tir_%s.json" % C["sha1_liste"][:10]),
                                                         "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("[D2] OK : %d / %d archives verifiees et rangees ; statuts %s" % (len(vus), len(rendus), C["statuts"]))
        return True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------------------------------------------- temoin
def _tar(fichiers):
    o = io.BytesIO()
    with tarfile.open(fileobj=o, mode="w:gz") as T:
        for n, b in fichiers:
            i = tarfile.TarInfo(n); i.size = len(b); T.addfile(i, io.BytesIO(b))
    return o.getvalue()


def temoin():
    FORGE = {
        "2001.00001": _tar([("main.tex", b"A = B"), ("sec/intro.tex", b"intro"), ("fig/x.txt", b"x")]),
        "math/0412127": _tar([("old.tex", b"ancien")]),
        "2001.00003": gzip.compress(b"un seul fichier TeX"),
        "2001.00666": _tar([("ok.tex", b"ok"), ("../evade.tex", b"non"), ("/abs.tex", b"non")]),
    }
    mode = {"n": 0}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            aid = self.path[len("/e-print/"):]
            if aid == "2001.00429":
                self.send_response(429); self.end_headers(); return
            if aid == "2001.99999":
                self.send_response(200); self.send_header("Content-Length", str(BORNE + 5)); self.end_headers(); return
            b = FORGE.get(aid)
            if b is None:
                self.send_response(404); self.end_headers(); return
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.send_header("Content-Disposition", 'attachment; filename="arXiv-%sv2.tar.gz"' % aid.replace("/", "-"))
            self.end_headers(); self.wfile.write(b)

    S = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=S.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d/e-print/" % S.server_address[1]
    R = tempfile.mkdtemp()
    ok = True

    def face(n, lib, obtenu, attendu=True):
        nonlocal ok
        b = obtenu == attendu; ok = ok and b
        print("%2d %s : %s%s" % (n, lib, "OK" if b else "XX", "" if b else "  obtenu %r attendu %r" % (obtenu, attendu)))

    def tir(nom, ids, phrase="phrase de temoin"):
        l = os.path.join(R, nom + ".json"); json.dump(ids, open(l, "w"))
        a = os.path.join(R, nom + "_artefact"); r = recolter(l, a, phrase, base=base, pause=0.0)
        return r, a, json.load(open(os.path.join(a, "comptes.json")))

    try:
        r, a, C = tir("t1", ["2001.00001", "math/0412127", "2001.00003", "2001.00404", "2001.99999", "2001.00666"])
        d = os.path.join(R, "donnees1")
        face(1, "trois archives et un fichier seul : chiffres, dechiffres, sha1 egaux [D2]", rapatrier(a, d, "phrase de temoin"))
        face(2, "l'arborescence est rendue telle quelle",
             sorted(os.path.relpath(os.path.join(p, f), os.path.join(d, "2001.00001", "source")).replace("\\", "/")
                    for p, _, fs in os.walk(os.path.join(d, "2001.00001", "source")) for f in fs), ["fig/x.txt", "main.tex", "sec/intro.tex"])
        face(3, "le nom servi (qui porte la version) est note", [l.get("nom_servi") for l in C["articles"] if l["id"] == "2001.00001"],
             ["arXiv-2001.00001v2.tar.gz"])
        face(4, "un e-print qui est un TeX seul compresse : un fichier unique",
             open(os.path.join(d, "2001.00003", "source", "principal.tex"), "rb").read(), b"un seul fichier TeX")
        face(5, "un identifiant inconnu : compte absent, la passe continue",
             (C["statuts"].get("absent"), C["statuts"].get("rendu"), C["arret"]), (1, 4, None))
        r6, a6, C6 = tir("t6", ["2001.00001", "2001.00429", "2001.00003"])
        face(6, "un 429 : la passe s'ARRETE, le dit, et chaque identifiant garde sa ligne [D3]",
             (r6, C6["arret"] is not None, C6["statuts"]), (False, True, {"non_tente": 2, "rendu": 1}))
        d7 = os.path.join(R, "donnees7")
        face(7, "une mauvaise phrase : rien n'est range", (rapatrier(a, d7, "autre phrase"), os.path.exists(d7)), (False, False))
        face(8, "un membre qui remonte ou absolu : refuse, compte",
             (sorted(os.listdir(os.path.join(d, "2001.00666", "source"))),
              [x["membres_refuses"] for x in json.load(open([os.path.join(d, f) for f in os.listdir(d) if f.startswith("_JOURNAL")][0],
                                                            encoding="utf-8"))["ranges"] if x["id"] == "2001.00666"],
              os.path.exists(os.path.join(d, "evade.tex")), os.path.exists(os.path.join(d, "2001.00666", "evade.tex"))),
             (["ok.tex"], [2], False, False))
        a9 = os.path.join(R, "a9"); shutil.copytree(a, a9); open(os.path.join(a9, "source.tex"), "w").write("fuite")
        face(9, "un troisieme fichier dans l'artefact : [D1] echoue", garde_D1(a9)[0], False)
        a9b = os.path.join(R, "a9b"); os.makedirs(a9b); open(os.path.join(a9b, "comptes.json"), "w").write("{}")
        open(os.path.join(a9b, "paquet.tar.gpg"), "wb").write(_tar([("x.tex", b"en clair")]))
        face(9, "un paquet en clair sous le bon nom : [D1] echoue", garde_D1(a9b)[0], False)
        a10 = os.path.join(R, "a10"); shutil.copytree(a, a10)
        b = bytearray(open(os.path.join(a10, "paquet.tar.gpg"), "rb").read()); b[len(b) // 2] ^= 0xFF
        open(os.path.join(a10, "paquet.tar.gpg"), "wb").write(bytes(b))
        d10 = os.path.join(R, "donnees10")
        face(10, "un octet change dans le paquet : vu, rien n'est range", (rapatrier(a10, d10, "phrase de temoin"), os.path.exists(d10)),
             (False, False))
        face(11, "une archive au-dela de la borne : trop_gros, non gardee", C["statuts"].get("trop_gros"), 1)
        r12, a12, C12 = tir("t12", ["2001.00001", "math/0412127", "2001.00003", "2001.00404", "2001.99999", "2001.00666"])
        sans = lambda c: json.dumps({k: v for k, v in c.items() if k not in ("duree_s", "sha1_liste")}, sort_keys=True)
        face(12, "deux passes : memes comptes, au temps pres", sans(C12), sans(C))
        face(13, "[D4] la phrase n'est ni dans les comptes ni dans le paquet",
             b"phrase de temoin" in open(os.path.join(a, "comptes.json"), "rb").read() + open(os.path.join(a, "paquet.tar.gpg"), "rb").read(), False)
    finally:
        S.shutdown(); shutil.rmtree(R, ignore_errors=True)
    print("TEMOIN", "OK" if ok else "XX")
    return ok


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["--temoin"]:
        sys.exit(0 if temoin() else 1)
    phrase = os.environ.get("RECOLTE_PHRASE") or ""
    if a[:1] == ["--recolter"] and len(a) == 3 and phrase:
        sys.exit(0 if recolter(a[1], a[2], phrase) else 1)
    if a[:1] == ["--rapatrier"] and len(a) == 3 and phrase:
        sys.exit(0 if rapatrier(a[1], a[2], phrase) else 1)
    print(__doc__ if a[:1] not in (["--recolter"], ["--rapatrier"]) else "RECOLTE_PHRASE absente ou arguments manquants")
    sys.exit(2)
