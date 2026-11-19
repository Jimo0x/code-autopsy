"""Génère « patient-zero », un petit dépôt Git volontairement malade, pour la démo."""
from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timedelta

FILES = {
    "shop/orders.py": '''import os, json, pickle, subprocess
from shop.utils import *

DB_PASSWORD = "sup3rS3cretPassw0rd"


def process_order(order, user, cart, coupon, shipping, payment, notify=True, log=[]):
    """Traite une commande. TODO: découper cette fonction"""
    total = 0
    if order is None:
        return None
    for item in cart:
        if item["qty"] > 0:
            if item["price"] > 0:
                if item.get("promo"):
                    if coupon and coupon.startswith("VIP"):
                        total += item["price"] * item["qty"] * 0.7
                    elif coupon:
                        total += item["price"] * item["qty"] * 0.9
                    else:
                        total += item["price"] * item["qty"] * 0.95
                else:
                    total += item["price"] * item["qty"]
            else:
                log.append("prix invalide")
        else:
            log.append("quantité invalide")
    if shipping == "express":
        total += 15
    elif shipping == "relay":
        total += 4
    elif shipping == "home" and total < 50:
        total += 7
    if payment == "card" or payment == "paypal" and user.get("verified"):
        status = "paid"
    else:
        status = "pending"
    try:
        os.system("echo commande " + str(order) + " >> /tmp/orders.log")
    except:
        pass
    if notify:
        send_mail(user["email"], "Commande", f"Total {total}")
    return {"order": order, "total": round(total, 2), "status": status}


def load_session(blob):
    return pickle.loads(blob)


def export(orders, fmt):
    if fmt == "json":
        return json.dumps(orders)
    if fmt == "csv":
        out = []
        for o in orders:
            out.append(",".join(str(o[k]) for k in ("order", "total", "status")))
        return "\\n".join(out)
    return eval(fmt + "(orders)")


def run_report(name):
    return subprocess.run("report.sh " + name, shell=True)
''',
    "shop/invoices.py": '''from shop.utils import send_mail


def compute_invoice(order, user, cart, coupon, shipping, payment):
    total = 0
    for item in cart:
        if item["qty"] > 0:
            if item["price"] > 0:
                if item.get("promo"):
                    if coupon and coupon.startswith("VIP"):
                        total += item["price"] * item["qty"] * 0.7
                    elif coupon:
                        total += item["price"] * item["qty"] * 0.9
                    else:
                        total += item["price"] * item["qty"] * 0.95
                else:
                    total += item["price"] * item["qty"]
    return {"order": order, "total": total}


def old_invoice_format(inv):
    # FIXME: plus utilisé depuis 2023 ?
    return "FACTURE %s : %s €" % (inv["order"], inv["total"])
''',
    "shop/utils.py": '''import hashlib
import requests


def send_mail(to, subject, body):
    if to == None:
        return False
    requests.post("https://mail.example.com/send", json={"to": to, "s": subject, "b": body}, verify=False)
    return True


def hash_password(p):
    return hashlib.md5(p.encode()).hexdigest()


def slugify(text):
    return "-".join(w.lower() for w in text.split() if w.isalnum())
''',
    "shop/__init__.py": "",
    "web/cart.js": '''var API_KEY = "sk_live_51HxDemoKeyDoNotUse";

function renderCart(items, el) {
  var html = "";
  for (var i = 0; i < items.length; i++) {
    if (items[i].qty > 0) {
      html += "<li>" + items[i].name + " x" + items[i].qty + "</li>";
    }
  }
  el.innerHTML = html;
  console.log("rendu", items.length);
}

function applyCoupon(code, total) {
  if (code == "VIP") return total * 0.7;
  if (code == "NOEL") return total * 0.85;
  if (code != "") return total * 0.95;
  return total;
}

const checkout = async (cart, user) => {
  try {
    const r = await fetch("/api/checkout", { method: "POST", body: JSON.stringify({ cart, user }) });
    return await r.json();
  } catch (e) {}
};

function legacyTracker(evt) {
  return eval("track_" + evt + "()");
}
''',
    "tests/test_utils.py": '''from shop.utils import slugify


def test_slugify():
    assert slugify("Hello World") == "hello-world"
''',
    "README.md": "# Patient zéro\n\nBoutique en ligne de démonstration — volontairement mal en point.\n",
}

HISTORY = [
    ("Alice Martin", "Initial commit : boutique", ["README.md", "shop/__init__.py", "shop/utils.py"]),
    ("Alice Martin", "Ajout des commandes", ["shop/orders.py"]),
    ("Bruno Leroy", "Panier côté client", ["web/cart.js"]),
    ("Alice Martin", "fix: total négatif", ["shop/orders.py"]),
    ("Chloé Diallo", "Factures", ["shop/invoices.py"]),
    ("Bruno Leroy", "fix crash panier vide", ["web/cart.js", "shop/orders.py"]),
    ("Alice Martin", "Coupons VIP", ["shop/orders.py", "shop/invoices.py"]),
    ("Alice Martin", "hotfix livraison express", ["shop/orders.py"]),
    ("Chloé Diallo", "Tests utilitaires", ["tests/test_utils.py"]),
    ("Bruno Leroy", "fix: coupon NOEL", ["web/cart.js"]),
    ("Alice Martin", "fix arrondi total", ["shop/orders.py", "shop/invoices.py"]),
    ("Alice Martin", "Export CSV", ["shop/orders.py"]),
    ("David Roux", "Envoi des mails", ["shop/utils.py", "shop/orders.py"]),
    ("Alice Martin", "fix bug paiement paypal", ["shop/orders.py"]),
    ("Bruno Leroy", "Checkout asynchrone", ["web/cart.js"]),
    ("Alice Martin", "fix: double notification", ["shop/orders.py", "shop/utils.py"]),
    ("Alice Martin", "Rapport des ventes", ["shop/orders.py"]),
    ("Chloé Diallo", "fix facture coupon", ["shop/invoices.py", "shop/orders.py"]),
]


def build(dest: str) -> str:
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    run = lambda *a, env=None: subprocess.run(["git", "-C", dest, *a], check=True, capture_output=True, env=env)
    run("init", "-q", "-b", "main")
    start = datetime(2025, 9, 1, 10, 0)
    final = FILES
    for i, (author, msg, paths) in enumerate(HISTORY):
        for p in paths:
            full = os.path.join(dest, p)
            os.makedirs(os.path.dirname(full) or dest, exist_ok=True)
            content = final[p]
            lines = content.splitlines(keepends=True)
            # les versions intermédiaires sont des préfixes du fichier final (simule la croissance)
            later = sum(1 for _, _, ps in HISTORY[i + 1:] if p in ps)
            total = sum(1 for _, _, ps in HISTORY if p in ps)
            keep = len(lines) if later == 0 else max(3, int(len(lines) * (total - later) / total))
            with open(full, "w", encoding="utf-8") as fh:
                fh.write("".join(lines[:keep]) + (f"# rev {i}\n" if p.endswith(".py") and later else f"// rev {i}\n" if p.endswith(".js") and later else ""))
        date = (start + timedelta(days=i * 9, hours=i * 3)).isoformat()
        email = author.split()[0].lower() + "@patient-zero.dev"
        env = {**os.environ, "GIT_AUTHOR_NAME": author, "GIT_AUTHOR_EMAIL": email, "GIT_COMMITTER_NAME": author, "GIT_COMMITTER_EMAIL": email,
               "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
        run("add", "-A", env=env)
        run("commit", "-q", "-m", msg, env=env)
    return dest


if __name__ == "__main__":
    import sys
    print(build(sys.argv[1] if len(sys.argv) > 1 else "data/patient-zero"))
