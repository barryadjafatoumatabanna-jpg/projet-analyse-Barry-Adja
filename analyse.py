"""Projet 1 - Analyse des journaux d'un pare-feu.

Usage : python analyse.py
Lit data/logs_reseau.csv, nettoie les donnees, calcule les resultats
(resultats.json) et enregistre les figures dans figures/.
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

BASE = Path(__file__).parent
DATA = BASE / "data" / "logs_reseau.csv"
FIG_DIR = BASE / "figures"
FIG_DIR.mkdir(exist_ok=True)


def nettoyer(df: pd.DataFrame) -> pd.DataFrame:
    """Doublons exacts, protocole en majuscules, bytes_sent manquants -> mediane."""
    df = df.drop_duplicates().copy()
    df["protocol"] = df["protocol"].str.upper()
    mediane = df["bytes_sent"].median()
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def calculer_resultats(df: pd.DataFrame) -> dict:
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        "ip_scanner": str(df.groupby("src_ip")["dst_port"].nunique().idxmax()),
        "ip_exfiltration": str(df.groupby("src_ip")["bytes_sent"].sum().idxmax()),
    }


def sauver(fig, nom: str) -> None:
    fig.tight_layout()
    fig.savefig(FIG_DIR / nom, dpi=120)
    plt.close(fig)


def figures(df: pd.DataFrame, res: dict) -> None:
    # 1. Top 10 des ports de destination
    fig, ax = plt.subplots(figsize=(8, 4.5))
    top = df["dst_port"].value_counts().head(10)
    ax.bar(top.index.astype(str), top.values, color="#2c7fb8")
    ax.set_title("Top 10 des ports de destination")
    ax.set_xlabel("Port de destination")
    ax.set_ylabel("Nombre de connexions")
    sauver(fig, "top_ports.png")

    # 2. Connexions par jour
    fig, ax = plt.subplots(figsize=(8, 4.5))
    par_jour = df.groupby(df["timestamp"].dt.date).size()
    ax.plot([str(d) for d in par_jour.index], par_jour.values, marker="o", color="#d95f0e")
    ax.set_title("Nombre de connexions par jour")
    ax.set_xlabel("Jour")
    ax.set_ylabel("Nombre de connexions")
    ax.tick_params(axis="x", rotation=45)
    sauver(fig, "connexions_par_jour.png")

    # 3. Octets envoyes par type d'appareil
    fig, ax = plt.subplots(figsize=(8, 4.5))
    vol = df.groupby("device_type")["bytes_sent"].sum().sort_values(ascending=False)
    ax.bar(vol.index, vol.values / 1e6, color="#31a354")
    ax.set_title("Volume d'octets envoyes par type d'appareil")
    ax.set_xlabel("Type d'appareil")
    ax.set_ylabel("Volume envoye (Mo)")
    sauver(fig, "octets_par_appareil.png")

    # 4. Repartition ALLOW / DENY
    fig, ax = plt.subplots(figsize=(5.5, 5.5))
    rep = df["action"].value_counts()
    ax.pie(rep.values, labels=rep.index, autopct="%1.1f%%", colors=["#74c476", "#e34a33"])
    ax.set_title("Repartition ALLOW / DENY")
    sauver(fig, "repartition_allow_deny.png")

    # 5. Top 10 des IP par ports distincts (scan)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ports = df.groupby("src_ip")["dst_port"].nunique().sort_values(ascending=False).head(10)
    ax.bar(ports.index, ports.values, color="#756bb1")
    ax.set_title("Ports distincts contactes par IP source (top 10)")
    ax.set_xlabel("IP source")
    ax.set_ylabel("Nombre de ports distincts")
    ax.tick_params(axis="x", rotation=45)
    sauver(fig, "ports_distincts_par_ip.png")

    # 6. Top 10 des IP par volume envoye (exfiltration)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    vols = df.groupby("src_ip")["bytes_sent"].sum().sort_values(ascending=False).head(10)
    ax.bar(vols.index, vols.values / 1e6, color="#c51b8a")
    ax.set_title("Volume total envoye par IP source (top 10)")
    ax.set_xlabel("IP source")
    ax.set_ylabel("Volume envoye (Mo)")
    ax.tick_params(axis="x", rotation=45)
    sauver(fig, "volume_par_ip.png")


def main() -> None:
    brut = pd.read_csv(DATA)
    df = nettoyer(brut)
    res = calculer_resultats(df)
    (BASE / "resultats.json").write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    figures(df, res)
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
