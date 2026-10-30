# Projet 1 — Analyse des journaux d'un pare-feu

**Auteure :** Adja Fatoumata Banna BARRY — adjafatoumatabanna@gmail.com

Analyse d'une semaine de connexions réseau (`data/logs_reseau.csv`) : nettoyage,
calcul d'indicateurs, figures et détection de comportements suspects.

## Lancer le projet
```bash
pip install -r requirements.txt
python analyse.py
```
Le script génère `resultats.json` et les figures dans `figures/`.
Le rapport d'analyse se trouve dans [`rapport.md`](rapport.md).

## Structure
```
├── README.md
├── requirements.txt
├── analyse.py
├── rapport.md
├── resultats.json
├── data/logs_reseau.csv
└── figures/*.png
```
