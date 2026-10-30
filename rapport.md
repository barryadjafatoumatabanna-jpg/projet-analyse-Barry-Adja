# Rapport — Analyse des journaux du pare-feu

**Adja Fatoumata Banna BARRY**

## 1. Résumé
Après nettoyage (60 doublons supprimés, protocoles harmonisés en majuscules, 166 `bytes_sent`
manquants remplacés par la médiane de 1 710 octets), il reste **5 440 connexions** sur la semaine du 5 au
11 octobre. Le trafic est dominé par HTTPS (port 443, 1 874 connexions), suivi de HTTP (80), DNS (53)
et MQTT (1883). Le taux de connexions bloquées est de **13,57 %**. Le trafic est régulier (environ 700
connexions par jour), sauf le 8 octobre (1 137) et un volume d'octets très anormal le 10 octobre.
Deux comportements suspects ressortent nettement : un scan de ports et une exfiltration de données.

## 2. Comportements suspects

### a) Scan de ports par `192.168.1.99`
- Cette machine (un PC) a contacté **328 ports distincts** sur `10.0.0.5`, alors que toutes les autres IP
  en contactent 8 au maximum.
- Elle a généré **400 connexions entre 00:00 et 00:15 le 8 octobre**, soit 383 `DENY` sur 400. Cela explique
  le pic du 8 octobre (1 137 connexions) et représente 383 des 747 blocages du pare-feu.
- Ces blocages touchent surtout RDP (3389), Telnet (23) et HTTPS : signature d'une reconnaissance
  (*port scan*), probablement d'un poste compromis ou d'un usage malveillant interne.
- Preuve : figure `figures/ports_distincts_par_ip.png`.

### b) Exfiltration de données par `192.168.1.11`
- Cette caméra IoT a envoyé **259,9 Mo** au total, alors que les autres IP envoient moins de 0,7 Mo
  chacune. À elle seule, elle représente environ 95 % du volume sortant de la semaine.
- Presque tout part en **38 transferts de plus de 1 Mo, le 10 octobre**, tous vers `8.8.8.8` sur le port 8080
  (jusqu'à 8,7 Mo par connexion), alors que 8.8.8.8 est normalement un résolveur DNS. Une caméra n'a aucune raison d'envoyer
  de tels volumes vers un serveur externe sur ce port.
- Preuves : `figures/volume_par_ip.png` et `figures/octets_par_appareil.png` (les caméras IoT
  dominent largement).

## 3. Recommandations
1. **Bloquer et isoler `192.168.1.99`** : analyser le poste (antivirus/EDR), changer les mots de passe,
   et ajouter une détection de scan (alerte au-delà de N ports distincts en quelques minutes).
2. **Segmenter les objets IoT** dans un VLAN dédié avec une politique « tout interdit sauf le nécessaire » :
   les caméras ne doivent parler qu'à leur serveur d'enregistrement, pas à Internet.
3. **Filtrer le trafic sortant** : refuser le port 8080 vers l'extérieur et n'autoriser le DNS que vers
   les résolveurs internes ; mettre en place une alerte sur les volumes sortants anormaux.
4. **Fermer Telnet (23) et restreindre RDP (3389)** : utiliser SSH avec clés, et RDP uniquement via VPN.
5. **Isoler et réinitialiser la caméra `192.168.1.11`** (mot de passe par défaut, mise à jour du firmware).
6. **Centraliser les logs** dans un SIEM avec des alertes automatiques pour ce type d'anomalie.
