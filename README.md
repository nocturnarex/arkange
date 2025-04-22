# Arkange
 <p align="center">
  <img src="https://img.shields.io/badge/license-AGPL--3.0-blue" />
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" />
  <img src="https://img.shields.io/badge/interface-Terminal%20CLI-black" />  <img src="https://img.shields.io/badge/status-Dev-orange" />
  <img src="https://img.shields.io/badge/Made%20with-%E2%9D%A4-red" />
</p>


**Arkange** est un outil OSINT conçu pour rechercher à partir d'un email, d'un numéro de téléphone ou d'un nom d'utilisateur les failles liées. Il est développé avec une approche modulaire, sécurisée, et en constante évolution.

## ⚙️ Fonctionnalités principales
- 🔍 Recherche sur :
  - Pastebin, Ghostbin, Pasteee, Hastebin, Write.as
  - GitHub Gists publics
  - PublicWWW, Snusbase (web indexé)
  - Reddit (via Pushshift.io)
  - AnonPaste

- 🗂️ Exploration locale de fichiers de fuites (`.txt`, `.csv`, `.json`, `.gz`, `.zip`)
- 🔐 Sans enregistrement des résultats ni fichier sensible
- 🧪 Mode démonstration `--mock` (pour les tests)
- 💬 Affichage direct dans le terminal
- 🧵 Exécution multi-threadée (8 threads)


## 🚀 Installation

```bash
git clone https://github.com/<ton_username>/arkange.git
cd arkange
pip install requests beautifulsoup4
chmod +x arkange_cli.py  # Optionnel
```

## 🧪 Exemples d’utilisation

```bash
# Recherche en ligne d’un email
python arkange_cli.py --email test@example.com

# Analyse d’un dossier de fuites local
python arkange_cli.py --user admin --dump-folder ./fuites

# Mode démonstration (fuite fictive simulée)
python arkange_cli.py --email demo@mail.com --mock

# Mode debug (affiche les URLs explorées)
python arkange_cli.py --user admin --debug
```

## 📂 Structure d’un dossier de dumps

Vous pouvez ajouter tous tes fichiers `.txt`, `.csv`, `.json`, `.gz` ou `.zip` dans un dossier comme `./fuites/`.

Exemple :

```
./fuites/
├── leak1.txt
├── collection.json
├── db_dump.gz
└── emails.zip
```

Le script analysera **chaque ligne de chaque fichier** à la recherche de l’identifiant fourni.

## 👤 Auteur

Développé par **@nocturnarex**  

## 📌 Licence

Projet libre sous licence APGL-3.0.  
Voir [LICENSE](./LICENSE) pour les détails.

