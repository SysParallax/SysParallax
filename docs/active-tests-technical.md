# Documentation technique des modules Active Tests

**Projet :** AuditCore / Vulnerability Scanner

**Périmètre :** code présent dans `internal/scanner/` et `internal/audit/`

**État documenté :** 12 juillet 2026

**Nature du document :** description du comportement réellement implémenté, sans proposition de refonte automatique

## 1. Objet du document

Ce document décrit le fonctionnement réel de la phase **Active Tests**. Il ne décrit pas un fonctionnement théorique ou une capacité future : chaque comportement indiqué ci-dessous est déduit du code exécuté par le pipeline et des tests unitaires présents dans le dépôt.

L'objectif est de répondre à quatre questions :

1. quels points d'entrée sont planifiés pour chaque module ;
2. quelles requêtes sont réellement envoyées ;
3. quelles comparaisons et quelles preuves permettent une confirmation ;
4. dans quels cas le moteur refuse de conclure.

Une distinction importante est utilisée partout dans ce document :

- **test actif** : instance `ActiveTest` avec un statut technique comme `CONFIRMED`, `INCONCLUSIVE` ou `TIMEOUT` ;
- **finding** : vulnérabilité affichée et consolidée dans le rapport ;
- **replay** : nouvelle validation déclenchée depuis l'interface après le scan. Le replay possède un état séparé (`confirmed`, `not_reproduced`, `failed`, `unavailable`) et ne doit pas être confondu avec la reproduction réalisée pendant le test actif.

## 2. Résumé exécutif

### 2.1 Modules Active réellement enregistrés

Le runner enregistre actuellement les modules suivants dans `registerActiveModules` :

| Nom du module | Vulnérabilité | Type | Taxonomie principale |
|---|---|---|---|
| `sqli-detection` | SQL Injection | Active spécialisé | `WEB-SQLI-001` |
| `xss-reflected` | XSS réfléchie | Active spécialisé | `WEB-XSS-002` |
| `path-traversal` | Path Traversal | Active spécialisé | `WEB-PATH-001` |
| `ssrf-basic` | SSRF | Active spécialisé avec callback | `WEB-SSRF-001` |
| `idor-simple` | IDOR / contournement d'autorisation objet | Active spécialisé | `WEB-IDOR-001` |
| `open-redirect` | Open Redirect | Active spécialisé | `WEB-REDIR-001` |

Il n'existe pas de module Active dédié pour Stored XSS, DOM XSS, Command Injection, XXE, SSTI, Prototype Pollution, HTTP Request Smuggling, Host Header Injection, CRLF Injection, LDAP Injection, NoSQL Injection, XML Injection ou XPath Injection.

### 2.2 Modules présents mais passifs

Les modules suivants produisent des findings, mais ne suivent pas le contrat `active.Module` et ne sont pas des Active Tests spécialisés :

- `headers-security` ;
- `cors-misconfig` ;
- `cookies-security` ;
- `sensitive-exposure`.

Ils sont exécutés par la phase passive avec le contrat `engine.Module`. Leur présence dans un rapport ne signifie donc pas qu'un test actif, une baseline ou une reproduction active ont été exécutés.

### 2.3 Profils qui activent les modules

Les profils configurés dans `internal/httpx/httpx.go` sélectionnent les modules :

| Profil | Modules Active prévus |
|---|---|
| `full-scan` | SQLi, XSS réfléchie, traversal, SSRF, IDOR, open redirect |
| `passive-only` | aucun module Active |
| `api-deep` | SQLi, SSRF, IDOR, open redirect |
| `quick-check` | SQLi, XSS réfléchie, traversal |
| `custom` | les six modules disponibles, sauf désactivation explicite |

Un module non présent dans `ActiveModules` ne génère aucun `ActiveTest`. La documentation ci-dessous décrit les modules disponibles, pas uniquement ceux activés par un profil donné.

## 3. Architecture d'exécution

### 3.1 Création d'un plan

Le runner construit les plans dans l'ordre suivant :

1. les assets sont récupérés depuis le store ;
2. chaque module Active reçoit un `ModuleContext` ;
3. `active.PlansForModule` récupère les paramètres de l'asset ou les paramètres de la query URL ;
4. les paramètres sont triés et dédupliqués ;
5. le filtre `relevant(module, parameter)` décide si le nom du paramètre est pertinent ;
6. un `ActiveTestPlan` est créé avec `EntryPoint`, valeur originale, emplacement et éventuel `SourceFindingID` ;
7. chaque plan reçoit un identifiant unique et devient une instance `ActiveTest` en statut `QUEUED`.

Le lien avec un finding passif éventuel est uniquement un lien de traçabilité (`SourceFindingID`). La confirmation active ne dépend pas du fait qu'un finding passif existe déjà.

### 3.2 Points d'entrée génériques supportés par le contrat

Le modèle `EntryPointLocation` prévoit désormais :

- `query` ;
- `form` ;
- `json` ;
- `xml` ;
- `multipart` ;
- `graphql` ;
- `path` ;
- `header` ;
- `cookie`.

Les plans automatiques peuvent maintenant découvrir des feuilles JSON imbriquées, des variables GraphQL et des éléments XML lorsque le corps brut de l'asset est disponible. Les paramètres peuvent aussi être déclarés explicitement sous la forme `header:Nom`, `cookie:Nom`, `path[index]`, `json:chemin`, `graphql:variables.nom`, `xml:racine.element` ou `multipart:nom`.

### 3.3 Construction des requêtes

`active.BuildProbeRequest` construit la requête de référence ou de probe :

- query GET : la valeur du paramètre est remplacée précisément, sans concaténation du payload à l'ancienne valeur ;
- POST/PUT/PATCH form : le `BodyTemplate` est reconstruit en `application/x-www-form-urlencoded` et le paramètre ciblé reçoit la valeur fournie ;
- POST/PUT/PATCH JSON : le `BodyRaw` est décodé, le chemin imbriqué et les index de tableaux sont modifiés, puis le JSON est ré-encodé ;
- GraphQL : le même mécanisme JSON s'applique aux variables, par exemple `variables.filters[0].url` ;
- XML : un chemin d'éléments ou d'attributs est réécrit via un parseur XML ;
- multipart : les champs texte sont reconstruits et, si un corps brut avec boundary est disponible, les autres parts sont conservées ;
- path : un segment `path[index]` est remplacé dans l'URL ;
- header/cookie : la valeur ciblée est modifiée alors que les autres headers, cookies et le corps sont conservés ;
- headers de l'asset : recopiés sur la requête ;

`BuildRequest` reste un alias compatible vers ce constructeur. `sqli.NewProbeRequest` est conservé pour le chemin historique, mais délègue lui aussi au constructeur commun. Les six modules spécialisés utilisent désormais cette logique pour leurs probes structurées.

### 3.4 Instrumentation de l'executor

Chaque test reçoit un `active.Executor`. Il :

- contrôle le contexte et l'annulation ;
- interdit les nouvelles requêtes après `MarkMinimumProof()` ;
- compte les requêtes et réponses ;
- conserve les échanges HTTP dans `HTTPExchange` ;
- conserve une baseline et son hash normalisé ;
- enregistre les étapes de lifecycle ;
- applique les limites par test, endpoint et module ;
- calcule un fingerprint de requête pour limiter les répétitions ;
- limite la taille des corps conservés ;
- masque les headers, URLs et textes sensibles avant stockage.

Les statuts de progression les plus utilisés sont :

```text
QUEUED -> STARTED -> BASELINE_REQUEST_SENT -> BASELINE_RESPONSE_RECEIVED
       -> TEST_REQUEST_SENT -> TEST_RESPONSE_RECEIVED -> COMPARING
       -> VALIDATING -> REPRODUCING -> CONFIRMED / NOT_CONFIRMED / INCONCLUSIVE
```

Un test peut également finir en `UNTESTABLE`, `FAILED`, `TIMEOUT`, `CANCELLED` ou `SKIPPED`.

### 3.5 Limites par défaut

Après normalisation des options, les valeurs par défaut sont :

| Limite | Valeur par défaut | Portée |
|---|---:|---|
| `ActiveTestTimeoutSeconds` | 60 s | un test |
| `ActivePhaseTimeoutSeconds` | 900 s | phase Active entière |
| `ActiveMaxRequestsPerTest` | 32 | un test |
| `ActiveMaxRequestsPerEndpoint` | 128 | endpoint et module globalement |
| `ActiveMaxRequestsPerModule` | 512 | module globalement |
| `ActiveMaxRepetitions` | 3 | fingerprint identique dans un test |
| `ActiveMaxRedirects` | 5 | suivi manuel des redirections |
| `ActiveMaxResponseBytes` | 256 KiB | corps conservé par réponse |
| `RateLimitRPS` | 4 | client HTTP |

Les tests unitaires fournissent parfois des valeurs plus petites. Les nombres indiqués dans les sections suivantes sont donc des maxima théoriques avec les valeurs par défaut, avant saturation d'une autre limite.

### 3.6 Normalisation et masquage

Les corps sont normalisés avant hash afin d'ignorer notamment :

- dates ISO ;
- UUID ;
- valeurs associées à `csrf`, `xsrf`, `request_id`, `trace_id`, `nonce`, `token` ;
- valeurs de cookies de session connus.

Les headers sensibles, `Authorization`, cookies, tokens, secrets, mots de passe et clés API sont remplacés par `[REDACTED]` selon `SanitizeHeaders`, `RedactURL` et `RedactText`.

Limite : cette normalisation est basée sur des expressions régulières. Elle ne comprend pas le schéma métier de la réponse et peut donc supprimer une valeur qui serait réellement significative, ou ne pas reconnaître un secret dont le nom ne ressemble pas à un token ou un mot de passe.

## 4. Cycle des statuts

### 4.1 Statuts d'un ActiveTest

| Statut | Signification réelle |
|---|---|
| `CONFIRMED` | le module a obtenu sa preuve minimale et a appelé `MarkMinimumProof()` ; l'engine exige également une evidence marquée `MinimumProofReached` |
| `NOT_CONFIRMED` | le test a envoyé et analysé des réponses, mais aucune preuve suffisante n'a été obtenue |
| `INCONCLUSIVE` | un comportement est suspect ou ambigu, une limite a interrompu la validation, ou la preuve est insuffisante pour conclure |
| `UNTESTABLE` | prérequis absents, point d'entrée non constructible, identités ou callback manquants |
| `FAILED` | erreur de transport, résultat vide, baseline ou module en erreur |
| `TIMEOUT` | contexte ou requête interrompu par une deadline |
| `CANCELLED` | contexte annulé par l'opérateur ou l'arrêt de l'audit |
| `FALSE_POSITIVE` | statut prévu dans le modèle, mais aucun module Active spécialisé ne le produit automatiquement |
| `SKIPPED` | statut disponible pour un test non exécuté ; il n'est pas utilisé comme conclusion normale par les six modules |

### 4.2 Effet de `normalizeActiveResult`

Après le retour du module, l'engine applique des garde-fous :

- `NOT_CONFIRMED` sans aucune requête devient `UNTESTABLE` ;
- un résultat avec requêtes mais sans réponse exploitable devient `INCONCLUSIVE` ;
- `CONFIRMED` sans evidence ou sans `MinimumProofReached` est rétrogradé en `INCONCLUSIVE`.

Cette étape protège le lifecycle, mais elle ne transforme pas tous les findings en statut équivalent. Un finding est créé par les modules spécialisés essentiellement lorsqu'ils ont décidé de confirmer.

### 4.3 Statut du finding et replay

Un finding créé par un module peut rester `confirmed` même après un replay non reproduit : le statut représente la qualification obtenue pendant le scan. L'état actuel du replay est conservé séparément :

- `not_run` : aucun replay lancé ;
- `confirmed` : la preuve a été retrouvée ;
- `not_reproduced` : la requête a répondu mais le matcher n'a pas retrouvé la preuve ;
- `failed` : le replay n'a pas pu s'exécuter ;
- `unavailable` : aucune preuve HTTP rejouable n'est disponible.

L'interface doit donc lire les deux informations : « confirmé lors du scan » et « état de la dernière revalidation ».

### 4.4 Limites actuelles transversales

Les limites communes à tous les modules sont l'absence de navigateur réel pour les modules qui ne l'utilisent pas encore, la couverture limitée des corps non JSON/form, la dépendance aux noms heuristiques des paramètres, la normalisation basée sur des motifs et l'absence d'un oracle métier générique. Une réponse HTTP correcte ne constitue donc jamais à elle seule une preuve universelle : chaque module ajoute son propre matcher, mais les modules ne couvrent pas tous les contextes d'exécution possibles.

### 4.5 Navigateur headless contrôlé

`internal/scanner/browser` fournit un runner headless commun basé sur le protocole Chrome DevTools et `x/net/websocket`, sans dépendance supplémentaire. Chaque exécution :

- lance Chromium/Chrome/Edge avec un profil temporaire supprimé à la fin ;
- utilise `--disable-extensions`, `--incognito`, un user-data-dir isolé et une durée maximale ;
- intercepte les requêtes avec `Fetch` et bloque les origins hors allowlist avant de les poursuivre ;
- limite les navigations principales et conserve les URLs, événements bloqués et événements console ;
- récupère le DOM rendu avec une taille maximale ;
- peut observer un marqueur textuel dans le DOM ou les événements console ;
- arrête le processus navigateur et supprime le profil même en cas d'erreur.

Le runner refuse les URLs `file:`, `javascript:` et les origines non autorisées. Si aucun exécutable compatible n'est disponible, il retourne `ErrBrowserUnavailable`. Le module `xss-reflected` consomme ce composant pour les réflexions JavaScript GET lorsque l'option navigateur est activée ; le module open redirect ne l'utilise pas encore.

Le runner est actuellement consommé par `xss-reflected` pour les réflexions
JavaScript lorsque `ActiveBrowserEnabled` est vrai. Le module open redirect ne
l'utilise pas encore : ses redirections JavaScript et `meta refresh` restent
statiques et `INCONCLUSIVE`.

## 5. SQL Injection - `sqli-detection`

### 5.1 Objectif

Le module cherche deux familles :

1. **error-based** : l'entrée provoque une signature d'erreur SQL qui n'existe pas dans la baseline et qui se reproduit ;
2. **boolean-based** : un contrôle vrai ressemble à la baseline, un contrôle faux produit une réponse différente, et le couple se reproduit.
3. **time-based** : lorsque l'option dédiée est activée, une condition temporelle courte est comparée à un contrôle neutre et reproduite avec une analyse statistique robuste.

Le module ne confirme pas une SQLi sur un simple code 500, une différence de taille seule, un ralentissement ou une variation dynamique non stable.

### 5.2 Points d'entrée et lancement

La planification accepte tout paramètre non vide pour `sqli-detection`, qu'il vienne de `Asset.Params` ou de la query URL. Les types de point d'entrée annoncés par le plan peuvent être :

- query GET ;
- formulaire POST/PUT/PATCH ;
- JSON POST/PUT/PATCH selon le `BodyType`.

En pratique :

- la baseline et les probes utilisent `active.BuildProbeRequest` ;
- le chemin GET et le formulaire sont couverts ;
- JSON imbriqué, tableaux, XML, multipart, path, headers et cookies utilisent le même contrat ;
- les paramètres GraphQL sont traités comme des chemins JSON sous `variables` lorsque le corps brut est disponible.

Le module ne s'appuie pas sur le finding passif pour décider de la preuve. Le finding passif éventuel est seulement associé au plan via `SourceFindingID`.

### 5.3 Requêtes et ordre exact

Pour un paramètre :

1. une requête baseline avec la valeur originale ;
2. une seconde baseline identique si `ActiveMaxRequestsPerTest != 1`, afin de vérifier que le contenu normalisé est stable ;
3. jusqu'à six probes error-based : `'`, `''`, variantes booléennes et double quote ;
4. lorsqu'une signature SQL apparaît, une seconde requête identique est envoyée pour la reproduction ;
5. si aucune preuve error-based n'est confirmée, jusqu'à trois couples boolean-based sont essayés ;
6. chaque couple comporte une requête vraie et une requête fausse ;
7. le couple vrai/faux est ensuite reproduit avec deux nouvelles requêtes ;
8. si `ActiveSQLiTimingEnabled` est activé et qu'aucune preuve précédente n'est obtenue, les contrôles neutres, probes temporelles et reproductions time-based sont envoyés.

Le maximum théorique avec les valeurs par défaut est :

```text
2 baselines
+ 6 probes error-based
+ jusqu'à 6 répétitions error-based
+ 3 x 2 probes boolean
+ 3 x 2 reproductions boolean
+ 2 contrôles time-based
+ 2 probes time-based
+ 1 reproduction time-based
= 31 requêtes au maximum avec le time-based activé
```

La stratégie time-based réutilise les deux baselines initiales. Les limites d'endpoint, de module et de répétition peuvent arrêter plus tôt ; une configuration avec davantage d'échantillons doit augmenter explicitement `ActiveMaxRequestsPerTest`.

### 5.4 Validation error-based

La réponse de baseline doit être exploitable et son code ne doit pas être supérieur ou égal à 500. Un HTTP 500 de baseline est classé `INCONCLUSIVE`, car le module ne peut pas distinguer une erreur applicative générique d'une erreur SQL.

Le module reconnaît notamment :

- `you have an error in your sql syntax` ;
- signatures MySQL ;
- `SQLSTATE` ;
- erreurs PostgreSQL ;
- erreurs SQLite ;
- erreurs Oracle ;
- `unclosed quotation mark` ;
- erreurs de requête explicites.

Une signature est acceptée seulement si :

- elle est absente de la baseline ;
- elle apparaît dans la réponse du payload ;
- elle est identique dans la répétition.

La preuve minimale contient le payload, la requête et la réponse répétée ainsi que la signature textuelle. Le module appelle `MarkMinimumProof()` après cette seconde observation.

### 5.5 Validation boolean-based

Pour chaque paire :

- la réponse vraie est comparée à la baseline ;
- la réponse fausse doit être différente de la réponse vraie ;
- la comparaison utilise le code HTTP et le hash du corps normalisé ;
- le couple vrai/faux est rejoué ;
- la réponse vraie répétée doit correspondre à la baseline ;
- la réponse fausse répétée doit correspondre à la première réponse fausse.

La conclusion est donc une différence conditionnelle reproductible, et non une simple différence de longueur.

### 5.6 Variantes couvertes

| Variante SQLi | État | Détail |
|---|---|---|
| Error-based | Couvert | signatures textuelles, répétition obligatoire |
| Boolean-based | Couvert | trois couples vrai/faux, comparaison normalisée et reproduction |
| Blind boolean | Partiellement couvert | seulement si le comportement produit une différence de code/hash observable |
| Time-based blind | Couvert sur activation explicite | famille `SLEEP` MySQL-compatible, contrôles neutres, médianes, MAD, seuil adaptatif et reproduction ; pas de détection de dialecte |
| Union-based | Non couvert | aucun payload UNION ni comparaison de colonnes |
| Stacked queries | Non couvert | le payload de sommeil n'est pas une validation de stacked queries |
| Out-of-band SQLi | Non couvert | aucun callback SQL |
| JSON/XML/multipart | Partiellement couvert par le constructeur | dépend de la présence d'un `BodyRaw`, d'un `BodyTemplate` ou d'une métadonnée de chemin |

### 5.7 Performances, faux positifs, faux négatifs et limites

Le budget maximal est détaillé en 5.3. Le module s'arrête immédiatement après une signature reproduite, un couple booléen reproduit ou une preuve time-based reproduite, ce qui réduit généralement le nombre réel de requêtes.

### 5.8 Validation time-based statistique

Cette stratégie est désactivée par défaut et s'active avec `ActiveSQLiTimingEnabled`. Elle utilise actuellement une famille MySQL-compatible basée sur `SLEEP`; elle ne tente aucune extraction de données et ne déduit pas le dialecte du serveur.

Le déroulement est le suivant :

1. la baseline initiale est réutilisée, avec deux échantillons attendus par défaut ; si elle est absente, instable ou non fonctionnelle, le résultat reste `INCONCLUSIVE` ;
2. le module construit un contrôle neutre `SLEEP(0)` et une probe courte avec le délai configuré, par défaut 500 ms et plafonné à 2 secondes ;
3. deux contrôles neutres puis deux probes temporelles sont envoyés par défaut ; les valeurs peuvent être réduites ou augmentées jusqu'à trois échantillons ;
4. les durées `HTTPResponseRecord.DurationMillis` sont conservées dans `ActiveEvidence.Timing` ;
5. le module calcule la médiane et la MAD, c'est-à-dire la médiane des écarts absolus à la médiane ;
6. le seuil est au minimum de 100 ms, augmenté selon la dispersion de la baseline et du contrôle, et ne peut pas être inférieur à 35 % du délai demandé ;
7. une variance excessive, un contrôle qui ne ressemble pas à la baseline ou des échantillons insuffisants donnent `INCONCLUSIVE` ;
8. la probe doit dépasser le contrôle au-dessus du seuil dans la majorité des échantillons ;
9. une probe positive est envoyée une nouvelle fois par défaut. `CONFIRMED` exige que cette reproduction dépasse elle aussi le seuil, puis `MarkMinimumProof()` est appelé.

Un endpoint naturellement lent produit donc `NOT_CONFIRMED` si baseline, contrôle et probe restent au même niveau. Une latence instable produit `INCONCLUSIVE`, car le module refuse de transformer une mesure bruitée en preuve. Un timeout reste `TIMEOUT`, tandis qu'une limite de requêtes produit `INCONCLUSIVE` avec la limite tracée.

Les options disponibles sont : `ActiveSQLiTimingEnabled`, `ActiveSQLiTimingDelayMillis`, `ActiveSQLiTimingBaselineSamples`, `ActiveSQLiTimingControlSamples`, `ActiveSQLiTimingProbeSamples` et `ActiveSQLiTimingReproductionSamples`. Les compteurs sont plafonnés à trois par catégorie par la normalisation des options. Le délai reste borné à 2 secondes.

Les limites actuelles sont importantes : seule la syntaxe MySQL-compatible `SLEEP` est générée, les variantes PostgreSQL/MSSQL/Oracle/SQLite ne sont pas encore sélectionnées, et le module ne confirme que les contextes numériques ou chaînes simples construits par le constructeur commun. Les protections WAF, les conversions de type SQL, les fonctions de délai propriétaires et les applications dont la variance naturelle dépasse le seuil peuvent produire `NOT_CONFIRMED` ou `INCONCLUSIVE`.

- `CONFIRMED` : signature SQL répétée ou couple booléen répété ;
- `NOT_CONFIRMED` : test complet, aucune différence fiable ;
- `INCONCLUSIVE` : baseline 500, signature observée une seule fois, limite atteinte, réponse dynamique non résolue ;
- `UNTESTABLE` : pas de paramètre ou requête de référence impossible ;
- `FAILED` : erreur de transport ou réponse inutilisable ;
- `TIMEOUT` / `CANCELLED` : contexte interrompu.

Le module ne produit pas automatiquement `FALSE_POSITIVE`.

Les protections contre les faux positifs sont la baseline double, la signature spécifique, les hashes normalisés, la reproduction et le refus de conclure sur un 500 générique. Les limites principales sont les suivantes :

- une application qui affiche une signature SQL générique peut encore provoquer un faux positif ;
- la normalisation ne comprend pas tous les champs dynamiques ;
- une SQLi qui ne change ni code ni contenu normalisé peut être manquée ;
- les time-based, union-based et OOB ne sont pas testées ;
- les paramètres de chemin, headers, cookies et XML ne sont pas couverts.

### 5.8 Exemple complet

Pour `GET /search?id=1` :

1. baseline `id=1`, puis seconde baseline ;
2. `id='` et les autres payloads error-based ;
3. une réponse `HTTP 200` contenant `You have an error in your SQL syntax` est observée ;
4. le même payload est envoyé une seconde fois ;
5. la même signature apparaît encore ;
6. le test est `CONFIRMED`, l'evidence conserve la baseline, les deux échanges et la règle de validation ;
7. `MarkMinimumProof()` arrête les probes suivantes.

Pour une cible saine qui renvoie toujours le même contenu, le test essaie les couples booléens mais les réponses normalisées restent identiques : `NOT_CONFIRMED`.

## 6. Reflected XSS - `xss-reflected`

### 6.1 Objectif

Le module ne cherche pas seulement une chaîne réfléchie. Il cherche une valeur :

- réfléchie dans la réponse ;
- non correctement encodée ;
- placée dans un contexte HTML interprétable ;
- capable de produire une construction active détectable ;
- reproduite dans une seconde requête.

### 6.2 Points d'entrée et prérequis

Le module refuse de planifier ses tests lorsque `Fingerprint.LooksLikeAPI` est vrai. Pour les autres assets, il utilise les paramètres query/form/JSON exposés par `PlansForModule`, avec la même limite de construction des probes décrite dans la section SQLi.

Il ne teste pas :

- les cookies ;
- les headers ;
- les fragments URL côté navigateur ;
- les WebSockets ;
- les champs multipart ;
- les sinks JavaScript côté client.

### 6.3 Payloads et nombre de requêtes

Les six formes présentes dans le code sont :

- balise `<script>` directe ;
- variantes avec rupture de guillemet double ou simple ;
- attribut événementiel `onerror` ;
- URL `javascript:` ;
- événement SVG `onload`.

Pour un paramètre :

1. une baseline ;
2. au maximum six probes, dans l'ordre du tableau de payloads ;
3. si une réflexion active est détectée, une requête de reproduction avec le même payload ;
4. arrêt après une preuve confirmée.

Maximum théorique : huit requêtes par paramètre. Il n'y a pas de seconde baseline spécifique XSS.

### 6.4 Analyse de réflexion

`analyzeReflection` commence par chercher le payload brut dans le corps.

Si le payload brut est présent :

- réponse JSON ou corps JSON valide : contexte `json`, non exécutable ;
- contenu entre `<script>` : contexte `javascript` ;
- contenu entre `<style>` : contexte `css` ;
- valeur entre `<` et `>` après un nom d'attribut : contexte `attribute` ;
- sinon : contexte `html-text`.

Le module cherche ensuite une construction active dans un parsing HTML :

- nœud `<script>` si le payload contient `<script` ;
- attribut dont le nom commence par `on` et dont la valeur contient `alert(1)` ;
- attribut `href` commençant par `javascript:`.

Le corps est comparé à une version où la première occurrence du payload a été retirée. La construction active doit augmenter grâce au payload. Une simple présence de texte n'est donc pas suffisante.

Si le payload brut n'est pas trouvé, le module cherche plusieurs représentations encodées : HTML, JSON, JSON HTML, query URL et path URL. Une valeur encodée est documentée comme réfléchie mais non active.

### 6.5 Confirmation et reproduction

Une confirmation exige :

- réflexion localisée ;
- contexte non `javascript`, non `json` et non `css` ;
- construction active détectée dans le HTML parsé ;
- seconde réponse avec le même contexte et le même encodage ;
- evidence avec emplacement, contexte, encodage et raison.

Le module appelle `MarkMinimumProof()` après la reproduction.

Une réflexion brute dans un bloc JavaScript ou CSS est conservée comme suspicion : `INCONCLUSIVE`, car le payload actuel ne prouve pas une sortie de chaîne ou un sink exécutable dans ces contextes.

### 6.6 Validation navigateur optionnelle du JavaScript

Depuis l'ajout du runner headless, une réflexion brute dans un bloc JavaScript
peut être validée plus fortement lorsque `AuditOptions.ActiveBrowserEnabled`
est activé. Cette option reste désactivée par défaut afin qu'un audit HTTP ne
dépende pas de la présence de Chromium, Chrome ou Edge.

Le chemin navigateur est volontairement limité aux requêtes `GET` dont le point
d'entrée est un paramètre query ou un segment de chemin. Il ne fabrique pas de
requête POST, ne soumet pas de formulaire et ne tente pas d'exécuter une
interaction utilisateur.

Pour un contexte JavaScript suspect :

1. le module génère un marqueur unique par test ;
2. il essaie au maximum deux variantes de rupture de chaîne, guillemet simple
   puis guillemet double ;
3. chaque variante pose un attribut DOM contrôlé contenant le marqueur ;
4. le runner ouvre deux profils navigateur isolés et indépendants ;
5. le résultat est `CONFIRMED` uniquement si le marqueur est observé dans les
   deux rendus ;
6. `MarkMinimumProof()` est appelé après cette reproduction navigateur.

Le runner autorise exactement l'origine de la requête probe. Les ressources
externes, navigations secondaires, schémas `file:`/`javascript:` et origines
hors périmètre sont bloqués et tracés. Le DOM, les URLs, les événements CDP et
les erreurs sont limités puis masqués avant d'être stockés.

La preuve navigateur est conservée dans `ActiveEvidence.Browser` : URL finale,
origine finale, DOM borné, marqueur, navigations, événements, URLs bloquées,
erreur éventuelle et nombre de reproductions. Une absence de navigateur, un
blocage d'origine ou une erreur CDP laisse le résultat `INCONCLUSIVE`, jamais
`CONFIRMED`.

Le budget maximal de ce chemin est de quatre rendus navigateur par point
d'entrée, soit deux variantes avec deux reproductions chacune. Les tests
HTTP déjà exécutés restent dans les échanges Active ; le budget navigateur est
indépendant mais borné par `ActiveBrowserTimeoutSeconds` (10 secondes par
défaut, 30 secondes maximum).

Cette validation ne constitue pas encore un module DOM XSS générique : elle
prouve seulement l'exécution d'une réflexion JavaScript du point d'entrée
HTTP testé. Les sources `location.hash`, `postMessage`, stockage local,
frameworks et sinks découverts dans des scripts séparés restent hors périmètre.

### 6.7 Variantes couvertes et non couvertes

| Variante XSS | État | Détail |
|---|---|---|
| HTML text | Couvert | réflexion brute et construction active |
| Attribut HTML | Couvert | rupture d'attribut et événements détectables |
| Event handlers | Partiellement couvert | `onerror`/`onload` avec `alert(1)` |
| SVG | Partiellement couvert | surtout `svg onload`, sans rendu navigateur |
| JSON | Détecté mais non confirmé | le JSON est classé non interprétable comme HTML |
| JavaScript string | Partiellement couvert | `INCONCLUSIVE` sans navigateur ; validation navigateur optionnelle pour GET query/path si le marqueur est reproduit |
| URL / `javascript:` | Payload présent, couverture limitée | pas d'exécution navigateur ; classification dépend du contexte HTML |
| DOM XSS | Non couvert comme module autonome | le runner navigateur valide seulement la réflexion JavaScript du point d'entrée HTTP |
| Stored XSS | Non couvert | pas de workflow écriture puis lecture |
| CSP bypass | Non couvert | CSP non évaluée pendant la confirmation |

### 6.8 Faux positifs et faux négatifs

Réduction des faux positifs : parsing HTML, comparaison avant/après suppression du payload, distinction JSON/JavaScript/CSS et reproduction.

Faux positifs encore possibles :

- un parser HTML peut compter une construction sans vérifier le comportement d'un navigateur réel ;
- le motif `alert(1)` est très spécifique et ne représente pas toutes les exécutions possibles ;
- une réflexion dans une zone HTML inhabituelle peut être mal localisée lexicalement.

Faux négatifs probables :

- payloads filtrés mais exploitables par un encodage alternatif ;
- contextes JavaScript nécessitant une fermeture de chaîne calculée ;
- DOM XSS ;
- XSS stockée ;
- réponses fragmentaires ou exécutées uniquement après interaction navigateur.

### 6.9 Exemple complet

Pour `GET /search?q=hello` qui répond dans `<input value="...">` :

1. baseline avec `q=hello` ;
2. payload `"><script>alert(1)</script>` ;
3. réponse HTML contenant le payload dans un attribut ;
4. le parseur constate une nouvelle construction active ;
5. le même payload est envoyé une seconde fois ;
6. contexte `attribute`, encodage `raw/non encoded` et construction active sont identiques ;
7. résultat `CONFIRMED` et finding `WEB-XSS-002`.

Si la cible renvoie `html.EscapeString(payload)`, le module identifie une réflexion HTML encodée et conclut `NOT_CONFIRMED`.

## 7. Path Traversal - `path-traversal`

### 7.1 Objectif

Le module cherche la résolution d'un chemin hors du répertoire prévu. Il exige un marqueur de ressource spécifique ; un HTTP 200, une taille différente ou un contenu générique ne suffisent pas.

### 7.2 Points d'entrée et conditions

Les noms de paramètres privilégiés contiennent :

`file`, `path`, `dir`, `folder`, `include`, `page`, `template`, `view`, `load`, `doc`, `document`, `img`, `image`.

Si aucun nom ne correspond, le premier paramètre disponible est quand même testé. Si aucun paramètre n'est présent, le module ne planifie pas le test.

Les paramètres query, form et JSON sont pris en charge par le constructeur commun. Les segments de chemin peuvent être construits lorsqu'un plan explicite utilise `EntryPointPath`, mais le module traversal ne découvre pas encore automatiquement tous les chemins REST sans métadonnée d'asset.

### 7.3 Marqueur et payloads

Le marqueur par défaut est `root:x:0:0`. Il peut être remplacé par `ActiveTraversalProofMarker`. Un `ActiveTraversalProofPath` personnalisé sans marqueur explicite rend le test `INCONCLUSIVE`, car le module ne peut pas savoir quelle preuve rechercher. `ActiveTraversalProofPlatform` peut limiter les probes à `unix`/`linux` ou `windows`. `ActiveTraversalProofResourceType` distingue `path-traversal` de `lfi`/`local-file-inclusion` dans le finding et l'evidence.

Les familles de payloads sont :

- traversals Unix de profondeur variable vers la ressource de preuve ;
- slash encodé une fois et doublement encodé ;
- traversals Windows avec backslash direct ou encodé ;
- variante null byte héritée, lorsque la plateforme le permet.

La sélection par défaut couvre neuf variantes bornées, tandis qu'une plateforme explicite réduit le nombre de probes et évite d'envoyer des chemins Windows à une cible Unix ou inversement.

### 7.4 Déroulement et nombre de requêtes

Pour un paramètre :

1. baseline avec la valeur normale ;
2. chemin invalide `__auditcore_invalid_path_7f3c__` ;
3. probes traversal sélectionnées par plateforme, jusqu'à neuf par défaut ;
4. dès qu'un marqueur est observé, répétition du même payload ;
5. arrêt après preuve minimale.

Maximum théorique : douze requêtes.

### 7.5 Validation

Le marqueur doit être :

- absent de la réponse normale ;
- absent de la réponse du chemin invalide ;
- présent dans la réponse traversal ;
- présent dans la répétition traversal ;
- reçu avec un code inférieur à 500.

La différence générique fournie par l'executor est conservée en complément, mais elle ne décide pas seule de la conclusion. Le module appelle `MarkMinimumProof()` uniquement après la seconde présence du marqueur.

### 7.6 Performances, faux positifs, faux négatifs et variantes non couvertes

Le budget maximal est détaillé en 7.4. Le module s'arrête après le premier marqueur reproduit et n'envoie pas les payloads restants.

| Variante | État |
|---|---|
| Unix `/etc/passwd` | Couvert |
| Encodage URL / double encodage | Couvert |
| Windows `win.ini` | Couvert |
| Null byte | Payload présent, efficacité dépend de la cible moderne |
| LFI local | Couvert via `ActiveTraversalProofResourceType=lfi` avec une ressource et un marqueur de recette dédiés |
| RFI distant | Non couvert ; aucun protocole distant n'est injecté |
| Traversal de segments REST | Couvert lorsqu'un plan explicite fournit `EntryPointPath`, découverte automatique encore limitée |
| Archive traversal / Zip Slip | Non couvert |
| Normalisation Unicode ou double décodage complexe | Non couvert ; seules les variantes slash/backslash et double encodage bornées sont générées |

Faux positif possible si l'application expose déjà le marqueur dans une réponse de contrôle. Le code le détecte et classe alors le cas `INCONCLUSIVE`. Faux négatif possible si le fichier de preuve n'est pas `/etc/passwd`, si la réponse est binaire, si la ressource requiert une session, ou si la canonicalisation utilise une forme non présente dans la liste.

### 7.7 Exemple complet

Pour `GET /download?file=home.txt` :

1. baseline : `home.txt` retourne `normal resource` ;
2. contrôle invalide retourne `not found` ;
3. `../../../etc/passwd` retourne `root:x:0:0...` ;
4. le marqueur est absent des deux contrôles ;
5. le même payload retourne encore le marqueur ;
6. résultat `CONFIRMED`, evidence avec normal/invalide/traversal et reproduction.

Si la cible retourne seulement 200 et un corps plus long sans `root:x:0:0`, résultat `NOT_CONFIRMED`.

## 8. SSRF - `ssrf-basic`

### 8.1 Objectif

Le module confirme une requête réellement émise par le serveur cible vers une URL de callback contrôlée. Une URL acceptée, affichée, redirigée côté client ou retournée dans le corps ne suffit pas.

Les anciennes cibles metadata et loopback sont désactivées dans le chemin Active : `ssrfTargets` est vide. Le module utilise uniquement un callback configuré par l'opérateur.

### 8.2 Points d'entrée et configuration obligatoire

Les paramètres suspects comprennent notamment :

`url`, `webhook`, `callback`, `redirect`, `src`, `href`, `path`, `dest`, `destination`, `remote`, `fetch`, `load`, `import`, `endpoint`, `service`.

Le test n'est pas lancé sans :

- `ActiveSSRFCallbackURL` ;
- `ActiveSSRFCallbackCheckURL`.

Chaque URL reçoit un token UUID unique. Le template peut utiliser `{token}` ou recevoir un paramètre `auditcore_token`.

Les URLs callback et check doivent être absolues en HTTP(S). Par défaut, les hosts localhost, `.local`, `.internal`, loopback, privés et link-local sont refusés. `ActiveSSRFAllowPrivateCallback` permet un opt-in explicite pour les environnements de test locaux.

### 8.3 Requêtes

Pour un paramètre :

1. une baseline avec la valeur originale ;
2. une première probe avec un callback et un token uniques ;
3. un polling borné vers l'URL de vérification ;
4. si le premier callback est observé, une seconde probe avec un second token et un second callback distincts ;
5. un second polling indépendant doit observer le second token avant toute confirmation OOB.

Les probes passent par l'executor et sont comptées dans le budget Active. Les requêtes de polling vers le check endpoint utilisent un client HTTP séparé, mais chaque poll est conservé dans `ActiveEvidence.CallbackObservations[].PollTrace` et compté dans `CallbackPolls`. Le callback entrant du serveur cible n'est évidemment pas envoyé par le scanner.

La fenêtre de polling est configurable avec `ActiveSSRFCallbackWindowMillis`, l'intervalle avec `ActiveSSRFCallbackPollIntervalMillis` et le nombre maximal de polls avec `ActiveSSRFCallbackMaxPolls`. Les valeurs par défaut sont respectivement 500 ms, 100 ms et 6 polls, avec des plafonds pour empêcher une explosion des requêtes de contrôle.

Pour GET, le callback est injecté dans la query. Pour POST/PUT/PATCH, `active.BuildProbeRequest` reconstruit un formulaire, un objet JSON, un XML ou un multipart selon le plan.

La probe cible est exécutée avec `DoNoRedirect`. Une redirection HTTP de la cible vers le callback n'est pas considérée comme une preuve d'émission serveur.

### 8.4 Validation

La confirmation exige l'un des deux chemins :

1. le collecteur callback indique que le premier token puis le second token de reproduction ont été observés séparément ;
2. la réponse directe de la cible contient le marqueur configuré `ActiveSSRFCallbackMarker`.

Le JSON du collecteur doit indiquer un booléen `observed`, `received`, `matched` ou `callback_received` à `true`. Si un token est présent dans la réponse JSON, il doit correspondre au token du test. Un JSON qui ne fait que refléter le token n'est pas accepté.

Un callback absent, tardif, invalide ou associé à un autre token ne constitue pas une preuve. Sans seconde observation OOB, le résultat reste `INCONCLUSIVE`, même si le premier callback a été reçu. La preuve directe configurée reste un chemin séparé et ne dépend pas du polling OOB.

Lorsque le collecteur fournit une destination effective, un hostname ou une adresse, ces valeurs sont conservées dans l'observation. Une destination fournie qui ne correspond pas à l'hostname du callback attendu est classée `mismatched` et ne peut pas confirmer le test.

### 8.5 Performances, faux positifs, faux négatifs, variantes et limites

Le budget cible comprend une baseline, jusqu'à deux probes instrumentées et les polls bornés des deux observations. Le test s'arrête dès que les deux callbacks indépendants sont confirmés.

| Variante | État |
|---|---|
| URL fetch SSRF avec callback OOB | Couvert |
| Callback avec token unique | Couvert |
| Reproduction avec second token | Couvert |
| Polling configurable et tracé | Couvert |
| Callback absent/tardif/invalide/mauvais token | Couvert |
| Preuve directe configurée | Couvert |
| URL simplement affichée | Refusée |
| Redirection HTTP côté cible | Refusée |
| Redirection JavaScript | Refusée par absence de callback |
| Metadata cloud intégrée | Non utilisée |
| DNS rebinding | Non couvert |
| SSRF via header, cookie, multipart, XML | Non couvert par le plan automatique |
| Protocoles `file://`, `gopher://`, `ftp://` | Refusés pour les URLs callback et non testés comme stratégie séparée |

La preuve est forte lorsque deux callbacks réels et distincts sont observés. Le principal faux positif évité est l'acceptation d'une URL simplement affichée, d'une redirection HTTP ou d'un callback attribué au mauvais token. Un faux positif reste possible si le collecteur associe incorrectement un token à un autre test ou si la preuve directe est configurée avec un marqueur trop générique. Les faux négatifs peuvent venir d'un callback retardé au-delà de la fenêtre, d'un collecteur indisponible, d'un budget trop faible ou d'une application qui fait la requête via un protocole non couvert. Les limites restantes sont l'absence de validation DNS avancée, la dépendance au collecteur et l'absence de navigateur pour les flux client.

### 8.6 Statuts

- `CONFIRMED` : callback observé ou preuve directe équivalente ;
- `INCONCLUSIVE` : callback absent, URL affichée ou redirection seulement ;
- `UNTESTABLE` : callback manquant, URL invalide ou hors périmètre ;
- `FAILED` / `TIMEOUT` / `CANCELLED` : échange ou contexte interrompu ;
- `NOT_CONFIRMED` n'est pas utilisé comme conclusion normale de ce module.

### 8.7 Exemple complet

Pour `GET /fetch?url=hello` :

1. baseline `url=hello` ;
2. le scanner génère `https://collector.example/hit?token=<uuid>` ;
3. probe `url=<callback unique>` ;
4. le serveur cible effectue réellement la requête vers `/hit` ;
5. le scanner interroge `/check?token=<uuid>` ;
6. la réponse JSON confirme `observed=true` avec le même token ;
7. résultat `CONFIRMED`, evidence avec token, callback URL, check URL et preuve redacted.

Si la cible répond `displayed URL: ...` ou `302 Location: ...`, le résultat est `INCONCLUSIVE`.

## 9. IDOR - `idor-simple`

### 9.1 Objectif

Le module valide un défaut d'autorisation objet en comparant plusieurs identités et plusieurs ressources dont la propriété est connue. Une modification d'identifiant et un HTTP 200 ne suffisent pas.

### 9.2 Prérequis obligatoires

Le test est `UNTESTABLE` sans :

- au moins deux identités distinctes présentes dans `ActiveIDORIdentities` ;
- au moins deux ressources avec un `OwnerIdentity` distinct ;
- `ActiveIDORResources` pour une matrice explicite, ou les deux paires historiques `ActiveIDOROwner*`/`ActiveIDORNonOwner*` ;
- deux URLs absolues HTTP(S) ;
- le même host que l'asset ;
- des hosts autorisés si `AllowedHosts` est défini.

Chaque identité peut porter `role`, `tenant`, `organization`, `scopes`, headers, cookies, bearer token ou basic auth. Chaque ressource peut porter un nom, une URL, son propriétaire et son tenant. Le module utilise `WithAuthenticationOverride` pour empêcher l'authentification globale de contaminer la session testée. La matrice est limitée à huit identités et huit ressources.

Les opérations POST, PUT, PATCH et DELETE sont considérées comme des écritures. Elles sont refusées par défaut et ne sont testées que si `ActiveIDORAllowWrite` est vrai.

### 9.3 Points d'entrée

La planification vise les noms :

`id`, `user_id`, `account_id`, `order_id`, `item_id`, `product_id`, `doc_id`, `tenant`.

Elle peut donc préparer query/form/JSON. Si aucun paramètre correspondant n'existe, un segment numérique de chemin peut produire un `EntryPointPath`. Toutefois, la construction actuelle remplace l'URL de ressource explicite par l'URL fournie dans les options ; le segment path n'est pas manipulé comme un encodeur REST autonome.

### 9.4 Déroulement exact

Pour une opération de lecture, le module :

1. envoie une requête de contrôle avec le propriétaire de chaque ressource ;
2. envoie une requête croisée pour chaque identité différente du propriétaire ;
3. compare chaque réponse croisée à la réponse du propriétaire de la même ressource ;
4. conserve pour chaque cas l'acteur, le rôle, le tenant, le propriétaire, la ressource, le statut et la décision métier dans `ActiveEvidence.IDORCases`.

Pour une opération d'écriture :

1. contrôle propriétaire sur chaque ressource ;
2. tentative croisée par les identités non propriétaires ;
3. arrêt et conclusion selon les réponses observées.

Le contrôle propriétaire est utilisé comme baseline métier par ressource. Le nombre de requêtes est `nombre_de_ressources + nombre_de_cas_croisés`, sans énumération d'identifiants.

### 9.5 Validation métier

Une réponse est un succès métier si :

- le code est 2xx ;
- avec `ActiveIDORSuccessMarker`, le marqueur est présent ;
- sans marqueur, le corps est non vide, mesure au moins huit caractères et n'est pas un simple `ok`, `success`, `true`, `false`, `accepted`, `authorized`, `forbidden` ou `not found`.

Le cross-case est `CONFIRMED` lorsque la session non autorisée reçoit une réponse métier équivalente à celle de la ressource de référence :

- avec marqueur : le marqueur est présent et le code HTTP correspond ;
- avec JSON métier : les champs connus (`owner`, `owner_id`, `user_id`, `tenant_id`, `account_id`, `organization`, `permissions`, `role`, `resource_id`, `id`) sont comparés ;
- sans projection JSON : le code et le corps normalisé doivent correspondre.

Si tous les cross-cases sont refusés par 401, 403, 404, 405 ou par le marqueur de refus, le résultat est `NOT_CONFIRMED`. Si une réponse est 2xx mais ne contient pas une preuve métier comparable, le résultat est `INCONCLUSIVE`.

### 9.6 Performances, faux positifs, faux négatifs, variantes et limites

Le test envoie une baseline par ressource puis un cas croisé par couple acteur/ressource non propriétaire, sans boucle d'énumération. Il s'arrête dès le premier cross-case équivalent confirmé. Les matrices dépassant huit identités ou huit ressources sont refusées comme `UNTESTABLE`.

| Variante | État |
|---|---|
| Lecture owner/non-owner | Couvert |
| Contrôle croisé dans les deux directions | Couvert en lecture |
| Modification non autorisée | Couvert seulement avec opt-in explicite |
| Plusieurs identités | Couvert, jusqu'à huit identités |
| Ressources propriétaires explicites | Couvert via `ActiveIDORResources` |
| IDOR REST path automatique | Couvert pour les segments `path[index]` connus |
| Multi-tenant | Couvert lorsque tenant et propriétaire sont configurés |
| Rôle et scopes | Conservés dans la matrice ; oracle d'autorisation métier encore configurable uniquement par réponses |
| GraphQL/WebSocket | Non couvert |
| Enumeration d'identifiants | Non couverte ; aucune génération de liste d'IDs |

Faux positif possible si un `ActiveIDORSuccessMarker` trop générique est utilisé comme oracle. La comparaison JSON réduit ce risque en exigeant des champs métier correspondants. Faux négatif possible si les réponses métier changent naturellement, si un token dynamique n'est pas normalisé, ou si l'application renvoie le même contenu public pour toutes les ressources. Une identité ou une ressource mal configurée provoque plutôt `UNTESTABLE` qu'une conclusion silencieuse.

### 9.7 Exemple complet

Supposons :

- identité `alice`, ressource `/api/orders/100` ;
- identité `bob`, ressource `/api/orders/200` ;
- `GET` avec un corps JSON métier stable.

Le propriétaire reçoit le JSON de la commande 100. Bob reçoit le JSON de la commande 200. Le test envoie ensuite Bob sur `/api/orders/100`. Si le code et le corps normalisé correspondent exactement au contrôle Alice, le test est `CONFIRMED` et l'evidence conserve les identités, ressources et différences. Si Bob reçoit 403, tous les contrôles sont refusés et le test est `NOT_CONFIRMED`.

## 10. Open Redirect - `open-redirect`

### 10.1 Objectif

Le module vérifie la destination finale réellement atteinte après résolution de la chaîne. Il ne confirme pas une simple valeur affichée dans le HTML, une URL JavaScript ou une redirection interne normalisée vers le domaine légitime.

### 10.2 Points d'entrée et conditions

Le module exige :

- une méthode GET ;
- un paramètre dont le nom contient `next`, `url`, `redirect`, `return`, `continue`, `dest`, `destination` ou `callback`.

Les POST, form JSON, headers, cookies et redirections basées uniquement sur le body ne sont pas couverts par le module Active.

### 10.3 Requêtes et chaîne

Pour un paramètre :

1. baseline GET exécutée sans suivre la redirection automatiquement ;
2. probe avec `https://auditcore-open-redirect.example.com/` ;
3. chaque `Location` interne à l'origine est suivi manuellement ;
4. une destination externe différente de la cible est arrêtée et documentée ;
5. une destination externe correspondant à l'origine de contrôle marque `TargetMatched` ;
6. la chaîne complète est rejouée ;
7. la confirmation exige la même origine finale, le même indicateur et la même suite d'URLs.

Le nombre d'hops est limité par `ActiveMaxRedirects`, cinq par défaut. Le nombre maximal de requêtes est donc approximativement six pour la probe et six pour sa reproduction, plus une baseline : treize dans le cas le plus long, avant les budgets globaux.

### 10.4 Variantes observées

Le suivi différencie :

- redirection HTTP `Location` ;
- chaîne interne puis destination externe ;
- JavaScript `window.location`, `location.href` ou `location.replace` ;
- balise meta refresh ;
- URL simplement affichée dans le corps ;
- destination finale restant sur l'origine légitime ;
- boucle ou chaîne dépassant la limite.

Une redirection JavaScript ou meta refresh est classée `INCONCLUSIVE` lorsqu'elle atteint la destination contrôlée, car aucun navigateur n'est utilisé pour prouver l'exécution. Une URL seulement affichée devient `NOT_CONFIRMED`.

### 10.5 Performances, faux positifs, faux négatifs et limites

Le budget maximal de redirection est décrit en 10.3. Le suivi s'arrête dès que la destination finale est externe, qu'une boucle est détectée ou que la limite de hops est atteinte. La reproduction ne réutilise pas le browser : elle rejoue la chaîne HTTP manuellement.

Le mécanisme évite le faux positif d'une valeur seulement affichée, d'une destination externe non contrôlée ou d'une redirection JavaScript non exécutée. Un faux négatif reste possible pour des redirections déclenchées par du JavaScript complexe, une meta refresh non reconnue ou une logique nécessitant un navigateur. Les POST, headers, cookies et redirections après interaction ne sont pas couverts.

### 10.6 Exemple complet

Pour `GET /login?next=/home` :

1. baseline vers `/home` ;
2. probe `next=https://auditcore-open-redirect.example.com/` ;
3. réponse `302 Location: /continue` ;
4. `/continue` répond `302 Location: https://auditcore-open-redirect.example.com/` ;
5. l'origine finale correspond à l'origine externe de contrôle ;
6. la même chaîne est rejouée ;
7. résultat `CONFIRMED`, avec `FinalURL`, `FinalOrigin`, `RedirectChain` et `RedirectType` dans l'evidence.

Si la réponse HTML contient seulement `<script>window.location=...</script>`, le résultat est `INCONCLUSIVE`, pas confirmé.

## 11. Vulnérabilités non implémentées comme Active Modules

La présence d'un terme dans le modèle ou dans une description ne constitue pas une implémentation. L'inventaire du runner ne contient pas les modules suivants :

| Vulnérabilité demandée | État actuel | Conséquence |
|---|---|---|
| Stored XSS | Absente | aucun workflow écriture puis lecture |
| DOM XSS | Absente | aucun navigateur, source/sink JS ou instrumentation DOM |
| Command Injection | Absente | aucun payload shell ni preuve d'exécution |
| LFI/RFI | Absente comme module distinct | seulement des payloads traversal et noms `include`/`page` |
| XXE | Absente | aucun parseur XML ou document XML envoyé |
| SSTI | Absente | aucun moteur de template ni oracle d'évaluation |
| Template Injection | Absente | pas de stratégie dédiée |
| Prototype Pollution | Absente | pas de JSON prototype ou vérification d'objet côté client |
| HTTP Request Smuggling | Absente | pas de contrôle CL/TE, hop-by-hop ou connexions divergentes |
| Host Header Injection | Absente | aucun test Host/X-Forwarded-Host |
| CRLF Injection | Absente | aucune injection de séparation de headers |
| LDAP Injection | Absente | aucun oracle LDAP |
| NoSQL Injection | Absente | aucune variante Mongo/JSON opérateur |
| XML Injection | Absente | aucun contexte XML testé |
| XPath Injection | Absente | aucun oracle XPath |
| GraphQL injection/introspection abusive | Absente | le mot `/graphql` ne crée pas de module Active |
| WebSocket injection | Absente | aucune connexion WebSocket |
| CSRF active | Absente | le cookie SameSite est passif ; aucun workflow token/action |
| Brute force | Absente | aucune boucle d'authentification contrôlée |
| File upload | Absente | aucun multipart ni validation de fichier |

## 12. Modules passifs associés, hors Active Tests

Cette section est incluse pour éviter d'attribuer à la phase Active une capacité qui appartient à la phase passive.

### 12.1 Security headers

`headers-security` envoie une requête HEAD sur l'asset et fait un GET de fallback en cas d'échec. Il vérifie l'absence de CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy et Permissions-Policy. Il ignore les réponses dont le Content-Type ressemble à une image, une police, du CSS ou du JavaScript.

Chaque header absent génère un finding passif `missing-header`, `CONFIRMED` et confiance haute. Il n'y a ni payload, ni baseline Active, ni reproduction Active. La déduplication peut ensuite consolider la même faiblesse sur plusieurs endpoints, mais cela ne transforme pas la détection en Active Test.

### 12.2 CORS

`cors-misconfig` cible les URLs qui ressemblent à une racine, une API, `/v1`, `/v2` ou `/graphql`. Il envoie un GET avec `Origin: https://evil-cors-probe.example.com` et inspecte `Access-Control-Allow-Origin` et `Access-Control-Allow-Credentials`.

Il signale :

- wildcard `*` ;
- origine arbitraire reflétée ;
- origine reflétée avec credentials, plus sévère.

Il s'agit d'une observation passive active au sens HTTP, mais pas d'un `ActiveTest` spécialisé : aucune reproduction, comparaison différentielle ou lifecycle Active n'est produit.

### 12.3 Cookies

`cookies-security` fait un GET et inspecte les `Set-Cookie`. Il identifie heuristiquement les cookies dont le nom contient `session`, `sess`, `auth`, `token`, `jwt`, `phpsessid` ou `jsessionid`.

Il signale l'absence de `HttpOnly`, `Secure` ou `SameSite` explicite. Cette détection n'exécute pas de XSS, ne rejoue pas une session et ne prouve pas une exploitabilité métier.

### 12.4 Exposition sensible

`sensitive-exposure` cible principalement la racine GET :

`.env`, `.git/config`, `.svn/entries`, backups ZIP/SQL, fichiers PHP de configuration, `phpinfo.php`, `server-status`.

Il teste aussi l'asset pour une page de listing contenant `index of /` ou `parent directory`. Les preuves sont des marqueurs de contenu et des codes HTTP. Il ne s'agit pas d'un module Active paramétrique et aucun test LFI/RFI ou upload n'est déduit de sa présence.

## 13. Matrice de couverture et qualité actuelle

| Module | Preuve principale | Reproduction | Robustesse actuelle | Limite dominante |
|---|---|---|---|---|
| SQLi | signature SQL, différentiel vrai/faux ou statistiques temporelles | Oui, selon la famille | Bonne pour error/boolean et time-based MySQL-compatible | pas de union/OOB ni sélection de dialecte |
| Reflected XSS | contexte HTML actif et réflexion répétée | Oui, même contexte/encodage | Bonne pour HTML/attribut | pas de navigateur, DOM/stored/JS avancé absents |
| Traversal/LFI | marqueur spécifique hors contrôles | Oui, même payload | Bonne si ressource et plateforme sont configurées | découverte REST automatique et RFI absentes |
| SSRF | callback OOB ou marqueur direct | Polling callback, pas de seconde probe | Forte pour OOB contrôlé | callback hors budget et pas de reproduction séparée |
| IDOR | identité non autorisée + réponse métier équivalente | Non séparée | Forte avec deux identités et ressources connues | couverture métier et marker parfois permissifs |
| Open redirect | origine finale externe + chaîne répétée | Oui, chaîne complète | Bonne pour HTTP redirects | pas de navigateur JS, GET seulement |

## 14. Lecture d'un résultat complet

Pour comprendre un résultat dans l'interface, il faut suivre cette chaîne :

```text
Asset
  -> EntryPoint et ActiveTestPlan
  -> ActiveTest unique
  -> baseline
  -> probes et réponses
  -> comparaison propre au module
  -> reproduction éventuelle
  -> ActiveEvidence
  -> statut final du test
  -> Finding éventuel
  -> consolidation passive/active
  -> scoring et mapping OWASP/CWE/ASVS
  -> replay ultérieur et ReplayState
```

Les éléments les plus importants dans `ActiveEvidence` sont :

- `Baseline` : requête(s) et réponse(s) de référence ;
- `TestExchanges` : requêtes de payload et réponses ;
- `Differences` : différences code/hash/taille ou différences métier ;
- `Timing` : séries de durées, médianes, MAD, seuil adaptatif et compteurs de reproduction pour une validation time-based ;
- `ValidationRule` : règle annoncée par le module ;
- `Reproductions` : nombre d'échanges étiquetés reproduction ;
- `MinimumProofReached` : preuve minimale obtenue ;
- `Conclusion` : explication textuelle de la décision.

Le rapport final compte les findings, pas les tests inconclusifs sans finding. Pour analyser la couverture réelle, il faut donc consulter à la fois la page Findings et les statistiques Active (`generated_tests`, `finalized_tests`, `status_counts`, nombre de requêtes et réponses).

## 15. Améliorations futures prioritaires

Les améliorations suivantes découlent directement des limites observées, sans être déjà implémentées :

1. ajouter la sélection de contexte et de dialecte SQLi sans envoyer toutes les variantes à tous les paramètres ;
2. ajouter un navigateur contrôlé pour DOM XSS, JS string, meta refresh et XSS stockée ;
3. étendre la découverte automatique des paramètres de chemin REST et des champs multipart fichier ;
4. ajouter un module RFI séparé et enrichir les preuves LFI selon la plateforme et la ressource ;
5. ajouter une validation DNS avancée SSRF et des preuves de destination effective fournies par le collecteur ;
6. enrichir IDOR avec des règles métier explicites par rôle, scope, opération et schéma de réponse ;
7. ajouter des tests Active dédiés pour headers, CORS, cookies et exposition lorsqu'une revalidation active est souhaitée ;
8. ajouter les modules absents uniquement avec un oracle défensif explicite et une preuve minimale adaptée ;
9. conserver séparément la qualification historique du scan, l'état courant du replay et l'état de remédiation afin d'éviter toute ambiguïté dans GRC.

## 16. Références de code

- Contrat, executor, budgets, plans, normalisation et masquage : `internal/scanner/active/active.go`
- Navigateur headless isolé, allowlist, DOM et événements : `internal/scanner/browser/browser.go`
- Orchestration et lifecycle : `internal/scanner/engine/engine.go`
- Enregistrement des modules et profils : `internal/audit/runner.go`, `internal/httpx/httpx.go`
- Modèles Active et evidence : `internal/models/models.go`
- SQLi : `internal/scanner/modules/sqli/sqli.go`
- XSS réfléchie : `internal/scanner/modules/xss/xss.go`
- Traversal : `internal/scanner/modules/traversal/traversal.go`
- SSRF : `internal/scanner/modules/ssrf/ssrf.go`
- IDOR : `internal/scanner/modules/idor/idor.go`
- Open Redirect : `internal/scanner/modules/redirect/redirect.go`
- Matchers et chemin historique : `internal/scanner/matchers/matchers.go`
- Replay ultérieur : `internal/scanner/replay/replay.go`
- Tests de comportement : `internal/scanner/modules/*/*_test.go`, `internal/scanner/engine/*_test.go`, `internal/scanner/active/active_test.go`
