# Active tests - fonctionnement complet

> Document de reference de la refonte Active tests.
>
> Il couvre le travail realise depuis la mise en place de la tracabilite des
> tests actifs jusqu'a la validation specialisee des modules SQLi, XSS,
> Open Redirect, Path Traversal, SSRF et IDOR.

## 1. Objectif de la refonte

La premiere version du scanner raisonnait principalement ainsi :

1. trouver un parametre qui semble interessant ;
2. envoyer une valeur modifiee ;
3. regarder un code HTTP, une taille ou une signature simple ;
4. creer un finding.

Cette approche avait plusieurs limites importantes :

- un test pouvait etre affiche comme actif sans que sa requete ait ete
  envoyee ;
- l'interface ne distinguait pas toujours la file, l'execution, l'analyse et
  la conclusion ;
- un code `200`, `500` ou une difference de taille pouvait etre interprete
  comme une preuve ;
- les modules utilisaient surtout une logique commune et peu de regles
  propres au contexte de chaque vulnerabilite ;
- les profils de scan pouvaient etre selectionnes dans l'interface sans
  influencer suffisamment le moteur ;
- une confirmation n'etait pas toujours liee a une reproduction technique ;
- les requetes, tokens, cookies et en-tetes sensibles risquaient d'apparaitre
  dans les traces ;
- l'arret d'un audit ne se propageait pas correctement jusqu'aux requetes
  actives.

La refonte transforme Active tests en une chaine de validation explicite :

```text
profil de scan
    -> options fusionnees et normalisees
    -> modules actifs autorises
    -> plans par endpoint et point d'entree
    -> test actif avec ID unique
    -> requetes controlees et enregistrees
    -> baseline et comparaison normalisee
    -> regle de validation propre au module
    -> preuve minimale et reproduction
    -> statut final + evidence persistante
```

Le principe central est le suivant :

> Un finding suspect ne devient `CONFIRMED` que si le module a obtenu la
> preuve technique minimale qu'il a definie, et si cette preuve est exploitable
> dans `ActiveEvidence`.

---

## 2. Architecture generale

### 2.1 Les composants

| Composant | Responsabilite |
|---|---|
| `internal/audit/runner.go` | orchestre les phases, fusionne les options, enregistre les modules et gere l'arret |
| `internal/scanner/engine/engine.go` | cree les plans, met les tests en file, execute les modules et enregistre leurs conclusions |
| `internal/scanner/active/active.go` | fournit le contrat Active, l'execution HTTP, la baseline, les limites, la normalisation et le masquage |
| `internal/models/models.go` | definit `ActiveTest`, `ActiveTestPlan`, `ActiveTestResult`, `ActiveEvidence` et les statuts |
| `internal/storage/store.go` | persiste les tests, transitions, compteurs, preuves, findings et statistiques |
| `internal/api/handlers.go` | expose les tests, statistiques, resume, arret et donnees nettoyees |
| `internal/httpx/httpx.go` | applique les profils, le scope, les limites par defaut et l'authentification HTTP |
| `internal/scanner/modules/*` | applique la validation metier propre a chaque type de vulnerabilite |

### 2.2 Nouveau contrat des modules actifs

Chaque module actif suit le contrat :

```go
type Module interface {
    Name() string
    Plan(ctx *models.ModuleContext, findings []*models.Finding) []models.ActiveTestPlan
    RunActive(
        ctx context.Context,
        moduleCtx *models.ModuleContext,
        plan models.ActiveTestPlan,
        executor *active.Executor,
    ) *models.ActiveTestResult
}
```

Le module ne recoit donc plus seulement un client HTTP et un asset. Il recoit :

- le contexte d'annulation ;
- l'asset cible ;
- les options du profil de scan ;
- le point d'entree exact ;
- le finding passif source eventuel ;
- un executor instrumente ;
- une enveloppe de resultat structuree.

La methode historique `Run` reste presente dans plusieurs modules pour la
compatibilite, mais le chemin principal de l'audit utilise `Plan` puis
`RunActive` lorsqu'un module est enregistre comme module actif structure.

### 2.3 Pourquoi planifier par point d'entree

Un asset peut contenir plusieurs parametres :

```text
GET /search?id=42&q=phone&redirect=/home
```

Le moteur ne cree plus seulement un test abstrait `module x asset`. Il cree un
plan par point d'entree pertinent :

```text
asset        : /search?id=42&q=phone&redirect=/home
module       : sqli-detection
entry point  : id, location=query, original_value=42
source       : finding passif eventuel
```

Le plan conserve notamment :

- `Endpoint` ;
- `Method` ;
- `Name` ;
- `Location` : query, form, JSON, path, header ou cookie ;
- `OriginalValue` ;
- `BodyType` ;
- `SourceFindingID` ;
- la raison pour laquelle le point a ete retenu.

Cette association permet de repondre precisement a :

- quel endpoint a ete teste ;
- quel parametre a ete manipule ;
- quel module l'a manipule ;
- quel finding passif a donne naissance au test ;
- quelles requetes ont ete envoyees ;
- quelle preuve a ete obtenue pour ce point precis.

---

## 3. Profils de scan et propagation de configuration

### 3.1 Le profil est une source de verite

La configuration suit maintenant ce chemin :

```text
POST /api/audits
    -> CreateAuditRequest.Options
    -> Runner.CreateAndRun
    -> httpx.MergeOptions
    -> optionsForProfile
    -> options normalisees stockees dans AuditRun
    -> Runner et Engine
    -> modules actifs
```

`MergeOptions` applique dans l'ordre :

1. les valeurs par defaut liees a la cible ;
2. le preset du profil ;
3. les phases fournies par l'utilisateur ;
4. les modules passifs fournis par l'utilisateur ;
5. les modules actifs fournis par l'utilisateur ;
6. les limites et options personnalisees ;
7. les options propres aux modules : traversal, SSRF et IDOR ;
8. la normalisation finale.

Le profil selectionne n'est donc plus seulement un preset visuel. Il modifie
les phases, les modules effectivement enregistres, les limites et le
comportement du moteur.

### 3.2 Profils integres

| Profil | Phases | Modules actifs principaux | Valeurs generales |
|---|---|---|---|
| `full-scan` | pipeline complet | SQLi, XSS, traversal, SSRF, IDOR, open redirect | profondeur 3, jusqu'a 800 pages, 4 RPS |
| `quick-check` | pipeline complet avec exploration reduite | SQLi, XSS, traversal | profondeur 1, 50 pages, 6 RPS |
| `api-deep` | pipeline complet adapte API | SQLi, SSRF, IDOR, open redirect | profondeur 4, 300 pages, 3 RPS |
| `passive-only` | pas de phase active | aucun module actif | phases actives explicitement absentes |
| `custom` | selon les options | selon `active_modules` | valeurs personnalisees |

Les noms courts sont canonicalises :

```text
sqli       -> sqli-detection
xss        -> xss-reflected
traversal  -> path-traversal
ssrf       -> ssrf-basic
idor       -> idor-simple
redirect   -> open-redirect
```

### 3.3 Verification au niveau du runner

Avant d'executer la phase active, le runner verifie :

- si `PhaseActive` est dans `enabled_phases` ;
- si au moins un module actif est autorise ;
- si des assets sont disponibles ;
- si la phase n'a pas ete annulee.

Si la phase ou les modules ne sont pas autorises, un evenement
`profile-skip` est genere. La timeline ne doit donc pas presenter un pipeline
actif complet lorsqu'un profil `passive-only` a ete choisi.

---

## 4. Tracabilite complete d'un test actif

### 4.1 ID unique par test

Chaque plan genere un `ActiveTest` avec un UUID distinct. L'objet conserve :

- `ID` du test actif ;
- `AuditRunID` ;
- `AssetID` ;
- nom du module ;
- methode HTTP ;
- URL ;
- point d'entree ;
- `SourceFindingID` ;
- contexte d'authentification nominal ;
- statut courant ;
- etapes horodatees ;
- compteurs de requetes et reponses ;
- findings lies ;
- limites atteintes ;
- preuve ;
- date de creation, debut, fin et duree.

Un test actif est donc une unite observable, et non plus une simple ligne de
log issue d'un module.

### 4.2 Cycle de vie

Le cycle normal est :

```text
QUEUED
  -> STARTED
  -> BASELINE_REQUEST_SENT
  -> BASELINE_RESPONSE_RECEIVED
  -> TEST_REQUEST_SENT
  -> TEST_RESPONSE_RECEIVED
  -> COMPARING
  -> VALIDATING
  -> REPRODUCING (si necessaire)
  -> ANALYZING
  -> statut final
```

Des transitions generiques existent aussi pour les modules ou les erreurs :

| Etape | Signification |
|---|---|
| `QUEUED` | plan cree et place dans la file |
| `STARTED` | execution du module commencee |
| `REQUEST_SENT` | trace generique d'une requete envoyee |
| `RESPONSE_RECEIVED` | trace generique d'une reponse recue |
| `BASELINE_REQUEST_SENT` | requete de reference envoyee |
| `BASELINE_RESPONSE_RECEIVED` | reponse de reference recue |
| `TEST_REQUEST_SENT` | probe du module envoyee |
| `TEST_RESPONSE_RECEIVED` | reponse de probe recue |
| `COMPARING` | comparaison avec la reference ou un controle |
| `VALIDATING` | regle de conclusion appliquee |
| `REPRODUCING` | preuve candidate rejouee |
| `ANALYZING` | resultat structure persiste et finalise |

Chaque transition contient :

- le statut ;
- un message lisible ;
- un timestamp.

La timeline peut donc distinguer un test en attente, un test qui n'a jamais
emis de requete, un test qui attend une reponse et un test deja conclu.

### 4.3 Compteurs et statistiques

Le stockage maintient :

- nombre total de tests ;
- tests en file ;
- tests en cours ;
- requetes envoyees ;
- reponses recues ;
- tests demarres ;
- tests analyses ;
- tests sans requete ;
- tests sans reponse ;
- tests finalises ;
- repartition par statut final ;
- repartition par module ;
- progression `finalized / total`.

Le resume de phase ajoute :

- duree totale ;
- duree moyenne ;
- nombre de tests generes ;
- nombre de tests finalises ;
- compteurs par statut ;
- compteurs par module ;
- erreurs principales ;
- tests non finalises recuperes.

### 4.4 API de suivi

Les routes sont enregistrees dans `internal/api/router.go` :

```text
GET  /api/audits/{id}/active-tests
GET  /api/audits/{id}/active-stats
GET  /api/audits/{id}/active-summary
POST /api/audits/{id}/stop
```

`active-tests` accepte notamment :

```text
?status=CONFIRMED
?module=sqli-detection
?q=search
```

Le flux d'evenements general reste disponible via :

```text
GET /api/audits/{id}/events
```

Les evenements `active-trace`, `active-summary` et `profile-skip` permettent
de relier la timeline generale aux objets ActiveTest.

---

## 5. Statuts finaux et invariants

| Statut | Sens exact |
|---|---|
| `CONFIRMED` | preuve technique minimale obtenue et conclusion validee |
| `NOT_CONFIRMED` | requetes envoyees et analysees, mais aucune preuve suffisante |
| `INCONCLUSIVE` | comportement suspect, ambigu, instable ou limite atteinte |
| `UNTESTABLE` | configuration, point d'entree ou prerequis insuffisant |
| `FAILED` | erreur technique hors simple limite ou annulation |
| `TIMEOUT` | timeout du test ou de la phase |
| `CANCELLED` | execution interrompue par l'utilisateur ou le contexte |
| `FALSE_POSITIVE` | statut disponible pour une qualification ulterieure |
| `SKIPPED` | test volontairement ignore |

Le moteur applique des invariants apres le retour du module :

1. `NOT_CONFIRMED` avec zero requete devient `UNTESTABLE` ;
2. un statut qui attend une analyse mais ne contient aucune reponse devient
   `INCONCLUSIVE` ;
3. `CONFIRMED` sans `Evidence` structuree devient `INCONCLUSIVE` ;
4. `CONFIRMED` sans `MinimumProofReached` devient `INCONCLUSIVE` ;
5. le nombre de findings ne suffit jamais a calculer le statut ;
6. le moteur conserve la conclusion explicite du module.

Cette derniere regle est importante : un module peut avoir observe un
comportement interessant mais conclure `INCONCLUSIVE`. Le finding ne doit pas
forcer artificiellement `CONFIRMED`.

---

## 6. Execution HTTP commune

### 6.1 `active.Executor`

`active.Executor` enveloppe le client HTTP existant sans remplacer la logique
de payload des modules. Il ajoute :

- le lien avec `context.Context` ;
- la verification d'annulation avant et pendant l'echange ;
- le comptage des requetes et reponses ;
- l'enregistrement de chaque echange ;
- la baseline ;
- les labels metier de requete ;
- les limites ;
- la comparaison ;
- les transitions de statut ;
- l'arret apres preuve minimale.

Les modules utilisent principalement :

```text
Do(kind, label, request)
DoNoRedirect(kind, label, request)
DoBaseline(request)
Step(status, message)
CompareExchange(exchange)
MarkMinimumProof()
```

### 6.2 Requetes de reference

Une baseline correspond au comportement normal du point d'entree avec sa
valeur originale. Elle sert a savoir si une reponse de probe est differente
du fonctionnement normal.

Selon le module, la reference peut etre :

- une baseline HTTP classique ;
- deux baselines identiques pour tester la stabilite ;
- la reponse metier de l'identite proprietaire ;
- un chemin normal et un chemin invalide ;
- une chaine HTTP de reference.

Une baseline instable ne doit pas etre utilisee comme preuve forte. Par
exemple, SQLi etablit deux references afin de detecter une page dynamique
avant d'interpreter une variation.

### 6.3 Enregistrement d'un echange

Chaque `HTTPExchange` conserve :

- `Kind` : baseline ou test ;
- `Label` : par exemple `boolean-true`, `xss-reproduction` ou
  `idor-cross-non-owner-on-owner` ;
- requete : methode, URL, headers nettoyes, corps nettoye ;
- reponse : code, headers nettoyes, apercu, taille, duree, hash normalise ;
- erreur technique eventuelle ;
- timestamps de debut et de fin.

Les labels rendent la preuve lisible sans avoir a deviner quelle requete a
produit un resultat.

### 6.4 Construction des requetes

`BuildRequest` prend en charge les principaux emplacements :

- query string pour les requetes GET ;
- formulaire `application/x-www-form-urlencoded` ;
- corps JSON ;
- methode et endpoint de l'asset ;
- headers de l'asset ;
- valeur originale du point d'entree.

Les modules qui ont besoin d'une construction particuliere utilisent leur
propre constructeur, mais restent executes par le meme executor et soumis aux
memes limites.

### 6.5 Redirections

`Do` utilise les regles de redirection du client instrumente, avec une limite
`ActiveMaxRedirects`.

`DoNoRedirect` desactive le suivi automatique de `net/http`. Il est utilise
quand le module doit observer un `Location` ou eviter de confondre une
redirection cote client avec une requete emise par le serveur cible.

### 6.6 Comparaison normalisee

Le moteur compare principalement :

- code HTTP ;
- hash du corps normalise ;
- taille brute du corps.

La taille seule n'est jamais significative par defaut. Le corps est normalise
pour retirer ou remplacer des valeurs frequemment dynamiques :

- dates ;
- UUID ;
- nonce, token, request ID et trace ID ;
- session ID et cookies de session.

La comparaison normalisee reduit les faux positifs dus a une page dynamique.
Chaque module peut ajouter une comparaison plus specifique : signature SQL,
contexte HTML, marqueur de fichier, origine finale, preuve OOB ou reponse
metier.

### 6.7 Limites

Les valeurs par defaut normalisees sont :

| Limite | Valeur par defaut | Role |
|---|---:|---|
| timeout d'un test actif | 60 s | evite qu'un test bloque toute la phase |
| timeout de phase active | 900 s | borne l'ensemble de la phase |
| requetes par test | 32 | borne les payloads et reproductions |
| requetes par endpoint | 128 | borne la pression sur un endpoint |
| requetes par module | 512 | borne la pression globale d'un module |
| repetitions | 3 | evite les boucles de reproduction infinies |
| redirections | 5 | borne les chaines HTTP |
| taille de reponse | 256 KiB | limite la memoire et les preuves |
| rate limit | 4 RPS | cadence generale par client |

Un budget partage compte les requetes par endpoint et par module. Une limite
atteinte produit generalement `INCONCLUSIVE`, car l'absence de preuve ne
signifie pas que la vulnerabilite est absente.

### 6.8 Masquage des secrets

Le transport masque les secrets dans les traces :

- `Authorization` et Bearer tokens ;
- proxy authorization ;
- cookies et Set-Cookie ;
- mots de passe ;
- secrets ;
- API keys ;
- tokens CSRF ;
- identifiants de session ;
- en-tetes declares sensibles dans la configuration.

Les URLs sont aussi nettoyees par nom de parametre sensible. Les findings
sont nettoyes avant persistence.

Les identites IDOR ne sont pas renvoyees avec leurs tokens, passwords,
headers ou cookies par les endpoints d'audit. La liste des audits et le detail
d'un audit utilisent la meme version publique nettoyee.

---

## 7. Arret et annulation

L'audit est demarre avec un `context.WithCancel`. Le runner conserve le
cancel function par `auditID`.

La commande HTTP d'arret est :

```bash
curl -X POST http://localhost:8081/api/audits/<AUDIT_ID>/stop
```

Le comportement est :

1. l'API appelle `Runner.Stop` ;
2. le runner annule le contexte de l'audit ;
3. le contexte de phase active est derive du contexte d'audit ;
4. l'executor transmet le contexte a chaque requete ;
5. le transport interrompt l'echange en cours ;
6. le runner marque les tests non finalises `CANCELLED` et l'audit `STOPPED`.

Un bouton d'interface n'est donc qu'un client de cette route. La source de
verite de l'arret est le contexte et non l'etat visuel du bouton.

---

## 8. Validation SQL Injection

Module : `sqli-detection`

### 8.1 Point d'entree

Le module planifie les parametres disponibles dans la query, les formulaires
ou le JSON selon l'asset. Il ne declare pas une SQLi parce que le parametre
s'appelle `id` ou parce qu'il contient la valeur `1`.

### 8.2 Stabilite initiale

Le module envoie la requete normale au moins une fois et, lorsque le budget le
permet, une seconde fois avec la meme valeur originale.

Cette etape permet de verifier que :

- le endpoint repond normalement ;
- la baseline n'est pas deja une erreur serveur ;
- le contenu normalise est suffisamment stable ;
- une variation candidate ne vient pas seulement du timestamp, d'un nonce ou
  d'un contenu aleatoire.

Une baseline HTTP 500 generique est `INCONCLUSIVE`, pas `CONFIRMED` : le
module ne peut pas prouver que l'erreur vient du moteur SQL.

### 8.3 Validation error-based

Le module utilise plusieurs familles de probes, notamment :

- quote simple et double quote ;
- conditions booleennes SQL ;
- variantes avec commentaire ;
- variantes de parenthesage ;
- une variante de temporisation pour observer une eventualite, mais un
  ralentissement seul ne suffit jamais a confirmer.

La reponse n'est acceptee que si elle contient une signature SQL specifique
appartenant a une liste connue, par exemple :

- `you have an error in your sql syntax` ;
- `warning: mysql_` ;
- `sqlstate[` ;
- `syntax error at or near` ;
- `unterminated quoted string` ;
- `unclosed quotation mark` ;
- `sqlite error` ;
- `ora-01756` ou `ora-00933` ;
- erreurs PostgreSQL explicites.

Une page d'erreur applicative generique, meme en HTTP 500, n'est pas une
signature SQL.

Lorsqu'une signature SQL apparait :

1. elle doit etre absente de la baseline ;
2. la meme payload est renvoyee ;
3. la meme signature doit reapparaitre ;
4. seulement ensuite le finding error-based est confirme.

### 8.4 Validation boolean-based

Le module teste des paires conditionnelles vrai/faux, par exemple :

```text
true  : ' AND '1'='1
false : ' AND '1'='2

true  : 1 AND 1=1
false : 1 AND 1=2
```

Une paire est candidate si :

- la condition vraie ressemble a la baseline ;
- la condition fausse produit une reponse normalisee differente ;
- les deux reponses ne sont pas identiques entre elles.

La paire est ensuite rejouee integralement :

```text
baseline
true
false
true reproduction
false reproduction
```

La confirmation exige que le meme comportement reapparaisse pendant la
reproduction. Cela distingue une vraie decision conditionnelle d'une page
dynamique ou d'une variation aleatoire.

### 8.5 Conclusions SQLi

| Observation | Conclusion |
|---|---|
| signature SQL specifique, absente de baseline et reproduite | `CONFIRMED` |
| vrai/faux differentiels et reproduits | `CONFIRMED` |
| difference booleenne une seule fois | `INCONCLUSIVE` |
| HTTP 500 generique | `INCONCLUSIVE` |
| ralentissement isole | pas de confirmation |
| page dynamique sans logique vrai/faux stable | `NOT_CONFIRMED` ou `INCONCLUSIVE` selon le cas |
| aucune difference apres probes | `NOT_CONFIRMED` |

`MarkMinimumProof()` est appele des que la signature error-based ou la paire
boolean-based reproduite constitue la preuve minimale.

---

## 9. Validation XSS reflechie

Module : `xss-reflected`

### 9.1 Filtrage du contexte

Si le fingerprint indique une API pure, le module ne lance pas les tests XSS
HTML et ne cree pas de plan. Une reponse JSON n'est pas automatiquement une
XSS navigateur.

### 9.2 Payloads et reflexion

Le module teste plusieurs formes de payloads :

- balise `script` ;
- sortie d'attribut avec quote double ;
- sortie d'attribut avec quote simple ;
- balise image avec `onerror` ;
- scheme `javascript:` ;
- SVG avec `onload`.

Pour chaque reponse, il recherche la valeur brute puis plusieurs formes
encodees :

- echappement HTML ;
- quote JSON ;
- JSON echappe pour HTML ;
- URL query encodee ;
- URL path encodee.

La presence de la chaine dans la reponse ne suffit donc pas.

### 9.3 Contextes detectes

Le parseur distingue notamment :

| Contexte | Interpretation |
|---|---|
| `html-text` | valeur dans le texte d'un document HTML |
| `attribute` | valeur dans un attribut HTML |
| `javascript` | valeur dans un bloc `<script>` |
| `css` | valeur dans un bloc `<style>` |
| `json` | valeur dans une structure JSON ou une reponse JSON |

Le module conserve aussi l'emplacement, par exemple texte HTML, attribut
`href`, bloc script ou valeur JSON.

### 9.4 Contexte executable

Une reflexion brute est candidate seulement si le DOM produit par la reponse
contient un element actif issu du payload. Le parseur HTML recherche notamment :

- un element `script` cree par le payload ;
- un attribut evenementiel `onerror`, `onload` ou autre attribut `on*` ;
- un lien `javascript:`.

Le module compare aussi le nombre de constructions actives avec une version du
corps dans laquelle le payload est retire. Cela evite de compter un element
actif deja present dans la page.

### 9.5 Regles de conclusion

- valeur correctement HTML encodee : `NOT_CONFIRMED` ;
- valeur JSON correctement representee : `NOT_CONFIRMED` ;
- valeur URL encodee : `NOT_CONFIRMED` ;
- chaine brute simplement affichee dans le texte : `NOT_CONFIRMED` ;
- payload brut dans un contexte script ou CSS sans preuve de sortie de chaine :
  `INCONCLUSIVE` ;
- construction HTML active creee par l'entree puis reproduite : `CONFIRMED` ;
- contexte dynamique ou limite atteinte : `INCONCLUSIVE`.

Pour confirmer, le module rejoue le meme payload et exige :

- meme contexte ;
- meme emplacement ;
- meme encodage ;
- meme caractere executable.

Le module ne declare donc pas une XSS uniquement parce que la chaine
`<script>alert(1)</script>` est visible dans la page.

---

## 10. Validation Open Redirect

Module : `open-redirect`

### 10.1 Cible de controle

Le module utilise une origine externe de controle dediee :

```text
https://auditcore-open-redirect.example.com/
```

Cette URL sert a reconnaitre une destination externe. Le scanner ne doit pas
avoir besoin de l'ouvrir pour analyser la redirection.

### 10.2 Capture sans suivi automatique

Le module :

1. envoie la requete de reference sans suivre les redirections ;
2. injecte l'origine de controle dans le parametre GET ;
3. capture le premier `Location` ;
4. resout les destinations relatives ;
5. suit manuellement les hops qui restent sur l'origine de la cible ;
6. arrete la chaine avant d'envoyer une requete vers l'origine externe ;
7. conserve l'URL finale, l'origine finale et la chaine complete.

Cette strategie evite deux erreurs :

- prendre une valeur `Location` affichee comme une preuve de destination
  atteinte ;
- faire sortir le scanner de la cible simplement pour verifier un open
  redirect.

### 10.3 Cas distingues

| Observation | Conclusion |
|---|---|
| redirection HTTP externe vers l'origine de controle | candidate a confirmation |
| chaine de plusieurs hops qui finit sur l'origine externe | candidate a confirmation |
| redirection interne vers une ressource legitime | `NOT_CONFIRMED` |
| normalisation vers le domaine legitime | `NOT_CONFIRMED` |
| URL seulement affichee dans le corps | `NOT_CONFIRMED` |
| JavaScript `window.location` | `INCONCLUSIVE`, car aucun navigateur n'est execute |
| `meta refresh` | `INCONCLUSIVE` si la destination externe est detectee |

Une chaine HTTP externe doit etre rejouee exactement. La confirmation exige
la meme origine finale, le meme resultat et la meme longueur de chaine.

### 10.4 Preuve conservee

`ActiveEvidence` contient :

- `FinalURL` ;
- `FinalOrigin` ;
- `RedirectType` ;
- `RedirectChain` ;
- les echanges de chaque hop ;
- la conclusion et la regle de validation.

---

## 11. Validation Path Traversal

Module : `path-traversal`

### 11.1 Objectif

Le module ne confirme pas un traversal parce que la taille de la page a change
ou parce que la reponse est `200`. Il cherche une ressource de preuve
specifique qui ne doit pas etre presente dans les controles.

### 11.2 Sequences de controle

Le module execute :

1. un chemin normal avec la valeur originale ;
2. un chemin invalide controle ;
3. des payloads de traversal ;
4. une reproduction du payload candidat.

Le chemin invalide sert a distinguer une reponse generique du serveur d'une
lecture effective d'une ressource.

### 11.3 Payloads

Les familles couvertes sont :

- traversal Unix direct : `../../../etc/passwd` ;
- profondeurs Unix supplementaires ;
- slash encode `/` ;
- double encodage ;
- traversal Windows vers `win.ini` ;
- backslash encode ;
- variante legacy avec null byte.

### 11.4 Marqueur de preuve

Le marqueur par defaut est :

```text
root:x:0:0
```

Un environnement de test peut fournir :

```text
active_traversal_proof_path
active_traversal_proof_marker
```

Le chemin de preuve personnalise evite de dependre d'un fichier systeme reel
dans un laboratoire. Le marqueur doit etre suffisamment specifique pour
identifier la ressource attendue.

### 11.5 Regles de confirmation

Le marqueur doit :

- etre absent du chemin normal ;
- etre absent du chemin invalide ;
- apparaitre dans la reponse traversal ;
- reapparaitre dans la reproduction ;
- ne pas provenir d'une reponse HTTP 500.

Ainsi :

- `200` seul : pas une preuve ;
- difference de taille seule : pas une preuve ;
- page d'erreur : pas une preuve ;
- marqueur present dans la baseline : `INCONCLUSIVE` ;
- marqueur non reproductible : `INCONCLUSIVE` ;
- marqueur specifique absent des controles et present deux fois : `CONFIRMED`.

`MarkMinimumProof()` est appele juste apres la reproduction du marqueur.

---

## 12. Validation SSRF

Module : `ssrf-basic`

### 12.1 Pourquoi un callback hors bande

Une application peut :

- accepter une URL sans l'utiliser ;
- afficher l'URL dans une page ;
- la rediriger vers le navigateur ;
- la stocker pour un traitement ulterieur ;
- emettre une vraie requete cote serveur.

Seule la derniere situation est une preuve directe de SSRF. Le module utilise
donc un callback controle par l'operateur et un token different pour chaque
test.

### 12.2 Configuration

Les options sont :

```text
active_ssrf_callback_url
active_ssrf_callback_check_url
active_ssrf_callback_marker
active_ssrf_allow_private_callback
```

Les URLs peuvent contenir :

```text
{token}
```

Sinon le module ajoute le parametre `auditcore_token`.

Le callback de verification doit pouvoir indiquer que le token a ete recu,
par exemple :

```json
{"observed": true, "token": "<token-du-test>"}
```

Un JSON `observed:false` qui reflete simplement le token n'est pas accepte.
Un token correspondant a un autre test n'est pas accepte non plus.

### 12.3 Sequence d'execution

Pour un parametre URL pertinent :

1. verifier que le callback et le check URL sont presents ;
2. generer un UUID unique ;
3. construire les deux URLs avec ce token ;
4. verifier que les URLs sont HTTP(S) et dans le perimetre autorise ;
5. envoyer la requete normale ;
6. injecter l'URL callback dans le parametre ;
7. envoyer la requete de probe sans suivre les redirections de la cible ;
8. interroger le check endpoint jusqu'a trois fois ;
9. accepter seulement le token observe ou un marqueur direct configure.

Les requetes de verification du callback sont limitees et liees au contexte
du test. Le scanner ne suit pas un callback vers une autre destination.

### 12.4 Protection du perimetre

Les anciennes cibles automatiques metadata, loopback et services internes ne
sont plus utilisees par le chemin actif. `ssrfTargets` est vide.

Par defaut, les callbacks vers les destinations suivantes sont refuses :

- `localhost` ;
- domaines `.local` et `.internal` ;
- loopback ;
- adresses privees ;
- adresses link-local.

`active_ssrf_allow_private_callback` permet uniquement un laboratoire local
explicitement configure. Cette option ne doit pas etre activee pour une cible
non maitrisee.

### 12.5 Conclusions SSRF

| Observation | Conclusion |
|---|---|
| callback reel avec token correspondant | `CONFIRMED` |
| marqueur direct configure et retrouve dans la reponse cible | `CONFIRMED` |
| URL acceptee syntaxiquement | `INCONCLUSIVE` |
| URL affichee | `INCONCLUSIVE` |
| redirection HTTP de la cible vers le callback | `INCONCLUSIVE` |
| redirection JavaScript | `INCONCLUSIVE` |
| callback absent ou hors scope | `UNTESTABLE` |
| erreur de transport | `FAILED` |
| contexte annule ou expire | `CANCELLED` ou `TIMEOUT` |

La preuve conserve le token, les URLs callback, l'observation, le corps de
preuve nettoye, les echanges et la regle de validation. `MarkMinimumProof()`
est appele immediatement apres l'observation du callback ou du marqueur.

---

## 13. Validation IDOR

Module : `idor-simple`

### 13.1 Pourquoi l'IDOR est special

Une SQLi ou une XSS peut souvent etre validee par le comportement d'un seul
endpoint. Un IDOR necessite de connaitre la relation entre :

- l'identite connectee ;
- le proprietaire reel de la ressource ;
- l'identite qui demande la ressource ;
- la reponse metier attendue ;
- l'operation de lecture ou de modification.

Le module refuse donc de transformer automatiquement une substitution d'ID en
finding.

### 13.2 Configuration des identites

Les options IDOR sont :

```text
active_idor_identities
active_idor_owner_identity
active_idor_non_owner_identity
active_idor_owner_resource
active_idor_non_owner_resource
active_idor_success_marker
active_idor_denied_marker
active_idor_allow_write
```

Chaque identite peut fournir :

- headers ;
- cookies ;
- Bearer token ;
- Basic username/password.

Les identites sont appliquees par requete. L'authentification globale de
l'audit est neutralisee pour ces requetes afin que la session proprietaire ne
soit pas reutilisee accidentellement par le test non-proprietaire.

### 13.3 Verification de la configuration

Avant toute requete, le module exige :

- un point d'entree ;
- deux identites distinctes ;
- les deux identites presentes dans la liste configuree ;
- deux URLs de ressources distinctes ;
- des URLs HTTP(S) valides ;
- des ressources sur le meme host que l'asset ;
- le respect de `AllowedHosts` si cette option est configuree.

Si un de ces prerequis manque, le resultat est `UNTESTABLE` et aucune probe
n'est envoyee.

### 13.4 Controle des ressources

Le module execute d'abord deux controles de fonctionnement :

```text
owner identity     -> owner resource
non-owner identity -> non-owner resource
```

Ces controles prouvent minimalement que :

- la session proprietaire est valide ;
- la ressource proprietaire est exploitable ;
- la session non-proprietaire est valide ;
- la seconde ressource existe et peut servir de comparaison.

Si l'un des controles ne renvoie pas une reponse metier identifiable, le
module retourne `INCONCLUSIVE` plutot que de supposer que la session est
correcte.

### 13.5 Controle croise

Pour une lecture, le module execute :

```text
non-owner identity -> owner resource
owner identity     -> non-owner resource
```

Pour une modification, il effectue le controle principal non-owner vers la
ressource owner, mais seulement si `active_idor_allow_write=true`.

Le module s'arrete apres la premiere preuve croisee suffisante et appelle
`MarkMinimumProof()`.

### 13.6 Comprehension de la reponse metier

Un code `200` n'est pas considere comme une reponse metier suffisante par lui
seul.

Deux modes sont disponibles :

1. `active_idor_success_marker` est configure et doit apparaitre dans la
   reponse ;
2. le module exige une reponse 2xx non vide, non generique, puis compare :
   - code HTTP ;
   - hash du corps normalise ;
   - taille ;
   - contenu metier.

Les reponses trop generiques comme `ok`, `success`, `true`, `accepted` ou
`authorized` ne constituent pas une preuve metier autonome.

Un acces croise est confirme si la reponse est equivalente a celle du
controle proprietaire, ou si le marqueur de succes est retrouve. La preuve
conserve les identites nominales, les ressources nettoyees, l'operation, les
echanges et les differences.

### 13.7 Refus et ambiguite

Les reponses suivantes peuvent valider un refus :

- `401` ;
- `403` ;
- `404` ;
- `405` ;
- `active_idor_denied_marker`.

Si tous les acces croises sont refuses : `NOT_CONFIRMED`.

Si la reponse est differente mais ne permet pas de savoir s'il s'agit d'un
refus, d'une page publique, d'un filtrage ou d'une logique metier normale :
`INCONCLUSIVE`.

### 13.8 Lecture versus modification

Les methodes suivantes sont considerees comme potentiellement mutantes :

```text
POST, PUT, PATCH, DELETE
```

Elles sont `UNTESTABLE` par defaut. Cela evite qu'un audit de validation de
lecture modifie une commande, un profil, un document ou une ressource reelle.

Le passage a `active_idor_allow_write=true` est un choix explicite de
l'operateur et doit etre reserve a des ressources de laboratoire ou a un
environnement de recette.

---

## 14. `ActiveEvidence` : contenu de la preuve

Chaque module construit une preuve adaptee mais reutilise la meme enveloppe.

Champs communs :

| Champ | Role |
|---|---|
| `Expected` | comportement attendu avant la probe |
| `Observed` | comportement effectivement observe |
| `Baseline` | echanges de reference et stabilite |
| `TestExchanges` | requetes de test et reproductions |
| `Differences` | differences code, hash, taille ou metier |
| `ValidationRule` | regle qui a determine le statut |
| `Confidence` | confiance associee au statut |
| `Reproductions` | nombre de reproductions identifiables |
| `MinimumProofReached` | preuve minimale atteinte ou non |
| `Conclusion` | conclusion lisible du module |

Champs specialises :

- Open Redirect : URL finale, origine finale, type et chaine de redirection ;
- SSRF : token, callback URL, check URL, observation, preuve et erreur de
  verification ;
- IDOR : operation, identite owner, identite non-owner, ressources owner et
  non-owner ;
- XSS : contexte, emplacement et encodage dans `Observed` ;
- XSS JavaScript avec navigateur : `Browser` contient le marqueur DOM, le DOM
  borne, l'URL finale, les navigations, les événements, les blocages et les
  reproductions ;
- traversal : marqueur et sequence normal/invalide/traversal dans
  `ValidationRule` et `Expected`.

Une preuve n'est pas seulement un texte de finding. Elle est composee des
requetes, des reponses, des comparaisons et de la regle qui relie ces elements
a la conclusion.

---

## 15. Exemple de configuration active

Exemple conceptuel pour un laboratoire autorise :

```json
{
  "scan_profile": "custom",
  "enabled_phases": ["pre-check", "recon", "crawl", "passive", "active", "scoring", "report"],
  "active_modules": [
    "sqli-detection",
    "xss-reflected",
    "path-traversal",
    "ssrf-basic",
    "idor-simple",
    "open-redirect"
  ],
  "active_max_requests_per_test": 32,
  "active_max_repetitions": 3,
  "active_max_redirects": 5,
  "active_browser_enabled": true,
  "active_browser_timeout_seconds": 10,
  "active_traversal_proof_path": "/audit-fixture.txt",
  "active_traversal_proof_marker": "AUDITCORE-FIXTURE-MARKER",
  "active_ssrf_callback_url": "https://callback.example.test/hit?token={token}",
  "active_ssrf_callback_check_url": "https://callback.example.test/check?token={token}",
  "active_idor_identities": [
    {
      "name": "owner",
      "bearer_token": "<secret-owner-token>"
    },
    {
      "name": "non-owner",
      "bearer_token": "<secret-non-owner-token>"
    }
  ],
  "active_idor_owner_identity": "owner",
  "active_idor_non_owner_identity": "non-owner",
  "active_idor_owner_resource": "https://target.example.test/api/orders/1001",
  "active_idor_non_owner_resource": "https://target.example.test/api/orders/1002",
  "active_idor_success_marker": "order_id",
  "active_idor_denied_marker": "not authorized",
  "active_idor_allow_write": false
}
```

Les tokens de cet exemple sont des placeholders. Ils ne doivent pas etre
commit dans le depot ni apparaitre dans les logs.

---

## 16. Tests de non-regression

Les tests ajoutes couvrent notamment :

| Module | Scenarios verifies |
|---|---|
| architecture active | plan, execution, trace, statut final et preuve minimale |
| SQLi | endpoint vulnerable, endpoint corrige, dynamique, lent, erreur 500, timeout |
| XSS | HTML actif, attribut, HTML echappe, JavaScript ambigu, JSON, URL encodee, preuve navigateur et masquage DOM |
| Open Redirect | externe HTTP, interne, multi-hop, destination affichee, JavaScript, normalisation |
| Path Traversal | marqueur specifique, HTTP 200 generique, marqueur deja present, non-reproductibilite, marqueur configure |
| SSRF | callback reel, URL affichee, redirection HTTP, redirection client, marqueur direct, absence de configuration, callback prive, token incorrect |
| IDOR | absence d'identites, hors scope, acces croise, refus, 200 generique, reponse ambigue, lecture/ecriture |
| API | masquage des credentials dans detail et liste d'audits |
| HTTPX | propagation du profil, configuration IDOR et override d'authentification |

La verification globale utilise :

```bash
go test ./...
```

---

## 17. Limites connues et interpretation des resultats

La refonte privilegie la fiabilite de la preuve, mais certains cas restent
volontairement limites :

- XSS DOM ou JavaScript nécessitant une exécution navigateur :
  `INCONCLUSIVE` si le navigateur est désactivé ou indisponible ; le contexte
  JavaScript GET query/path peut désormais être confirmé avec `Browser` ;
- redirection JavaScript ou `meta refresh` : observation statique seulement ;
- SSRF : un collecteur callback externe doit etre fourni par l'operateur ;
- IDOR : le scanner ne peut pas deviner de maniere fiable qui est
  proprietaire d'une ressource sans configuration d'identites et de ressources ;
- endpoint tres dynamique : l'absence de stabilite peut conduire a
  `INCONCLUSIVE` plutot qu'a un faux `CONFIRMED` ;
- limites atteintes : le test est incomplet et ne doit pas etre interprete
  comme un resultat negatif ;
- une erreur de connectivite est une erreur technique, pas une vulnerabilite.

La bonne lecture des statuts est donc :

```text
NOT_CONFIRMED = les controles ont ete executes et aucune preuve n'a ete trouvee
INCONCLUSIVE  = quelque chose est suspect, mais la preuve est insuffisante
UNTESTABLE    = les prerequis manquent ou le test est interdit par configuration
CONFIRMED     = la preuve minimale est presente et reproductible
```

Cette distinction est la finalite principale de la refonte Active tests.
