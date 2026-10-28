# Active tests

Ce document explique simplement comment fonctionne la partie **Active tests** de l'outil.

## Idee generale

Les active tests sont les tests offensifs controles du scanner.

Contrairement aux tests passifs, ils peuvent envoyer des requetes modifiees vers la cible pour essayer de confirmer une faiblesse : SQL injection, XSS, path traversal, SSRF, IDOR, open redirect, etc.

Le but n'est pas seulement de dire "il y a peut-etre une faille", mais de tenter une validation technique et de classer le resultat.

## Quand la phase active se lance

La phase active est lancee par le runner dans `internal/audit/runner.go`.

Elle ne s'execute que si le scan profile l'autorise :

- `full-scan` : active tests actives
- `quick-check` : active tests actives, mais avec moins de modules
- `api-deep` : active tests adaptes API
- `passive-only` : active tests desactives
- `custom` : selon `enabled_phases` et `active_modules`

Si la phase `active` n'est pas dans `enabled_phases`, le runner la saute et ajoute un evenement `profile-skip`.

## Modules actifs disponibles

Les modules actifs actuels sont :

| Module | Nom interne | Role |
|---|---|---|
| SQLi | `sqli-detection` | cherche des injections SQL |
| XSS | `xss-reflected` | cherche des XSS reflechies |
| Path traversal | `path-traversal` | teste des lectures de fichiers |
| SSRF | `ssrf-basic` | teste des comportements SSRF simples |
| IDOR | `idor-simple` | teste des acces indirects non autorises |
| Open redirect | `open-redirect` | teste les redirections ouvertes |

Le runner enregistre uniquement les modules presents dans `options.active_modules`.

## Deroulement d'un active test

La phase active fonctionne comme une file de plans ciblés. Un test n'est créé que
si le module trouve un point d'entrée pertinent : paramètre query/form/JSON,
identifiant de chemin ou paramètre de redirection/URL.

Chaque test recoit :

- un ID unique
- le module concerne
- l'asset cible
- la methode HTTP
- l'URL
- un statut courant
- une liste d'etapes horodatees
- un compteur de requetes
- un compteur de reponses
- un statut final
- le point d'entree et son emplacement
- le finding passif source eventuel
- la baseline et les echanges HTTP nettoyes
- la conclusion et la raison du statut

Le code principal est dans :

```text
internal/scanner/engine/engine.go
```

## Cycle de vie d'un test

Un active test passe par plusieurs etapes.

```text
QUEUED
  -> STARTED
  -> BASELINE_REQUEST_SENT
  -> BASELINE_RESPONSE_RECEIVED
  -> TEST_REQUEST_SENT
  -> TEST_RESPONSE_RECEIVED
  -> COMPARING
  -> VALIDATING
  -> ANALYZING
  -> statut final
```

### Etapes intermediaires

| Statut | Signification |
|---|---|
| `QUEUED` | le test est cree et place dans la file |
| `STARTED` | le worker commence ce test |
| `REQUEST_SENT` | une requete HTTP a ete envoyee |
| `RESPONSE_RECEIVED` | une reponse HTTP a ete recue |
| `ANALYZING` | le module analyse la reponse |
| `BASELINE_REQUEST_SENT` | la requete originale est envoyee |
| `BASELINE_RESPONSE_RECEIVED` | la reponse normale est recue |
| `TEST_REQUEST_SENT` | une requete de test est envoyee |
| `TEST_RESPONSE_RECEIVED` | la reponse de test est recue |
| `COMPARING` | la reponse est comparee a la baseline |
| `VALIDATING` | le module applique sa regle de conclusion |

Ces etapes servent surtout a la tracabilite et au debug.

## Statuts finaux

Le moteur utilise directement la conclusion du module. Il ne transforme plus
automatiquement la presence d'un finding en `CONFIRMED`.

| Statut | Signification |
|---|---|
| `CONFIRMED` | preuve suffisante, executee et reproductible selon le module |
| `NOT_CONFIRMED` | requetes envoyees et analysees, sans preuve suffisante |
| `INCONCLUSIVE` | comportement suspect, budget atteint ou comparaison insuffisante |
| `UNTESTABLE` | aucun point d'entree ou aucune requete pertinente |
| `FAILED` | erreur technique pendant le test |
| `TIMEOUT` | le timeout individuel ou global a ete atteint |
| `CANCELLED` | le test a ete interrompu par l'arret de l'audit |

Un test sans requete ne peut pas finir en `NOT_CONFIRMED`. Une confirmation
sans preuve structuree est convertie en `INCONCLUSIVE`.

## Socle commun

Le code partage se trouve dans `internal/scanner/active/active.go`.

Il fournit :

- `ActiveTestPlan` pour le point d'entree et le finding source ;
- une baseline commune ;
- l'enregistrement des requetes, reponses, codes, tailles, durees et hashes ;
- une normalisation initiale des dates, UUID, tokens et valeurs de session ;
- des budgets par test, endpoint et module ;
- une limite de repetitions, de redirections et de taille de reponse ;
- un transport lie au `context.Context` ;
- le masquage des tokens, cookies, mots de passe et cles API.

Les six modules internes utilisent ce contrat tout en conservant leurs payloads
et leur logique existants. L'etape suivante pourra remplacer progressivement
leur conclusion historique par des regles de validation propres a chaque
vulnerabilite.

## API

Les traces nettoyees sont accessibles par :

- `GET /api/audits/{id}/active-tests`
- `GET /api/audits/{id}/active-stats`
- `GET /api/audits/{id}/active-summary`

Les options d'authentification ne sont pas renvoyees par `GET /api/audits/{id}`.

## SQLi

Le module `sqli-detection` utilise maintenant une validation differentielle :

1. deux requetes de reference etablissent le comportement normal ;
2. les variantes error-based cherchent uniquement des signatures SQL specifiques ;
3. les variantes boolean-based comparent une condition vraie et une condition fausse ;
4. une difference candidate est reproduite avant toute confirmation ;
5. un HTTP 500 generique, une variation dynamique ou un ralentissement isole ne suffit pas.

Un `CONFIRMED` SQLi conserve la baseline, les controles vrai/faux, les reponses
normalisees, les differences, le nombre de reproductions et la regle de
validation dans `ActiveEvidence`. Le module appelle `MarkMinimumProof()` juste
apres la reproduction de la preuve minimale.

## XSS reflechie

Le module `xss-reflected` conserve les payloads existants mais analyse leur
contexte de reflexion. Il distingue notamment le texte HTML, un attribut, un
bloc JavaScript, une valeur JSON et une valeur URL.

Une valeur correctement echappee est classee `NOT_CONFIRMED` avec son
encodage. Une valeur brute dans une chaine JavaScript est `INCONCLUSIVE` si le
payload actuel ne prouve pas une sortie de chaine. `CONFIRMED` necessite un
element script ou un attribut evenementiel reellement cree par l'entree, puis
une reproduction du meme contexte.

La preuve conserve l'emplacement, le contexte, l'encodage observe, les
echanges de test, la comparaison avec la baseline et la raison de la conclusion.

## Open redirect

Le module `open-redirect` n'envoie pas la requete vers l'origine externe de
controle. Il capture chaque reponse HTTP, suit manuellement les hops internes,
puis compare l'origine finale avec l'origine de controle.

Une chaîne HTTP externe reproduite est `CONFIRMED`. Une normalisation vers le
domaine legitime ou une destination seulement affichee est `NOT_CONFIRMED`.
Une redirection JavaScript ou `meta refresh` est conservee comme observation
statique et reste `INCONCLUSIVE` tant qu'elle n'est pas executee dans un
navigateur.

`ActiveEvidence` conserve l'URL finale, l'origine finale, le type de
redirection et toute la chaîne des destinations.

## IDOR

Le module `idor-simple` ne modifie plus un identifiant et ne conclut plus sur
un simple code HTTP 200. Une validation IDOR exige une configuration explicite
des deux cotes de l'autorisation :

- `active_idor_identities` contient au moins deux sessions nommees, par
  exemple `alice` et `bob`, avec leurs headers, cookies ou tokens ;
- `active_idor_owner_identity` et `active_idor_non_owner_identity` indiquent
  les sessions a comparer ;
- `active_idor_owner_resource` et `active_idor_non_owner_resource` indiquent
  deux URLs de ressources appartenant a ces utilisateurs ;
- `active_idor_success_marker` peut identifier une reponse metier reussie ;
- `active_idor_denied_marker` peut identifier un refus metier explicite.

Le module verifie d'abord que chaque identite peut acceder a sa propre
ressource. Il tente ensuite l'acces croise :

1. session non proprietaire vers la ressource proprietaire ;
2. pour une lecture, session proprietaire vers la ressource non proprietaire.

Une confirmation exige une reponse metier equivalente a celle du proprietaire
ou le marqueur de succes configure. Un `200`, une page generique, une taille
identique ou un identifiant modifie ne suffit pas. Un refus `401`, `403`, `404`,
`405` ou le marqueur de refus donne `NOT_CONFIRMED`. Une reponse differente mais
ambigue donne `INCONCLUSIVE`.

Les methodes `POST`, `PUT`, `PATCH` et `DELETE` sont classees comme operations
de modification. Elles restent `UNTESTABLE` tant que
`active_idor_allow_write` n'est pas active, afin d'eviter de modifier une
ressource pendant un audit de lecture.

Sans deux identites, deux ressources attribuees et une reponse metier
identifiable, le module retourne `UNTESTABLE` ou `INCONCLUSIVE`. Les sessions
ne sont pas renvoyees par l'API d'audit ; seules leurs identites nominales et
les traces nettoyees restent visibles.

## SSRF

Le module `ssrf-basic` ne teste plus automatiquement des adresses metadata,
loopback ou des services internes. Une confirmation SSRF exige un callback
hors bande controle par l'operateur du scan.

Les options sont :

- `active_ssrf_callback_url` : URL recue par le serveur cible, avec `{token}`
  remplace par un identifiant unique du test ;
- `active_ssrf_callback_check_url` : endpoint de verification, egalement avec
  `{token}`, qui indique si ce token a ete recu ;
- `active_ssrf_callback_marker` : marqueur optionnel permettant une preuve
  directe retournee par la cible, sans callback hors bande ;
- `active_ssrf_allow_private_callback` : option explicite pour les callbacks
  locaux de laboratoire. Elle est desactivee par defaut.

Le module envoie d'abord la requete normale, puis une seule requete de test
avec l'URL callback dans le parametre URL pertinent. Les redirections HTTP de
la cible ne sont pas suivies par le scanner : une redirection ou une URL
affichee ne prouve pas une requete serveur. Une redirection JavaScript reste
`INCONCLUSIVE`, car elle n'est pas executee par ce module.

La conclusion suit ces regles :

- `CONFIRMED` uniquement si le collecteur confirme le token unique, ou si le
  marqueur direct configure est retourne par la cible ;
- `INCONCLUSIVE` si l'URL est acceptee, affichee ou redirigee sans preuve de
  requete emise par le serveur ;
- `UNTESTABLE` si les endpoints callback sont absents, invalides ou hors du
  perimetre autorise ;
- `FAILED` ou `TIMEOUT` en cas d'erreur technique ou de depassement du
  contexte.

`ActiveEvidence` conserve le token, les URLs callback, l'observation du
collecteur, la preuve retournee, les echanges HTTP et la regle de validation.
Les tests internes arbitraires sont volontairement absents du chemin actif :
le callback doit etre fourni et autorise explicitement par la configuration.

## Path traversal

Le module `path-traversal` compare un chemin normal, un chemin invalide et les
payloads de traversal existants. La confirmation exige un marqueur de ressource
spécifique, absent des contrôles et retrouvé dans la réponse traversal puis dans
sa reproduction.

Un code HTTP 200, une différence de taille ou une page d'erreur ne suffisent
pas. Le marqueur par défaut est `root:x:0:0` pour la ressource `/etc/passwd`.
Un environnement de recette peut fournir `active_traversal_proof_path` et
`active_traversal_proof_marker` pour utiliser une ressource de test dédiée.
