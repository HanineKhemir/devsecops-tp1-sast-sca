# VulnBank — TP1 DevSecOps (SAST + SCA)

Petite application Flask volontairement vulnerable, utilisee comme support du TP1 :
analyse statique (SonarQube / Bandit) et analyse des dependances (OWASP
Dependency-Check / pip-audit).

> **Avertissement** : ce code contient des vulnerabilites intentionnelles.
> Il ne doit jamais etre deploye ailleurs que sur un poste de travail local.

## Lancer l'application

```bash
docker build -t vulnbank:baseline .
docker run --rm -p 5000:5000 vulnbank:baseline
# http://localhost:5000
```

Comptes de test : `alice/password`, `bob/123456`, `admin/admin`.

## Structure

| Fichier | Role |
|---|---|
| `vulnbank/app.py` | routes Flask (login, comptes, commentaires, export, taux) |
| `vulnbank/db.py` | schema SQLite et donnees de test |
| `requirements.txt` | dependances epinglees sur des versions anciennes |
| `sonar-project.properties` | configuration du scan SonarQube |

## Historique Git

Le depot raconte le TP dans l'ordre :

1. `baseline` — application vulnerable, avant tout scan
2. correctifs SAST
3. correctifs SCA
