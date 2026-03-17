# Analyse de l'APK UnCrackable Level 2 — Recherche du secret natif

## Vue d'ensemble

Dans ce travail pratique, on s'intéresse à une application Android intentionnellement vulnérable tirée du projet **OWASP MSTG** : **UnCrackable Level 2**.

Le principe est simple en apparence — l'application demande un mot de passe secret — mais la vérification ne se fait pas dans le code Java traditionnel. Elle est déléguée à une **bibliothèque native** via **JNI (Java Native Interface)**, ce qui complique l'analyse directe.

Le but de ce rapport est de documenter pas à pas comment on est arrivé à retrouver cette valeur secrète en combinant décompilation Java, extraction d'APK et analyse de fichier `.so` avec **Ghidra**.

---

## Environnement de travail

| Outil | Rôle |
|---|---|
| Android Emulator (Pixel 3, API 28) | Exécution de l'application |
| ADB | Déploiement de l'APK |
| JADX | Décompilation du code Java |
| Ghidra | Analyse du binaire natif |
| PowerShell | Manipulation des fichiers |
| Python | Scripts auxiliaires |

---

## Étape 1 — Déploiement de l'application

Le fichier APK est poussé vers l'émulateur Android via **ADB** :

```bash
adb install uncrackable2.apk
```

Une fois l'application démarrée, l'interface présente un champ de texte unique accompagné d'un bouton **VERIFY**. Aucune indication sur la nature ou la longueur du mot de passe attendu n'est fournie à l'utilisateur.

### 📸 Image 1 — Interface principale de l'application
> Insérer ici la capture d'écran montrant l'application dans l'émulateur avec le champ de saisie vide.

---

## Étape 2 — Comportement avec une entrée incorrecte

Avant toute analyse, on teste l'application avec une valeur quelconque pour observer son comportement :

```text
test
```

L'application répond immédiatement par un message négatif :

```text
Nope...
That's not it. Try again.
```

Ce retour confirme qu'une comparaison est bien effectuée en arrière-plan entre la saisie et une valeur de référence. L'objectif est de remonter jusqu'à cette valeur de référence.

### 📸 Image 2 — Message d'échec après une mauvaise saisie
> Insérer ici la capture montrant le message "Nope... That's not it. Try again."

---

## Étape 3 — Décompilation avec JADX

L'APK est ouvert dans **JADX** pour inspecter le code Java décompilé.

On identifie rapidement la classe de départ : `MainActivity`. La méthode qui traite le bouton **VERIFY** est :

```java
public void verify(View view)
```

À l'intérieur, le texte saisi est récupéré ainsi :

```java
String string = ((EditText) findViewById(R.id.edit_text)).getText().toString();
```

Puis transmis à un autre objet :

```java
this.m.a(string);
```

La vérification n'est donc pas dans `MainActivity` elle-même. Elle est externalisée vers un objet de type différent, ce qui nous amène à chercher dans les classes auxiliaires.

### 📸 Image 3 — Décompilation de MainActivity dans JADX
> Insérer ici la capture montrant le code de la méthode verify() dans JADX.

---

## Étape 4 — Examen de la classe `CodeCheck`

En naviguant dans l'arborescence des classes JADX, on trouve `CodeCheck` :

```java
package sg.vantagepoint.uncrackable2;

public class CodeCheck {
    private native boolean bar(byte[] bArr);

    public boolean a(String str) {
        return bar(str.getBytes());
    }
}
```

Trois observations importantes :

- La méthode `bar()` est marquée **`native`** — son implémentation est dans un fichier `.so` compilé, pas dans le bytecode Java.
- La chaîne saisie par l'utilisateur est convertie en octets bruts via `getBytes()` avant d'être transmise.
- Tout le mécanisme de validation se situe donc hors du code Java analysable directement.

Cette architecture JNI est couramment utilisée pour rendre la rétro-ingénierie plus difficile.

### 📸 Image 4 — Code de la classe CodeCheck dans JADX
> Insérer ici la capture montrant la classe CodeCheck avec la méthode native bar().

---

## Étape 5 — Extraction des bibliothèques natives

Un fichier APK étant une archive ZIP renommée, on peut l'extraire directement avec PowerShell pour accéder à son contenu interne :

```powershell
Expand-Archive uncrackable2.zip -DestinationPath uncrackable_12
dir uncrackable_12
dir uncrackable_12\lib
dir uncrackable_12\lib\x86
```

Le dossier `lib` révèle plusieurs variantes compilées selon l'architecture cible :

```text
arm64-v8a
armeabi-v7a
x86
x86_64
```

Pour ce laboratoire, on cible l'architecture **x86** (compatible avec l'émulateur utilisé). On y trouve la bibliothèque native :

```text
libfoo.so
```

Chemin complet utilisé pour la suite :

```text
uncrackable_12/lib/x86/libfoo.so
```

### 📸 Image 5 — Terminal PowerShell montrant libfoo.so
> Insérer ici la capture du terminal affichant la structure extraite avec lib/x86/libfoo.so visible.

---

## Étape 6 — Import de libfoo.so dans Ghidra

Le fichier `libfoo.so` est importé dans **Ghidra** et soumis à l'analyse automatique.

Une fois l'analyse terminée, on recherche la fonction JNI correspondant à la méthode `bar()` identifiée dans `CodeCheck`. Grâce au nommage JNI qui suit une convention prévisible, on localise sans difficulté :

```text
Java_sg_vantagepoint_uncrackable2_CodeCheck_bar
```

Cette fonction est le point d'entrée exact appelé à chaque fois que l'utilisateur appuie sur **VERIFY**. C'est ici que la comparaison avec le secret a lieu.

---

## Étape 7 — Lecture du pseudo-code généré par Ghidra

Le décompilateur de Ghidra génère un pseudo-code C lisible à partir du binaire. On y repère immédiatement une copie de chaîne vers un buffer local :

```c
builtin_strncpy(local_30, "Thanks for all the fish", 0x18);
```

Suivie d'une comparaison avec l'entrée utilisateur :

```c
iVar1 = strncmp(_s1, local_30, 0x17);
```

Lecture du code :

- `local_30` reçoit la chaîne secrète codée en dur dans la bibliothèque.
- `_s1` correspond à l'entrée transmise depuis Java via `getBytes()`.
- `strncmp` effectue la comparaison octet par octet sur 23 caractères (`0x17`).
- Si le résultat est `0` (égalité), la vérification retourne un succès.

La valeur secrète est donc directement visible dans le binaire :

```text
Thanks for all the fish
```

### 📸 Image 6 — Pseudo-code Ghidra avec la chaîne secrète
> Insérer ici la capture Ghidra mettant en évidence la ligne builtin_strncpy avec "Thanks for all the fish".

---

## Étape 8 — Vérification dans l'émulateur

La chaîne trouvée est saisie dans l'application :

```text
Thanks for all the fish
```

L'application affiche cette fois un message de réussite :

```text
Success!
This is the correct secret.
```

La valeur retrouvée par analyse statique est correcte. L'objectif du laboratoire est atteint.

### 📸 Image 7 — Message de succès dans l'émulateur
> Insérer ici la capture de l'émulateur affichant "Success! This is the correct secret."

---

## Résultat

Le mot de passe attendu par l'application **UnCrackable Level 2** est :

```text
Thanks for all the fish
```

---

## Bilan

Ce laboratoire illustre une technique fréquente dans la protection d'applications mobiles : déporter la logique critique vers du code natif compilé, moins accessible à l'analyse statique classique.

En pratique, cette protection ne résiste pas longtemps face à des outils comme **Ghidra** : la fonction JNI est facilement identifiable grâce aux conventions de nommage, et le décompilateur produit un pseudo-code qui révèle directement les opérations de comparaison.

Les étapes clés de cette démarche ont été :
- identifier le délégué natif depuis `MainActivity` → `CodeCheck` → `bar()`
- extraire `libfoo.so` depuis l'APK traité comme archive ZIP
- localiser et analyser la fonction JNI dans Ghidra
- lire la chaîne secrète en clair dans le pseudo-code décompilé
