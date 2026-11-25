# Riegel

Hybride Post-Quanten-Verschlüsselung für Dateien.

English version: [README.md](README.md)

> **Experimentell und ungeprüft.** Weder der Entwurf noch der Code wurden von unabhängiger
> Seite begutachtet. Riegel ist nicht für Daten gedacht, auf die es ankommt; siehe
> [SECURITY.md](SECURITY.md).

> **Kein Open Source.** Der Quelltext ist veröffentlicht, damit man ihn lesen und prüfen kann.
> Kommerzielle und militärische Nutzung sind nicht erlaubt; siehe [Lizenz](#lizenz).

## Was Riegel macht

Riegel verschlüsselt eine Datei für einen öffentlichen Schlüssel. Nur wer den passenden
geheimen Schlüssel besitzt, kann sie entschlüsseln, und jede Veränderung an der verschlüsselten
Datei wird erkannt.

Der Schlüsselaustausch kombiniert ein Post-Quanten-Verfahren mit einem klassischen. Die Datei
bleibt vertraulich, solange **eines von beiden** hält. Das schützt auch vor Angreifern, die
verschlüsselte Dateien heute speichern, um sie später mit einem Quantencomputer zu
entschlüsseln.

Riegel erfindet keine eigene Kryptografie, sondern setzt veröffentlichte Bausteine zusammen:

| Zweck | Verfahren |
|---|---|
| Schlüsselaustausch | X-Wing: ML-KEM-768 (FIPS 203) kombiniert mit X25519 |
| Schlüsselableitung | HKDF-SHA-256 |
| Dateiverschlüsselung | ChaCha20-Poly1305 in Blöcken von 64 KiB, mit Erkennung abgeschnittener Dateien |
| Datei mit geheimem Schlüssel | Mit einem Passwort verschlüsselt (Argon2id und ChaCha20-Poly1305) |

[SPEC.md](SPEC.md) beschreibt das Format vollständig, bis aufs Byte (auf Englisch).

## Benutzung

Bauen mit Rust 1.88 oder neuer:

```sh
cargo build --release
```

Das Programm liegt danach unter `target/release/riegel`.

```sh
# Einmalig: Schlüsselpaar erzeugen. Dabei wählt man ein Passwort, das my.key verschlüsselt.
# my.key geheim halten, my.pub an alle geben, die einem etwas schicken sollen.
riegel keygen my.key my.pub

# Bevor man für einen erhaltenen Schlüssel verschlüsselt: diese Ausgabe mit dem Besitzer vergleichen.
riegel fingerprint my.pub

# Jeder mit my.pub kann für einen verschlüsseln.
riegel encrypt my.pub bericht.pdf bericht.pdf.riegel

# Nur my.key zusammen mit dem Passwort kann entschlüsseln.
riegel decrypt my.key bericht.pdf.riegel bericht.pdf
```

Riegel überschreibt nie eine vorhandene Datei. Der Rückgabewert ist 0 bei Erfolg, 1 bei einem
Fehler und 2 bei falschen Argumenten. Schlägt die Entschlüsselung fehl, bleibt keine
Ausgabedatei zurück.

Das Passwort wird am Terminal abgefragt und nicht angezeigt. Ist die Standardeingabe kein
Terminal, gilt ihre erste Zeile als Passwort, Byte für Byte; enthält es Umlaute oder andere
Sonderzeichen, sollte man es eintippen, weil eine Shell weitergeleiteten Text umkodieren kann.
`riegel keygen --no-passphrase` schreibt einen unverschlüsselten geheimen Schlüssel für
Rechner, an denen niemand ein Passwort eingeben kann.

Eine verschlüsselte Datei ist 1159 Bytes größer als das Original, dazu kommen 16 Bytes je
64 KiB.

## Was Riegel nicht macht

- Es zeigt nicht, wer eine Datei verschlüsselt hat. Jeder mit dem öffentlichen Schlüssel kann
  für dessen Besitzer verschlüsseln.
- Es gibt keine „Forward Secrecy“. Wird der geheime Schlüssel bekannt, lassen sich alle jemals
  dafür verschlüsselten Dateien lesen.
- Öffentliche Schlüssel werden nicht automatisch geprüft. Man vergleicht den Fingerabdruck mit
  dem Empfänger über einen Kanal, dem man vertraut.
- Die Größe einer Datei wird nicht verborgen.
- Die Datei mit dem geheimen Schlüssel ist nur so sicher, wie ihr Passwort schwer zu erraten
  ist.
- Eine Datei hat genau einen Empfänger.

Die Gründe stehen in [SECURITY.md](SECURITY.md) und in Abschnitt 8 von [SPEC.md](SPEC.md).

## Wie es geprüft wird

```sh
cargo test
```

prüft die Bausteine gegen die Testvektoren ihrer Spezifikationen (X-Wing-Entwurf, RFC 5869,
RFC 8439, RFC 9106), Verschlüsselung und Schlüsselschutz Bit für Bit gegen die Vektoren in
`tests/vectors/riegel-v1.json`, jede Ein-Bit-Änderung und jede Kürzung einer verschlüsselten
Datei, weitere manipulierte Dateien sowie das Kommandozeilenprogramm von Anfang bis Ende.

```sh
node interop/check.mjs target/release/riegel
```

liest, was das Programm erzeugt (verschlüsselte Dateien, den passwortgeschützten Schlüssel,
den Fingerabdruck), mit einer zweiten Implementierung, die keinen Code mit der ersten teilt:
`interop/reference.mjs`, nach der Spezifikation auf Basis von OpenSSL geschrieben. Dafür wird
Node.js 24.7 oder neuer gebraucht.

## Lizenz

Riegel ist **quelloffen einsehbar, aber kein Open Source**. Die [Riegel Source-Available
License 1.0](LICENSE) erlaubt, den Code für private Zwecke, Lehre und Forschung zu lesen, zu
bauen, auszuführen und zu ändern. Nicht erlaubt sind kommerzielle Nutzung, militärische Nutzung
und die Weitergabe. Alle übrigen Rechte bleiben beim Rechteinhaber; wer eine andere Lizenz
braucht, muss dort anfragen. Maßgeblich ist der englische Lizenztext.

Die verwendeten Bibliotheken stehen unter eigenen, freizügigen Lizenzen; siehe
[THIRD-PARTY.md](THIRD-PARTY.md).
