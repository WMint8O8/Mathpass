# MathPass v5 — Modus A

Eine lokale, deterministische Passwort-App auf Basis deines persönlichen
Mathematiksystems:

- 64
- 21
- Fibonacci
- Euler
- Boltzmann

## Sicherheitsmodell

Die Mathematik ist bewusst NICHT geheim.

Das eigentliche Geheimnis ist die 24-Wort-Master-Phrase.

Ablauf:

    Master Phrase
        +
    Dienst + Kürzel
        +
    persönlicher Mathematik-Kontext
        ↓
    Argon2id
        ↓
    HMAC-SHA256
        ↓
    16 Zeichen

Die Master Phrase wird in dieser Version nicht gespeichert.

## Installation unter Windows

1. Python 3 installieren.
2. Diesen Ordner entpacken.
3. Eingabeaufforderung/PowerShell im Ordner öffnen.
4. Einmalig:

    py -m pip install -r requirements.txt

5. Start:

    py mathpass_v5.py

Alternativ `start_mathpass.bat` doppelklicken.

Die Passwortberechnung benötigt danach keine Netzwerkverbindung.

## Master Phrase

Über "Neue 24-Wort-Phrase erzeugen" wird eine neue Phrase erzeugt.

Die Zufallsquelle liefert 256 Bit Entropie. Die 256-Bit-BIP39-Entropie wird
mit 8 Checksum-Bits zu einer 24-Wort-Mnemonic codiert.

WICHTIG:

- Die Phrase offline auf Papier oder einem geeigneten physischen Medium sichern.
- Nicht in Chat, E-Mail, Cloud oder Passwortmanager-Notizen kopieren, wenn
  du genau das hier gewünschte eigenständige Modell verwenden willst.
- Nicht als Wallet-Recovery-Seed verwenden.
- Zwei getrennte Backups sind sinnvoll.
- Wer die Phrase kennt, kann alle Passwörter dieses Systems erzeugen.
- Wenn die Phrase verloren geht, gibt es keine Wiederherstellung.

## Alltag

Immer:

    Dienst + genau 3 Buchstaben Kürzel

Beispiel:

    PayPal -> PPY
    Google -> GOO
    Instagram -> INS

Für verschiedene Accounts desselben Dienstes unterschiedliche Kürzel verwenden.

Der gleiche Dienst + das gleiche Kürzel + die gleiche Master Phrase ergibt immer
dasselbe Passwort.

## Passwortformat

Immer 16 Zeichen:

    a-z
    A-Z
    0-9
    ! @

Die App erzwingt mindestens ein Zeichen jeder Klasse.

64 mögliche Zeichen bedeuten bei 16 freien Zeichen einen maximalen
Zeichenraum von 64^16 = 2^96. Die erzwungenen Klassen reduzieren den exakten
Raum etwas.

Kollisionen sind theoretisch möglich, aber bei einer guten kryptografischen
Ableitung praktisch sehr unwahrscheinlich. Eine mathematische Garantie für
"niemals zweimal" gibt es bei endlichen Passworträumen nicht.

## Modus A

Kein Master-Key/Passwort wird auf Platte gespeichert.

Das reduziert das Risiko eines verlorenen oder gestohlenen Geräts mit
gespeichertem Geheimnis.

Gegen ein kompromittiertes Gerät (z.B. Keylogger/Malware) schützt Modus A
nicht. Nutze die Anwendung möglichst auf einem vertrauenswürdigen Gerät.

## Mathematik

Für Dienst + Kürzel:

    T = Summe der Buchstabenwerte A=1 ... Z=26
    L = Anzahl der Buchstaben

    n = ((T + 64L + 20) mod 26) + 1
    r = ((7n + 6) mod 26) + 2

    F = F_r

    E = e^(i*pi*r) = (-1)^r

    Omega = 64F + 21 + E

    H3 = floor(1000 * ln(Omega))

H3 wird durch Abschneiden gebildet, nicht durch Runden.

Die Mathematik ist ein persönlicher Fingerprint/Domain-Kontext und ersetzt
keine moderne Kryptografie.

## Grenzen

Für extrem wichtige Konten bleibt ein etablierter Passwortmanager mit
zufälligen, einzigartigen Passwörtern die konservativere Wahl.
