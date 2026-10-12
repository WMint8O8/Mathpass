#!/usr/bin/env python3
"""
MathPass v5 — local deterministic password generator

MODE A:
- The 24-word master phrase is entered for every generation.
- The phrase is NOT saved by this application.
- The app does not create a password database.

PERSONAL MATH:
    T = sum(A=1 ... Z=26 over service + 3-letter code)
    L = number of letters
    n = ((T + 64*L + 20) mod 26) + 1
    r = ((7*n + 6) mod 26) + 2
    F = F_r, where r is 2..27
    E = e^(i*pi*r) = (-1)^r
    Omega = 64*F + 21 + E
    H3 = floor(1000*ln(Omega))

SECURITY:
    24-word random master phrase
        -> Argon2id
        -> HMAC-SHA256
        -> deterministic 16-character password

The personal mathematics is a public domain-separation layer.
The master phrase is the secret.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import tkinter as tk
import unicodedata
from decimal import Decimal, getcontext
from tkinter import messagebox
from tkinter import ttk
from typing import Dict, Tuple

from argon2.low_level import Type, hash_secret_raw


getcontext().prec = 50


# ============================================================
# SYSTEM CONSTANTS
# ============================================================

VERSION = "MATHPASS-V5"

# Exactly F_2 ... F_27: 26 distinct Fibonacci values.
FIB = (
    1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377,
    610, 987, 1597, 2584, 4181, 6765, 10946, 17711,
    28657, 46368, 75025, 121393, 196418
)

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMBOLS = "!@"

# 26 + 26 + 10 + 2 = 64
ALPHABET = LOWER + UPPER + DIGITS + SYMBOLS

PASSWORD_LENGTH = 16

# Deterministic public salt: it is intentionally not secret.
ARGON2_SALT = hashlib.sha256(
    b"MathPass-V5|64|21|Fibonacci|Euler|Boltzmann"
).digest()[:16]

# Chosen to be memory-hard while still practical on a normal computer.
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 1
KEY_LENGTH = 32


# ============================================================
# INPUT NORMALIZATION
# ============================================================

def normalize_phrase(phrase: str) -> str:
    phrase = unicodedata.normalize("NFKD", phrase)
    return " ".join(phrase.strip().split())


def normalize_service(service: str) -> str:
    value = "".join(
        ch for ch in service.strip().upper()
        if "A" <= ch <= "Z"
    )

    if not value:
        raise ValueError(
            "Der Dienstname muss mindestens einen Buchstaben enthalten."
        )

    return value


def normalize_code(code: str) -> str:
    value = "".join(
        ch for ch in code.strip().upper()
        if "A" <= ch <= "Z"
    )

    if len(value) != 3:
        raise ValueError("Das Kürzel muss genau 3 Buchstaben haben.")

    return value


# ============================================================
# BIP-39 MASTER PHRASE
# ============================================================

def bip39_class():
    """
    Lazy import so the program can show a useful error if the
    'mnemonic' dependency was not installed.
    """
    try:
        from mnemonic import Mnemonic
    except ImportError as exc:
        raise RuntimeError(
            "Das Paket 'mnemonic' fehlt.\n\n"
            "Einmalig im MathPass-Ordner ausführen:\n"
            "py -m pip install -r requirements.txt"
        ) from exc

    return Mnemonic


def generate_master_phrase() -> str:
    """
    Generate 256 bits of OS-backed cryptographic randomness and encode it
    as a 24-word English BIP-39 mnemonic.
    """
    Mnemonic = bip39_class()
    entropy = secrets.token_bytes(32)  # 256 bits
    return Mnemonic("english").to_mnemonic(entropy)


def validate_master_phrase(phrase: str) -> bool:
    """
    Require exactly 24 BIP-39 English words and a valid checksum.
    """
    phrase = normalize_phrase(phrase)

    if len(phrase.split()) != 24:
        return False

    Mnemonic = bip39_class()
    return bool(Mnemonic("english").check(phrase))


# ============================================================
# PERSONAL MATHEMATICAL LAYER
# ============================================================

def alphabet_sum(text: str) -> int:
    return sum(ord(ch) - ord("A") + 1 for ch in text)


def math_values(service: str, code: str) -> Dict[str, int | float]:
    combined = service + code

    # A=1 ... Z=26
    T = alphabet_sum(combined)
    L = len(combined)

    # n is always 1..26.
    n = ((T + 64 * L + 20) % 26) + 1

    # r is always 2..27.
    r = ((7 * n + 6) % 26) + 2

    F = FIB[r - 2]

    # Euler:
    # e^(i*pi*r) = (-1)^r
    E = 1 if r % 2 == 0 else -1

    # Integer quantity used in the Boltzmann-inspired layer.
    Omega = 64 * F + 21 + E

    # Dimensionless entropy:
    # S/k_B = ln(Omega)
    entropy = Decimal(Omega).ln()

    # Keep exactly three decimal places as an integer fingerprint.
    H3 = int(entropy * Decimal(1000))

    return {
        "T": T,
        "L": L,
        "n": n,
        "r": r,
        "F": F,
        "E": E,
        "Omega": Omega,
        "H3": H3,
    }


def math_context(values: Dict[str, int | float]) -> str:
    return (
        f"T={values['T']}|L={values['L']}|n={values['n']}|"
        f"r={values['r']}|F={values['F']}|E={values['E']}|"
        f"Omega={values['Omega']}|H3={values['H3']}"
    )


# ============================================================
# CRYPTOGRAPHIC LAYER
# ============================================================

def derive_key(master_phrase: str) -> bytes:
    phrase = normalize_phrase(master_phrase)

    # Public math core is included as context; it is not secret.
    math_core = (
        "64=2^6=4^3=8^2;"
        "21=F8;"
        "e^(i*pi)+1=0;"
        "e^(i*2*pi)=1;"
        "i^2=-1;"
        "S/kB=ln(Omega)"
    )

    secret_material = (
        phrase.encode("utf-8")
        + b"\0"
        + math_core.encode("utf-8")
    )

    return hash_secret_raw(
        secret=secret_material,
        salt=ARGON2_SALT,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LENGTH,
        type=Type.ID,
    )


def hmac_stream(key: bytes, label: bytes):
    counter = 0

    while True:
        block = hmac.new(
            key,
            VERSION.encode("ascii")
            + b"\0"
            + label
            + b"\0"
            + counter.to_bytes(4, "big"),
            hashlib.sha256,
        ).digest()

        yield from block
        counter += 1


def uniform_index(stream, size: int) -> int:
    """
    Uniformly map bytes to [0, size) using rejection sampling.
    """
    limit = 256 - (256 % size)

    while True:
        value = next(stream)

        if value < limit:
            return value % size


def choose(stream, alphabet: str) -> str:
    return alphabet[uniform_index(stream, len(alphabet))]


def deterministic_shuffle(chars: list[str], stream) -> None:
    for i in range(len(chars) - 1, 0, -1):
        j = uniform_index(stream, i + 1)
        chars[i], chars[j] = chars[j], chars[i]


def generate_password(
    master_phrase: str,
    service: str,
    code: str,
) -> Tuple[str, Dict[str, int | float]]:
    service = normalize_service(service)
    code = normalize_code(code)

    if not validate_master_phrase(master_phrase):
        raise ValueError(
            "Die Master Phrase muss genau 24 gültige BIP-39-Wörter "
            "mit korrekter Prüfsumme enthalten."
        )

    values = math_values(service, code)
    context = (
        f"service={service}|code={code}|"
        f"{math_context(values)}"
    ).encode("utf-8")

    key = derive_key(master_phrase)

    # Guarantee all four desired classes.
    chars = [
        choose(hmac_stream(key, context + b"|lower"), LOWER),
        choose(hmac_stream(key, context + b"|upper"), UPPER),
        choose(hmac_stream(key, context + b"|digit"), DIGITS),
        choose(hmac_stream(key, context + b"|symbol"), SYMBOLS),
    ]

    # Remaining positions use the full 64-character alphabet.
    full_stream = hmac_stream(key, context + b"|full")
    while len(chars) < PASSWORD_LENGTH:
        chars.append(choose(full_stream, ALPHABET))

    # Mix positions so classes are not always at fixed positions.
    shuffle_stream = hmac_stream(key, context + b"|shuffle")
    deterministic_shuffle(chars, shuffle_stream)

    return "".join(chars), values


# ============================================================
# GUI
# ============================================================

class MathPassApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        self.title("MathPass v5")
        self.geometry("820x760")
        self.minsize(760, 680)

        self.master_entries: list[ttk.Entry] = []
        self.master_visible = False
        self.clipboard_clear_job = None

        self._build_ui()

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=18)
        outer.pack(fill="both", expand=True)

        ttk.Label(
            outer,
            text="MathPass v5",
            font=("Segoe UI", 20, "bold"),
        ).pack(anchor="w")

        ttk.Label(
            outer,
            text=(
                "64 • 21 • Fibonacci • Euler • Boltzmann  |  "
                "Modus A: Master Phrase wird nie gespeichert"
            ),
        ).pack(anchor="w", pady=(0, 14))

        # ---------- Master phrase ----------
        master_frame = ttk.LabelFrame(
            outer,
            text="1. Master Phrase — 24 Wörter",
            padding=12,
        )
        master_frame.pack(fill="x", pady=(0, 12))

        words_grid = ttk.Frame(master_frame)
        words_grid.pack(fill="x")

        for i in range(24):
            row = i // 4
            col = i % 4

            cell = ttk.Frame(words_grid)
            cell.grid(
                row=row,
                column=col,
                sticky="ew",
                padx=4,
                pady=3,
            )
            words_grid.columnconfigure(col, weight=1)

            ttk.Label(
                cell,
                text=f"{i + 1}.",
                width=3,
            ).pack(side="left")

            entry = ttk.Entry(cell, width=14, show="•")
            entry.pack(side="left", fill="x", expand=True)

            self.master_entries.append(entry)

        master_buttons = ttk.Frame(master_frame)
        master_buttons.pack(fill="x", pady=(8, 0))

        ttk.Button(
            master_buttons,
            text="Neue 24-Wort-Phrase erzeugen",
            command=self.generate_phrase_dialog,
        ).pack(side="left")

        ttk.Button(
            master_buttons,
            text="Phrase prüfen",
            command=self.validate_phrase,
        ).pack(side="left", padx=8)

        ttk.Button(
            master_buttons,
            text="Anzeigen / Verbergen",
            command=self.toggle_master_visibility,
        ).pack(side="left")

        ttk.Label(
            master_frame,
            text=(
                "Diese Phrase wird nur im Arbeitsspeicher verwendet. "
                "Sie ist ein Master-Geheimnis, kein Trezor-/Wallet-Seed."
            ),
            wraplength=740,
        ).pack(anchor="w", pady=(8, 0))

        # ---------- Service ----------
        input_frame = ttk.LabelFrame(
            outer,
            text="2. Dienst + Kürzel",
            padding=12,
        )
        input_frame.pack(fill="x", pady=(0, 12))

        grid = ttk.Frame(input_frame)
        grid.pack(fill="x")

        ttk.Label(grid, text="Dienst:").grid(
            row=0, column=0, sticky="w"
        )

        self.service_entry = ttk.Entry(grid)
        self.service_entry.grid(
            row=0, column=1, sticky="ew", padx=(8, 18)
        )
        self.service_entry.insert(0, "paypal")

        ttk.Label(grid, text="Kürzel:").grid(
            row=0, column=2, sticky="w"
        )

        self.code_entry = ttk.Entry(grid, width=8)
        self.code_entry.grid(
            row=0, column=3, sticky="w", padx=(8, 0)
        )
        self.code_entry.insert(0, "PPY")

        grid.columnconfigure(1, weight=1)

        ttk.Label(
            input_frame,
            text="Kürzel = exakt 3 Buchstaben; es ist frei wählbar, aber später unverändert wiederverwenden.",
        ).pack(anchor="w", pady=(8, 0))

        # ---------- Generate ----------
        ttk.Button(
            outer,
            text="PASSWORT GENERIEREN",
            command=self.on_generate,
        ).pack(fill="x", ipady=7, pady=(0, 12))

        # ---------- Result ----------
        result_frame = ttk.LabelFrame(
            outer,
            text="3. Passwort",
            padding=12,
        )
        result_frame.pack(fill="x", pady=(0, 12))

        result_row = ttk.Frame(result_frame)
        result_row.pack(fill="x")

        self.password_var = tk.StringVar()

        self.password_entry = ttk.Entry(
            result_row,
            textvariable=self.password_var,
            font=("Consolas", 14),
        )
        self.password_entry.pack(
            side="left", fill="x", expand=True
        )

        ttk.Button(
            result_row,
            text="Kopieren",
            command=self.copy_password,
        ).pack(side="left", padx=(8, 0))

        ttk.Label(
            result_frame,
            text=(
                "Standard: 16 Zeichen aus a-z / A-Z / 0-9 / ! @ "
                "mit mindestens einem Zeichen jeder Klasse."
            ),
        ).pack(anchor="w", pady=(8, 0))

        # ---------- Math ----------
        math_frame = ttk.LabelFrame(
            outer,
            text="4. Mathematischer Rechenweg",
            padding=12,
        )
        math_frame.pack(fill="both", expand=True)

        self.math_output = tk.Text(
            math_frame,
            height=11,
            wrap="word",
            font=("Consolas", 10),
            state="disabled",
        )
        self.math_output.pack(fill="both", expand=True)

        ttk.Label(
            outer,
            text=(
                "Sicherheit: Die Formel ist nicht geheim. Die Master Phrase ist das Geheimnis. "
                "Bei Verlust der Phrase sind die Passwörter nicht wiederherstellbar."
            ),
            wraplength=780,
        ).pack(anchor="w", pady=(10, 0))

    def get_master_phrase(self) -> str:
        words = [entry.get().strip() for entry in self.master_entries]

        if any(not word for word in words):
            return ""

        return " ".join(words)

    def set_master_phrase(self, phrase: str) -> None:
        words = normalize_phrase(phrase).split()

        for entry in self.master_entries:
            entry.delete(0, "end")

        for entry, word in zip(self.master_entries, words[:24]):
            entry.insert(0, word)

    def toggle_master_visibility(self) -> None:
        self.master_visible = not self.master_visible

        for entry in self.master_entries:
            entry.configure(show="" if self.master_visible else "•")

    def generate_phrase_dialog(self) -> None:
        try:
            phrase = generate_master_phrase()
        except RuntimeError as exc:
            messagebox.showerror("Abhängigkeit fehlt", str(exc))
            return

        words = phrase.split()

        dialog = tk.Toplevel(self)
        dialog.title("Neue Master Phrase")
        dialog.geometry("720x420")
        dialog.resizable(False, False)
        dialog.grab_set()

        ttk.Label(
            dialog,
            text="Neue 24-Wort-Master Phrase",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", padx=18, pady=(18, 6))

        ttk.Label(
            dialog,
            text=(
                "Schreibe alle 24 Wörter offline auf. "
                "Nicht in Chat, E-Mail oder Cloud speichern."
            ),
            wraplength=680,
        ).pack(anchor="w", padx=18, pady=(0, 12))

        grid = ttk.Frame(dialog)
        grid.pack(fill="x", padx=18)

        for i, word in enumerate(words):
            row = i // 4
            col = i % 4

            ttk.Label(
                grid,
                text=f"{i + 1}. {word}",
                font=("Consolas", 11),
            ).grid(
                row=row,
                column=col,
                sticky="w",
                padx=8,
                pady=4,
            )

        ttk.Label(
            dialog,
            text=(
                "Diese Phrase wurde lokal mit 256 Bit Zufallsentropie erzeugt "
                "und als 24-Wort-BIP39-Mnemonic dargestellt. "
                "Sie ist NICHT für eine Wallet zu verwenden."
            ),
            wraplength=680,
        ).pack(anchor="w", padx=18, pady=14)

        ttk.Button(
            dialog,
            text="Aufgeschrieben – schließen",
            command=dialog.destroy,
        ).pack(anchor="e", padx=18, pady=(0, 18))

    def validate_phrase(self) -> None:
        phrase = self.get_master_phrase()

        if not phrase:
            messagebox.showinfo(
                "Master Phrase",
                "Bitte alle 24 Wörter eingeben.",
            )
            return

        try:
            valid = validate_master_phrase(phrase)
        except RuntimeError as exc:
            messagebox.showerror("Abhängigkeit fehlt", str(exc))
            return

        if valid:
            messagebox.showinfo(
                "Master Phrase",
                "Gültig: 24 Wörter und korrekte BIP39-Prüfsumme.",
            )
        else:
            messagebox.showerror(
                "Master Phrase",
                "Ungültig. Prüfe Wörter, Reihenfolge und Schreibweise.",
            )

    def on_generate(self) -> None:
        phrase = self.get_master_phrase()
        service = self.service_entry.get()
        code = self.code_entry.get()

        if not phrase:
            messagebox.showerror(
                "Fehler",
                "Master Phrase fehlt.",
            )
            return

        try:
            password, values = generate_password(
                master_phrase=phrase,
                service=service,
                code=code,
            )
        except (ValueError, RuntimeError) as exc:
            messagebox.showerror("Fehler", str(exc))
            return

        self.password_var.set(password)

        service_n = normalize_service(service)
        code_n = normalize_code(code)

        entropy_decimal = Decimal(values["H3"]) / Decimal(1000)

        math_text = (
            f"Dienst + Kürzel: {service_n}{code_n}\n\n"
            f"T = Summe der Buchstabenwerte = {values['T']}\n"
            f"L = Anzahl Buchstaben = {values['L']}\n"
            f"n = ((T + 64·L + 20) mod 26) + 1 = {values['n']}\n"
            f"r = ((7·n + 6) mod 26) + 2 = {values['r']}\n"
            f"F_r = F_{values['r']} = {values['F']}\n"
            f"E = e^(i·π·r) = (-1)^r = {values['E']}\n"
            f"Ω = 64·F_r + 21 + E = {values['Omega']}\n"
            f"H3 = floor(1000·ln(Ω)) = {values['H3']}\n"
            f"(H3 entspricht dem abgeschnittenen ln(Ω)·1000 = {entropy_decimal})\n\n"
            "Sicherheitsschicht:\n"
            "Master Phrase + mathematischer Kontext → Argon2id → HMAC-SHA256 → 16 Zeichen"
        )

        self._set_math_output(math_text)

    def _set_math_output(self, text: str) -> None:
        self.math_output.configure(state="normal")
        self.math_output.delete("1.0", "end")
        self.math_output.insert("1.0", text)
        self.math_output.configure(state="disabled")

    def copy_password(self) -> None:
        password = self.password_var.get()

        if not password:
            messagebox.showinfo(
                "Kopieren",
                "Noch kein Passwort erzeugt.",
            )
            return

        self.clipboard_clear()
        self.clipboard_append(password)
        self.update()

        # Clear clipboard automatically after 30 seconds, but only if
        # nothing else has replaced it in the meantime.
        if self.clipboard_clear_job is not None:
            try:
                self.after_cancel(self.clipboard_clear_job)
            except tk.TclError:
                pass

        self.clipboard_clear_job = self.after(
            30_000,
            self._clear_clipboard_if_unchanged,
            password,
        )

        messagebox.showinfo(
            "Kopiert",
            "Passwort wurde kopiert. Die Zwischenablage wird nach 30 Sekunden "
            "gelöscht, sofern sie bis dahin unverändert ist.",
        )

    def _clear_clipboard_if_unchanged(self, expected: str) -> None:
        try:
            current = self.clipboard_get()
        except tk.TclError:
            return

        if current == expected:
            self.clipboard_clear()
            self.update()


if __name__ == "__main__":
    MathPassApp().mainloop()
