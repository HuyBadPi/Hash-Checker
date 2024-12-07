import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES

def calculate_hash(file_path):
    try:
        hash_results = {
            "MD5": hashlib.md5(),
            "SHA-1": hashlib.sha1(),
            "SHA-256": hashlib.sha256(),
            "SHA-512": hashlib.sha512(),
        }

        # Lire le fichier en blocs de 8 Ko
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                for algo in hash_results.values():
                    algo.update(chunk)

        # Renvoie le résultat sous forme de résumé hexadécimal
        return {name: algo.hexdigest() for name, algo in hash_results.items()}
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de calculer le hachage: {e}")
        return None


def open_file():
    file_path = filedialog.askopenfilename(title="Sélectionnez le fichier pour vérifier le hachage")
    if not file_path:
        return  # L'utilisateur appuie sur Annuler

    hash_values = calculate_hash(file_path)
    if hash_values:
        # Afficher les résultats
        result_text.set(
            f"Fichier: {file_path}\n\n"
            + f"MD5: {hash_values['MD5']}\n\n"
            + f"SHA-1: {hash_values['SHA-1']}\n\n"
            + f"SHA-256: {hash_values['SHA-256']}\n\n"
            + f"SHA-512: {hash_values['SHA-512']}\n\n"
        )


def on_drag_and_drop(event):
    file_path = event.data.strip()
    if file_path.startswith("{") and file_path.endswith("}"):  # Windows format
        file_path = file_path[1:-1]

    hash_values = calculate_hash(file_path)
    if hash_values:
        result_text.set(
            f"Fichier: {file_path}\n\n"
            + f"MD5: {hash_values['MD5']}\n\n"
            + f"SHA-1: {hash_values['SHA-1']}\n\n"
            + f"SHA-256: {hash_values['SHA-256']}\n\n"
            + f"SHA-512: {hash_values['SHA-512']}\n\n"
        )


# Interface
app = TkinterDnD.Tk()
app.title("Hash Checker")
app.geometry("600x400")
app.resizable(False, False)

# Ajouter une icône pour l'application
app.iconphoto(True, tk.PhotoImage(file='C:/Users/trann/Desktop/check hash/icon.png'))

# Résultat
result_text = tk.StringVar()
result_text.set("Glisser le fichier ici ou appuyez sur « Sélectionner un fichier »")

# Ajouter un cadre pour afficher les résultats
frame = tk.LabelFrame(app, text="Résultat", padx=10, pady=10)
frame.pack(fill="both", expand=True, padx=10, pady=10)

result_label = tk.Label(frame, textvariable=result_text, justify="left", wraplength=550, anchor="center")
result_label.pack(expand=True)

# Ajouter un bouton de sélection de fichier
choose_button = tk.Button(app, text="Sélectionner un fichier", command=open_file)
choose_button.pack(pady=10)

# Glisser et déposer des fichiers
app.drop_target_register(DND_FILES)
app.dnd_bind("<<Drop>>", on_drag_and_drop)

# Exécutez l'application
app.mainloop()
