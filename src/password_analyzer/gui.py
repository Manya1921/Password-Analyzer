import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict

from password_analyzer.analyzer import analyze_password
from password_analyzer.generator import generate_wordlist
from password_analyzer.exporter import save_wordlist

def _analyze(password: str) -> str:
    try:
        res = analyze_password(password)
        entropy = res.get("entropy", res.get("guesses_log10", "N/A"))
        score = res.get("score", "N/A")
        feedback = res.get("feedback", {})
        return f"Score: {score}\nEntropy: {entropy}\nFeedback: {feedback}"
    except Exception as e:
        return f"Error: {e}"

def run_gui():
    root = tk.Tk()
    root.title("Password Analyzer")
    root.geometry("700x460")

    frm = ttk.Frame(root, padding=12)
    frm.pack(fill="both", expand=True)

    ttk.Label(frm, text="Password to analyze:").grid(column=0, row=0, sticky="w")
    pwd_var = tk.StringVar()
    pwd_entry = ttk.Entry(frm, textvariable=pwd_var, width=40, show="*")
    pwd_entry.grid(column=0, row=1, sticky="w")
    ttk.Button(frm, text="Analyze", command=lambda: (result_box.delete("1.0", tk.END), result_box.insert(tk.END, _analyze(pwd_var.get())))).grid(column=1, row=1, padx=8)

    result_box = tk.Text(frm, height=6, width=80)
    result_box.grid(column=0, row=2, columnspan=3, pady=(6,12))

    ttk.Separator(frm, orient="horizontal").grid(column=0, row=3, columnspan=3, sticky="ew", pady=8)
    ttk.Label(frm, text="Custom wordlist inputs").grid(column=0, row=4, sticky="w")

    name_var = tk.StringVar()
    pet_var = tk.StringVar()
    date_var = tk.StringVar()
    ttk.Entry(frm, textvariable=name_var, width=30).grid(column=0, row=5, sticky="w")
    ttk.Label(frm, text="Name").grid(column=1, row=5, sticky="w")
    ttk.Entry(frm, textvariable=pet_var, width=30).grid(column=0, row=6, sticky="w")
    ttk.Label(frm, text="Pet").grid(column=1, row=6, sticky="w")
    ttk.Entry(frm, textvariable=date_var, width=30).grid(column=0, row=7, sticky="w")
    ttk.Label(frm, text="Date (YYYY or YYYY-MM-DD)").grid(column=1, row=7, sticky="w")

    def on_generate():
        inputs: Dict[str,str] = {"name": name_var.get(), "pet": pet_var.get(), "date": date_var.get()}
        words = generate_wordlist(inputs)
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
        if not path:
            return
        try:
            save_wordlist(words, path)
            messagebox.showinfo("Saved", f"Saved {len(words)} words to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    ttk.Button(frm, text="Generate Wordlist and Save", command=on_generate).grid(column=0, row=8, pady=12, sticky="w")

    root.mainloop()
