import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import pandas as pd

from core.preprocessor import load_and_clean
from core.predictor import IDSPredictor
from ui.charts import ChartsFrame
from ui.table import TableFrame
from ui.theme import (
    BG, SURFACE, BORDER, ACCENT, ACCENT2, GREEN, TEXT, TEXT_DIM,
    WHITE, FONT_BODY, FONT_LABEL, FONT_TITLE, FONT_CARD, FONT_CARD_LB,
    FONT_SMALL
)


class MainWindow(tk.Tk):
    def __init__(self, model_path: str):
        super().__init__()
        self.title("Network IDS — Flow Analyser")
        self.geometry("1280x820")
        self.minsize(1100, 700)
        self.configure(bg=BG)

        self.predictor = IDSPredictor(model_path)
        self._build_ui()

    # ══════════════════════════════════════════════════════════════════════════
    #  UI construction
    # ══════════════════════════════════════════════════════════════════════════
    def _build_ui(self):
        self._build_header()
        self._build_cards()
        self._build_progress()
        self._build_tabs()

    # ── header ────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=SURFACE, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # left: icon + title
        left = tk.Frame(hdr, bg=SURFACE)
        left.pack(side="left", padx=20, fill="y")
        tk.Label(left, text="🛡", bg=SURFACE, fg=ACCENT,
                 font=("Consolas", 18)).pack(side="left", padx=(0, 8))
        tk.Label(left, text="NETWORK INTRUSION DETECTION SYSTEM",
                 bg=SURFACE, fg=TEXT, font=FONT_TITLE).pack(side="left")

        # right: upload button
        right = tk.Frame(hdr, bg=SURFACE)
        right.pack(side="right", padx=20, fill="y")

        self.upload_btn = tk.Button(
            right, text="  📂  UPLOAD CSV LOG  ",
            bg=ACCENT, fg=WHITE,
            activebackground="#79b8ff", activeforeground=WHITE,
            font=FONT_LABEL, relief="flat", cursor="hand2",
            padx=12, pady=6,
            command=self._on_upload
        )
        self.upload_btn.pack(side="right", pady=12)

        # separator line
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    # ── summary cards ─────────────────────────────────────────────────────────
    def _build_cards(self):
        cards_row = tk.Frame(self, bg=BG)
        cards_row.pack(fill="x", padx=16, pady=14)

        specs = [
            ("TOTAL FLOWS",   "—", TEXT),
            ("MALICIOUS",     "—", ACCENT2),
            ("BENIGN",        "—", GREEN),
            ("TOP ATTACK",    "—", TEXT),
        ]
        self._card_values = {}
        for title, init_val, color in specs:
            card = tk.Frame(cards_row, bg=SURFACE,
                            highlightthickness=1,
                            highlightbackground=BORDER)
            card.pack(side="left", expand=True, fill="both",
                      padx=6, ipady=12)
            tk.Label(card, text=title, bg=SURFACE, fg=TEXT_DIM,
                     font=FONT_CARD_LB).pack()
            val_lbl = tk.Label(card, text=init_val, bg=SURFACE,
                               fg=color, font=FONT_CARD)
            val_lbl.pack()
            self._card_values[title] = val_lbl

    # ── indeterminate progress bar ────────────────────────────────────────────
    def _build_progress(self):
        self._progress_frame = tk.Frame(self, bg=BG)
        self._progress_frame.pack(fill="x", padx=16)

        style = ttk.Style()
        style.configure("IDS.Horizontal.TProgressbar",
                        troughcolor=SURFACE,
                        background=ACCENT,
                        bordercolor=BORDER)
        self._pbar = ttk.Progressbar(
            self._progress_frame,
            style="IDS.Horizontal.TProgressbar",
            mode="indeterminate", length=300
        )
        self._status_lbl = tk.Label(
            self._progress_frame, text="", bg=BG, fg=TEXT_DIM,
            font=FONT_SMALL
        )
        # hidden by default — shown during inference
        self._progress_frame.pack_forget()

    # ── notebook tabs ─────────────────────────────────────────────────────────
    def _build_tabs(self):
        style = ttk.Style()
        style.configure("IDS.TNotebook",
                        background=BG, bordercolor=BORDER)
        style.configure("IDS.TNotebook.Tab",
                        background=SURFACE, foreground=TEXT_DIM,
                        font=FONT_LABEL, padding=[14, 6])
        style.map("IDS.TNotebook.Tab",
                  background=[("selected", BG)],
                  foreground=[("selected", TEXT)])

        nb = ttk.Notebook(self, style="IDS.TNotebook")
        nb.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.charts_frame = ChartsFrame(nb)
        self.table_frame  = TableFrame(nb)

        nb.add(self.charts_frame, text="  📊  Attack Charts  ")
        nb.add(self.table_frame,  text="  🚨  Flagged Flows  ")

    # ══════════════════════════════════════════════════════════════════════════
    #  Event handlers
    # ══════════════════════════════════════════════════════════════════════════
    def _on_upload(self):
        path = filedialog.askopenfilename(
            title="Select CICFlowMeter CSV",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return

        # show progress
        self.upload_btn.config(state="disabled")
        self._progress_frame.pack(fill="x", padx=16, pady=(4, 8))
        self._pbar.pack(fill="x")
        self._status_lbl.config(text="Loading and running inference…")
        self._status_lbl.pack()
        self._pbar.start(12)

        # run in background thread so UI stays responsive
        threading.Thread(
            target=self._worker,
            args=(path,),
            daemon=True
        ).start()

    def _worker(self, path: str):
        """Runs in background thread — never touch widgets here."""
        try:
            X, timestamps  = load_and_clean(path)
            predictions    = self.predictor.predict(X)
            self.after(0, self._on_results, X, predictions, timestamps)
        except Exception as e:
            self.after(0, self._on_error, str(e))

    def _on_results(self, features: pd.DataFrame,
                    predictions: pd.DataFrame, timestamps):
        self._pbar.stop()
        self._progress_frame.pack_forget()
        self.upload_btn.config(state="normal")

        total   = len(predictions)
        mal_df  = predictions[predictions['prediction'] != 'BENIGN']
        benign  = total - len(mal_df)
        top_atk = (mal_df['prediction'].value_counts().idxmax()
                   if len(mal_df) else "None")

        self._card_values["TOTAL FLOWS"].config(text=f"{total:,}")
        self._card_values["MALICIOUS"].config(text=f"{len(mal_df):,}")
        self._card_values["BENIGN"].config(text=f"{benign:,}")
        self._card_values["TOP ATTACK"].config(
            text=top_atk[:18] + ("…" if len(top_atk) > 18 else ""))

        self.charts_frame.render(predictions, timestamps)
        self.table_frame.load(features, predictions)

    def _on_error(self, msg: str):
        self._pbar.stop()
        self._progress_frame.pack_forget()
        self.upload_btn.config(state="normal")
        messagebox.showerror("Error loading file", msg)