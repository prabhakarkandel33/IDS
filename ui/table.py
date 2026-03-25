import tkinter as tk
from tkinter import ttk
import pandas as pd
from ui.theme import BG, SURFACE, BORDER, TEXT, TEXT_DIM, ATTACK_COLORS, FONT_SMALL, FONT_LABEL


DISPLAY_COLS = [
    'destination port', 'flow duration', 'total fwd packets',
    'flow bytes/s', 'flow packets/s'
]


class TableFrame(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=BG, **kwargs)
        self._build()

    def _build(self):
        # ── toolbar ───────────────────────────────────────────────────────────
        toolbar = tk.Frame(self, bg=BG)
        toolbar.pack(fill="x", padx=12, pady=(8, 4))

        tk.Label(toolbar, text="FLAGGED FLOWS", bg=BG, fg=TEXT_DIM,
                 font=FONT_LABEL).pack(side="left")

        self.count_lbl = tk.Label(toolbar, text="", bg=BG, fg=TEXT_DIM,
                                  font=FONT_SMALL)
        self.count_lbl.pack(side="right")

        # ── search bar ────────────────────────────────────────────────────────
        search_frame = tk.Frame(self, bg=BG)
        search_frame.pack(fill="x", padx=12, pady=(0, 6))
        tk.Label(search_frame, text="Filter:", bg=BG, fg=TEXT_DIM,
                 font=FONT_SMALL).pack(side="left", padx=(0, 6))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_filter)
        entry = tk.Entry(search_frame, textvariable=self.search_var,
                         bg=SURFACE, fg=TEXT, insertbackground=TEXT,
                         relief="flat", font=FONT_SMALL,
                         highlightthickness=1, highlightcolor=BORDER,
                         highlightbackground=BORDER)
        entry.pack(side="left", fill="x", expand=True, ipady=4)

        # ── treeview + scrollbars ─────────────────────────────────────────────
        tree_frame = tk.Frame(self, bg=BG)
        tree_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("IDS.Treeview",
                        background=SURFACE,
                        foreground=TEXT,
                        fieldbackground=SURFACE,
                        bordercolor=BORDER,
                        rowheight=24,
                        font=FONT_SMALL)
        style.configure("IDS.Treeview.Heading",
                        background=BG,
                        foreground=TEXT_DIM,
                        font=FONT_LABEL,
                        relief="flat")
        style.map("IDS.Treeview",
                  background=[("selected", "#1f2937")],
                  foreground=[("selected", TEXT)])

        cols = ["Attack Type", "Confidence %"] + DISPLAY_COLS
        self.tree = ttk.Treeview(tree_frame, columns=cols,
                                 show="headings", style="IDS.Treeview")

        col_widths = {"Attack Type": 160, "Confidence %": 100,
                      "destination port": 110, "flow duration": 110,
                      "total fwd packets": 130, "flow bytes/s": 100,
                      "flow packets/s": 100}
        for col in cols:
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort(c))
            self.tree.column(col, width=col_widths.get(col, 100),
                             anchor="center", stretch=True)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal",
                            command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set,
                            xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        # tag colours per attack type
        for attack, color in ATTACK_COLORS.items():
            self.tree.tag_configure(attack, background=color, foreground="#000000")


        self._all_rows = []

    # ── public ────────────────────────────────────────────────────────────────
    def load(self, features: pd.DataFrame, predictions: pd.DataFrame):
        self.tree.delete(*self.tree.get_children())
        self._all_rows = []

        mask     = predictions['prediction'] != 'BENIGN'
        mal_feat = features[mask].reset_index(drop=True)
        mal_pred = predictions[mask].reset_index(drop=True)

        for i in range(len(mal_pred)):
            attack = mal_pred.loc[i, 'prediction']
            conf   = mal_pred.loc[i, 'confidence']
            vals   = [attack, f"{conf:.1f}%"]
            for col in DISPLAY_COLS:
                v = mal_feat.loc[i, col] if col in mal_feat.columns else "—"
                vals.append(f"{v:.2f}" if isinstance(v, float) else str(v))
            self._all_rows.append((attack, vals))

        self.count_lbl.config(text=f"{len(self._all_rows):,} malicious flows")
        self._populate(self._all_rows)

    # ── internals ─────────────────────────────────────────────────────────────
    def _populate(self, rows):
        self.tree.delete(*self.tree.get_children())
        for attack, vals in rows:
            tag = attack if attack in ATTACK_COLORS else ""
            self.tree.insert("", "end", values=vals, tags=(tag,))

    def _on_filter(self, *_):
        q = self.search_var.get().lower()
        if not q:
            self._populate(self._all_rows)
            return
        filtered = [(a, v) for a, v in self._all_rows if q in a.lower()]
        self._populate(filtered)

    def _sort(self, col):
        """Toggle sort on column header click."""
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:
            items.sort(key=lambda x: float(x[0].replace('%', '')))
        except ValueError:
            items.sort()
        for idx, (_, k) in enumerate(items):
            self.tree.move(k, "", idx)