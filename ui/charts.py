import tkinter as tk
import pandas as pd
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from .theme import BG, SURFACE, BORDER, TEXT, TEXT_DIM, ACCENT2, ATTACK_COLORS


class ChartsFrame(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=BG, **kwargs)
        self._placeholder()

    # ── placeholder shown before any file is loaded ───────────────────────────
    def _placeholder(self):
        for w in self.winfo_children():
            w.destroy()
        lbl = tk.Label(
            self,
            text="Upload a CSV log to see charts",
            bg=BG, fg=TEXT_DIM,
            font=("Consolas", 12)
        )
        lbl.place(relx=0.5, rely=0.5, anchor="center")

    # ── main render ───────────────────────────────────────────────────────────
    def render(self, predictions: pd.DataFrame, timestamps):
        for w in self.winfo_children():
            w.destroy()

        malicious = predictions[predictions['prediction'] != 'BENIGN']
        counts    = malicious['prediction'].value_counts()

        fig = Figure(figsize=(13, 3.8), facecolor=SURFACE)
        fig.subplots_adjust(wspace=0.4, left=0.06, right=0.97,
                            top=0.88, bottom=0.18)

        colors = [ATTACK_COLORS.get(k, "#aaaaaa") for k in counts.index]

        # ── 1. Donut ──────────────────────────────────────────────────────────
        ax1 = fig.add_subplot(1, 3, 1)
        ax1.set_facecolor(SURFACE)
        if len(counts):
            wedges, texts, autotexts = ax1.pie(
                counts, labels=None, autopct='%1.1f%%',
                startangle=90,
                wedgeprops=dict(width=0.55, edgecolor=BG, linewidth=1.5),
                colors=colors
            )
            for at in autotexts:
                at.set_color(TEXT)
                at.set_fontsize(7)
            ax1.legend(
                wedges, counts.index,
                loc="lower center", bbox_to_anchor=(0.5, -0.28),
                ncol=2, fontsize=6.5,
                facecolor=SURFACE, edgecolor=BORDER,
                labelcolor=TEXT
            )
        else:
            ax1.text(0.5, 0.5, "No attacks detected",
                     ha='center', va='center',
                     transform=ax1.transAxes, color=TEXT_DIM, fontsize=9)
        ax1.set_title("Attack Distribution", color=TEXT, fontsize=9, pad=8)

        # ── 2. Bar chart ──────────────────────────────────────────────────────
        ax2 = fig.add_subplot(1, 3, 2)
        ax2.set_facecolor(SURFACE)
        if len(counts):
            sorted_counts = counts.sort_values()
            bar_colors = [ATTACK_COLORS.get(k, "#aaaaaa") for k in sorted_counts.index]
            bars = ax2.barh(sorted_counts.index, sorted_counts.values,
                            color=bar_colors, edgecolor=BG, linewidth=0.8)
            ax2.bar_label(bars, padding=3, color=TEXT, fontsize=7)
        ax2.set_title("Attack Counts", color=TEXT, fontsize=9, pad=8)
        ax2.tick_params(colors=TEXT, labelsize=7)
        ax2.spines[:].set_color(BORDER)
        ax2.set_facecolor(SURFACE)
        for spine in ax2.spines.values():
            spine.set_color(BORDER)
        ax2.xaxis.label.set_color(TEXT_DIM)

        # ── 3. Timeline ───────────────────────────────────────────────────────
        ax3 = fig.add_subplot(1, 3, 3)
        ax3.set_facecolor(SURFACE)
        if timestamps is not None and not timestamps.isna().all() and len(malicious):
            mal_times = timestamps[malicious.index].dropna()
            if len(mal_times):
                timeline = mal_times.dt.floor('1min').value_counts().sort_index()
                ax3.plot(timeline.index, timeline.values,
                         color=ACCENT2, linewidth=1.5)
                ax3.fill_between(timeline.index, timeline.values,
                                 alpha=0.2, color=ACCENT2)
                fig.autofmt_xdate(rotation=30)
                ax3.tick_params(colors=TEXT, labelsize=6)
            else:
                ax3.text(0.5, 0.5, "No timestamp data",
                         ha='center', va='center',
                         transform=ax3.transAxes, color=TEXT_DIM, fontsize=9)
        else:
            ax3.text(0.5, 0.5, "No timestamp\ndata available",
                     ha='center', va='center',
                     transform=ax3.transAxes, color=TEXT_DIM, fontsize=9)
        ax3.set_title("Attacks Over Time", color=TEXT, fontsize=9, pad=8)
        for spine in ax3.spines.values():
            spine.set_color(BORDER)
        ax3.tick_params(colors=TEXT, labelsize=7)

        canvas = FigureCanvasTkAgg(fig, master=self)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)