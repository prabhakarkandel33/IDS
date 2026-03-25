import sys
import os

# make sure imports work from any working directory
sys.path.insert(0, os.path.dirname(__file__))

from ui.main_window import MainWindow

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "xgb_ids_model.pkl")

if __name__ == "__main__":
    if not os.path.exists(MODEL_PATH):
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Model not found",
            f"Could not find model file at:\n{MODEL_PATH}\n\n"
            "Please copy xgb_ids_model.pkl into the model/ folder."
        )
        sys.exit(1)

    app = MainWindow(MODEL_PATH)
    app.mainloop()