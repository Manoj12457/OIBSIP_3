import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import random
import string
import pyperclip

class PasswordGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")

        self.length_var = tk.IntVar()
        self.uppercase_var = tk.BooleanVar()
        self.numbers_var = tk.BooleanVar()
        self.symbols_var = tk.BooleanVar()
        self.password_var = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        # Length Label and Entry
        length_label = tk.Label(self.root, text="Password Length:")
        length_label.grid(row=0, column=0, pady=10, padx=10, sticky=tk.W)

        length_entry = tk.Entry(self.root, textvariable=self.length_var)
        length_entry.grid(row=0, column=1, pady=10, padx=10, sticky=tk.W)
        length_entry.insert(0, "12")  # Default length

        # Uppercase Checkbox
        uppercase_checkbox = tk.Checkbutton(self.root, text="Include Uppercase", variable=self.uppercase_var)
        uppercase_checkbox.grid(row=1, column=0, pady=5, padx=10, sticky=tk.W)

        # Numbers Checkbox
        numbers_checkbox = tk.Checkbutton(self.root, text="Include Numbers", variable=self.numbers_var)
        numbers_checkbox.grid(row=1, column=1, pady=5, padx=10, sticky=tk.W)

        # Symbols Checkbox
        symbols_checkbox = tk.Checkbutton(self.root, text="Include Symbols", variable=self.symbols_var)
        symbols_checkbox.grid(row=1, column=2, pady=5, padx=10, sticky=tk.W)

        # Generate Button
        generate_button = tk.Button(self.root, text="Generate Password", command=self.generate_password)
        generate_button.grid(row=2, column=0, columnspan=3, pady=10, padx=10)

        # Generated Password Label and Copy Button
        password_label = tk.Label(self.root, text="Generated Password:")
        password_label.grid(row=3, column=0, pady=5, padx=10, sticky=tk.W)

        password_entry = tk.Entry(self.root, textvariable=self.password_var, state="readonly")
        password_entry.grid(row=3, column=1, columnspan=2, pady=5, padx=10, sticky=tk.W)

        copy_button = tk.Button(self.root, text="Copy to Clipboard", command=self.copy_to_clipboard)
        copy_button.grid(row=4, column=0, columnspan=3, pady=10, padx=10)

    def generate_password(self):
        length = self.length_var.get()

        if length <= 0:
            messagebox.showerror("Error", "Password length must be greater than 0.")
            return

        characters = string.ascii_lowercase
        characters += string.ascii_uppercase if self.uppercase_var.get() else ""
        characters += string.digits if self.numbers_var.get() else ""
        characters += string.punctuation if self.symbols_var.get() else ""

        if not any((self.uppercase_var.get(), self.numbers_var.get(), self.symbols_var.get())):
            messagebox.showwarning("Warning", "Select at least one option for password complexity.")
            return

        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_var.set(password)

    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "Generate a password first.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()
