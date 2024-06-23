import tkinter as tk
from tkinter import ttk  # Import ttk from tkinter
from tkinter import messagebox
import re
import random
import string

# Global variables
password_history = []
custom_criteria = {
    'min_length': 8,
    'lowercase': True,
    'uppercase': True,
    'digits': True,
    'special_chars': True
}

def check_password_strength(password):
    # Customizable criteria
    length_criteria = len(password) >= custom_criteria['min_length']
    lower_criteria = custom_criteria['lowercase'] and (re.search("[a-z]", password) is not None)
    upper_criteria = custom_criteria['uppercase'] and (re.search("[A-Z]", password) is not None)
    digit_criteria = custom_criteria['digits'] and (re.search("[0-9]", password) is not None)
    special_criteria = custom_criteria['special_chars'] and (re.search("[@#$%^&+=]", password) is not None)
    
    # Initialize strength score
    strength_score = sum([length_criteria, lower_criteria, upper_criteria, digit_criteria, special_criteria])
    
    # Determine strength level
    if strength_score == 5:
        strength = "Very Strong"
    elif strength_score == 4:
        strength = "Strong"
    elif strength_score == 3:
        strength = "Moderate"
    elif strength_score == 2:
        strength = "Weak"
    else:
        strength = "Very Weak"
    
    return strength, strength_score

def evaluate_password():
    password = password_entry.get()
    if password in password_history:
        messagebox.showwarning("Warning", "This password has been used before. Please choose a different one.")
        return
    strength, score = check_password_strength(password)
    strength_meter['value'] = score * 20  # update the progress bar
    result_label.config(text=f"Strength: {strength}")
    password_history.append(password)

def generate_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(12))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

def toggle_password_visibility():
    if password_entry.cget('show') == '':
        password_entry.config(show='*')
        toggle_button.config(text='Show')
    else:
        password_entry.config(show='')
        toggle_button.config(text='Hide')

def save_password():
    password = password_entry.get()
    if password:
        with open("passwords.txt", "a") as file:
            file.write(f"{password}\n")
        messagebox.showinfo("Success", "Password saved successfully.")

def open_criteria_window():
    criteria_window = tk.Toplevel(root)
    criteria_window.title("Customize Criteria")

    tk.Label(criteria_window, text="Minimum Length:").grid(row=0, column=0, padx=10, pady=10)
    min_length_entry = tk.Entry(criteria_window, width=5)
    min_length_entry.insert(0, str(custom_criteria['min_length']))
    min_length_entry.grid(row=0, column=1, padx=10, pady=10)

    def update_criteria():
        custom_criteria['min_length'] = int(min_length_entry.get())
        custom_criteria['lowercase'] = lowercase_var.get()
        custom_criteria['uppercase'] = uppercase_var.get()
        custom_criteria['digits'] = digits_var.get()
        custom_criteria['special_chars'] = special_chars_var.get()
        criteria_window.destroy()

    lowercase_var = tk.BooleanVar(value=custom_criteria['lowercase'])
    lowercase_check = tk.Checkbutton(criteria_window, text="Require Lowercase Letters", variable=lowercase_var)
    lowercase_check.grid(row=1, column=0, padx=10, pady=10, columnspan=2)
    
    uppercase_var = tk.BooleanVar(value=custom_criteria['uppercase'])
    uppercase_check = tk.Checkbutton(criteria_window, text="Require Uppercase Letters", variable=uppercase_var)
    uppercase_check.grid(row=2, column=0, padx=10, pady=10, columnspan=2)
    
    digits_var = tk.BooleanVar(value=custom_criteria['digits'])
    digits_check = tk.Checkbutton(criteria_window, text="Require Digits", variable=digits_var)
    digits_check.grid(row=3, column=0, padx=10, pady=10, columnspan=2)
    
    special_chars_var = tk.BooleanVar(value=custom_criteria['special_chars'])
    special_chars_check = tk.Checkbutton(criteria_window, text="Require Special Characters", variable=special_chars_var)
    special_chars_check.grid(row=4, column=0, padx=10, pady=10, columnspan=2)

    save_button = tk.Button(criteria_window, text="Save", command=update_criteria)
    save_button.grid(row=5, column=0, columnspan=2, pady=10)

# Create the main window
root = tk.Tk()
root.title("Password Strength Checker")

# Create and place the widgets
tk.Label(root, text="Enter Password:").grid(row=0, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show="*", width=30)
password_entry.grid(row=0, column=1, padx=10, pady=10)

toggle_button = tk.Button(root, text='Show', command=toggle_password_visibility)
toggle_button.grid(row=0, column=2, padx=10)

check_button = tk.Button(root, text="Check Strength", command=evaluate_password)
check_button.grid(row=1, column=0, columnspan=3, pady=10)

generate_button = tk.Button(root, text="Generate Password", command=generate_password)
generate_button.grid(row=2, column=0, columnspan=3, pady=10)

save_button = tk.Button(root, text="Save Password", command=save_password)
save_button.grid(row=3, column=0, columnspan=3, pady=10)

result_label = tk.Label(root, text="")
result_label.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

criteria_button = tk.Button(root, text="Customize Criteria", command=open_criteria_window)
criteria_button.grid(row=5, column=0, columnspan=3, pady=10)

# Use ttk.Progressbar for the strength meter
strength_meter = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate", maximum=100)
strength_meter.grid(row=6, column=0, columnspan=3, pady=10)

# Run the main event loop
root.mainloop()
