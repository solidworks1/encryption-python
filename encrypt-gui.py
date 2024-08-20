"""
Copyright © 2024 t.me/solid_marketing
This code is the property of Solid Marketing. Unauthorized copying,
modification, distribution, or other use of this code is prohibited.
"""



import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import base64
from hashlib import sha256
import os

# t.me/solidmarketing

def generate_key(password):
    key = sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])

def encrypt_file(file_path, password, lang):
    key = generate_key(password)
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as file:
        original_data = file.read()
    
    encrypted_data = fernet.encrypt(original_data)
    
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypted_data)
    
    os.remove(file_path)
    return messages[lang]['file_encrypted'].format(encrypted_file_path)

def encrypt_folder(folder_path, password, lang):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            encrypt_file(file_path, password, lang)
    return messages[lang]['folder_encrypted'].format(folder_path)

def decrypt_file(encrypted_file_path, password, lang):
    key = generate_key(password)
    fernet = Fernet(key)
    
    try:
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = file.read()
        
        decrypted_data = fernet.decrypt(encrypted_data)
        
        decrypted_file_path = encrypted_file_path.replace('.encrypted', '')
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)
        
        return messages[lang]['file_decrypted'].format(decrypted_file_path)
    
    except Exception as e:
        print(f"Decryption error: {e}")  # For debugging purposes
        return messages[lang]['wrong_password']

def select_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

def select_folder():
    folder_path = filedialog.askdirectory()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, folder_path)

def process_action(lang):
    action = action_var.get()
    password = password_entry.get()
    file_path = file_entry.get()

    if not password:
        messagebox.showerror(messages[lang]['error'], messages[lang]['no_password'])
        return

    if action == messages[lang]['encrypt']:
        if os.path.isfile(file_path):
            result = encrypt_file(file_path, password, lang)
        elif os.path.isdir(file_path):
            result = encrypt_folder(file_path, password, lang)
        else:
            messagebox.showerror(messages[lang]['error'], messages[lang]['invalid_path'])
            return
        messagebox.showinfo(messages[lang]['result'], result)
        
    elif action == messages[lang]['decrypt']:
        if os.path.isfile(file_path):
            result = decrypt_file(file_path, password, lang)
        else:
            messagebox.showerror(messages[lang]['error'], messages[lang]['invalid_path'])
            return
        messagebox.showinfo(messages[lang]['result'], result)

    if messagebox.askyesno(messages[lang]['continue'], messages[lang]['another_action']):
        file_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        action_var.set(messages[lang]['encrypt'])
    else:
        root.destroy()

def set_language():
    lang = lang_var.get()
    if lang not in messages:
        messagebox.showerror("Error", "Invalid language selection!")
        return
    lang_window.destroy()
    main_program(lang)

def main_program(lang):
    global file_entry, password_entry, action_var, root

    root = tk.Tk()
    root.title(messages[lang]['title'])

    tk.Label(root, text=messages[lang]['file_folder_path']).grid(row=0, column=0, padx=10, pady=10)
    file_entry = tk.Entry(root, width=50)
    file_entry.grid(row=0, column=1, padx=10, pady=10)
    tk.Button(root, text=messages[lang]['select_file'], command=select_file).grid(row=0, column=2, padx=10, pady=10)
    tk.Button(root, text=messages[lang]['select_folder'], command=select_folder).grid(row=0, column=3, padx=10, pady=10)

    tk.Label(root, text=messages[lang]['password']).grid(row=1, column=0, padx=10, pady=10)
    password_entry = tk.Entry(root, show="*", width=50)
    password_entry.grid(row=1, column=1, padx=10, pady=10)

    action_var = tk.StringVar(value=messages[lang]['encrypt'])
    tk.Radiobutton(root, text=messages[lang]['encrypt'], variable=action_var, value=messages[lang]['encrypt']).grid(row=2, column=0, padx=10, pady=10)
    tk.Radiobutton(root, text=messages[lang]['decrypt'], variable=action_var, value=messages[lang]['decrypt']).grid(row=2, column=1, padx=10, pady=10)

    tk.Button(root, text=messages[lang]['start_action'], command=lambda: process_action(lang)).grid(row=3, column=0, columnspan=4, padx=10, pady=10)

    root.mainloop()

# Language messages
messages = {
    'en': {
        'title': 'Encryption and Decryption',
        'file_folder_path': 'File/Folder path:',
        'select_file': 'Select File',
        'select_folder': 'Select Folder',
        'password': 'Password:',
        'encrypt': 'Encrypt',
        'decrypt': 'Decrypt',
        'start_action': 'Start Action',
        'error': 'Error',
        'no_password': 'No password entered!',
        'invalid_path': 'Invalid file or folder path!',
        'result': 'Result',
        'file_encrypted': 'File encrypted: {}',
        'folder_encrypted': 'Folder encrypted: {}',
        'wrong_password': 'Incorrect password!',
        'file_decrypted': 'File decrypted: {}',
        'continue': 'Continue',
        'another_action': 'Do you want to perform another action?'
    },
    'de': {
        'title': 'Verschlüsselung und Entschlüsselung',
        'file_folder_path': 'Datei/Ordner Pfad:',
        'select_file': 'Datei auswählen',
        'select_folder': 'Ordner auswählen',
        'password': 'Passwort:',
        'encrypt': 'Verschlüsseln',
        'decrypt': 'Entschlüsseln',
        'start_action': 'Aktion starten',
        'error': 'Fehler',
        'no_password': 'Kein Passwort eingegeben!',
        'invalid_path': 'Ungültiger Datei- oder Ordnerpfad!',
        'result': 'Ergebnis',
        'file_encrypted': 'Datei verschlüsselt: {}',
        'folder_encrypted': 'Ordner verschlüsselt: {}',
        'wrong_password': 'Falsches Passwort!',
        'file_decrypted': 'Datei entschlüsselt: {}',
        'continue': 'Weiter',
        'another_action': 'Möchten Sie eine weitere Aktion ausführen?'
    },
    'ru': {
        'title': 'Шифрование и Расшифровка',
        'file_folder_path': 'Путь к файлу/папке:',
        'select_file': 'Выбрать файл',
        'select_folder': 'Выбрать папку',
        'password': 'Пароль:',
        'encrypt': 'Зашифровать',
        'decrypt': 'Расшифровать',
        'start_action': 'Начать действие',
        'error': 'Ошибка',
        'no_password': 'Пароль не введен!',
        'invalid_path': 'Недопустимый путь к файлу или папке!',
        'result': 'Результат',
        'file_encrypted': 'Файл зашифрован: {}',
        'folder_encrypted': 'Папка зашифрована: {}',
        'wrong_password': 'Неправильный пароль!',
        'file_decrypted': 'Файл расшифрован: {}',
        'continue': 'Продолжить',
        'another_action': 'Хотите выполнить другое действие?'
    },
    'zh': {
        'title': '加密与解密',
        'file_folder_path': '文件/文件夹路径:',
        'select_file': '选择文件',
        'select_folder': '选择文件夹',
        'password': '密码:',
        'encrypt': '加密',
        'decrypt': '解密',
        'start_action': '开始操作',
        'error': '错误',
        'no_password': '未输入密码!',
        'invalid_path': '无效的文件或文件夹路径!',
        'result': '结果',
        'file_encrypted': '文件已加密: {}',
        'folder_encrypted': '文件夹已加密: {}',
        'wrong_password': '密码错误!',
        'file_decrypted': '文件已解密: {}',
        'continue': '继续',
        'another_action': '您想执行另一个操作吗?'
    },
    'ar': {
        'title': 'التشفير وفك التشفير',
        'file_folder_path': 'مسار الملف/المجلد:',
        'select_file': 'اختر ملف',
        'select_folder': 'اختر مجلد',
        'password': 'كلمة المرور:',
        'encrypt': 'تشفير',
        'decrypt': 'فك التشفير',
        'start_action': 'ابدأ الإجراء',
        'error': 'خطأ',
        'no_password': 'لم يتم إدخال كلمة مرور!',
        'invalid_path': 'مسار الملف أو المجلد غير صالح!',
        'result': 'النتيجة',
        'file_encrypted': 'تم تشفير الملف: {}',
        'folder_encrypted': 'تم تشفير المجلد: {}',
        'wrong_password': 'كلمة المرور غير صحيحة!',
        'file_decrypted': 'تم فك تشفير الملف: {}',
        'continue': 'استمر',
        'another_action': 'هل تريد تنفيذ إجراء آخر؟'
    },
    'hi': {
        'title': 'एन्क्रिप्शन और डिक्रिप्शन',
        'file_folder_path': 'फ़ाइल/फ़ोल्डर पथ:',
        'select_file': 'फ़ाइल चुनें',
        'select_folder': 'फ़ोल्डर चुनें',
        'password': 'पासवर्ड:',
        'encrypt': 'एन्क्रिप्ट करें',
        'decrypt': 'डिक्रिप्ट करें',
        'start_action': 'कार्य प्रारंभ करें',
        'error': 'त्रुटि',
        'no_password': 'कोई पासवर्ड नहीं डाला गया!',
        'invalid_path': 'अमान्य फ़ाइल या फ़ोल्डर पथ!',
        'result': 'परिणाम',
        'file_encrypted': 'फ़ाइल एन्क्रिप्ट की गई: {}',
        'folder_encrypted': 'फ़ोल्डर एन्क्रिप्ट किया गया: {}',
        'wrong_password': 'गलत पासवर्ड!',
        'file_decrypted': 'फ़ाइल डिक्रिप्ट की गई: {}',
        'continue': 'जारी रखें',
        'another_action': 'क्या आप एक और क्रिया करना चाहते हैं?'
    }
}

# Language selection window
lang_window = tk.Tk()
lang_window.title("Select Language")

tk.Label(lang_window, text="Choose your language:").pack(pady=10)
lang_var = tk.StringVar(value='en')
tk.Radiobutton(lang_window, text="English", variable=lang_var, value='en').pack(anchor='w')
tk.Radiobutton(lang_window, text="Русский", variable=lang_var, value='ru').pack(anchor='w')
tk.Radiobutton(lang_window, text="Deutsch", variable=lang_var, value='de').pack(anchor='w')
tk.Radiobutton(lang_window, text="中文", variable=lang_var, value='zh').pack(anchor='w')
tk.Radiobutton(lang_window, text="العربية", variable=lang_var, value='ar').pack(anchor='w')
tk.Radiobutton(lang_window, text="हिन्दी", variable=lang_var, value='hi').pack(anchor='w')

tk.Button(lang_window, text="OK", command=set_language).pack(pady=10)

lang_window.mainloop()

# t.me/solidmarketing

# t.me/solidmarketing

# t.me/solidmarketing

# t.me/solidmarketing
