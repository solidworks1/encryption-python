"""
Copyright © 2024 t.me/solid_marketing
This code is the property of Solid Marketing. Unauthorized copying,
modification, distribution, or other use of this code is prohibited.
"""

# t.me/solidmarketing

import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import base64
import os
from hashlib import sha256
import getpass
import sys
 
# t.me/solidmarketing

# Dictionary for translations
translations = {
    'en': {
        'program_started': 'Program started.',
        'encrypt_or_decrypt': 'Would you like to encrypt or decrypt? (encrypt/decrypt): ',
        'encrypt': 'encrypt',
        'decrypt': 'decrypt',
        'visible_password': 'Should the password be visible? (y/n): ',
        'enter_password': 'Please enter the password: ',
        'confirm_password': 'Please confirm the password: ',
        'passwords_do_not_match': 'Passwords do not match. Encryption process aborted.',
        'password_set': 'Password successfully set.',
        'enter_path': 'Please enter the path of the file or folder to encrypt: ',
        'entered_path': 'Entered path: {}',
        'initial_confirmation': 'Are you sure you want to encrypt {}? (y/n): ',
        'process_canceled': 'Encryption process canceled.',
        'final_confirmation': '{} will be encrypted. Do you approve? (y/n): ',
        'invalid_path': 'Invalid file or folder path. Encryption process aborted.',
        'encryption_completed': 'Encryption process completed.',
        'password_entered': 'Password entered.',
        'enter_decrypt_path': 'Please enter the path of the file to decrypt: ',
        'incorrect_location': 'Incorrect or missing location, would you like to try again? (y/n): ',
        'confirm_info': 'Do you confirm this information? (y/n): ',
        'decryption_completed': 'Decryption process completed.',
        'file_encrypted': 'File encrypted: {}',
        'folder_encrypted': 'Folder encrypted: {}',
        'incorrect_password': 'Incorrect password!',
        'file_decrypted': 'File decrypted: {}'
    },
    'ru': {
        'program_started': 'Программа запущена.',
        'encrypt_or_decrypt': 'Вы хотите зашифровать или расшифровать? (encrypt/decrypt): ',
        'encrypt': 'зашифровать',
        'decrypt': 'расшифровать',
        'visible_password': 'Пароль должен быть виден? (y/n): ',
        'enter_password': 'Пожалуйста, введите пароль: ',
        'confirm_password': 'Пожалуйста, подтвердите пароль: ',
        'passwords_do_not_match': 'Пароли не совпадают. Процесс шифрования прерван.',
        'password_set': 'Пароль успешно установлен.',
        'enter_path': 'Пожалуйста, введите путь к файлу или папке для шифрования: ',
        'entered_path': 'Введенный путь: {}',
        'initial_confirmation': 'Вы уверены, что хотите зашифровать {}? (y/n): ',
        'process_canceled': 'Процесс шифрования отменен.',
        'final_confirmation': '{} будет зашифрован. Вы подтверждаете? (y/n): ',
        'invalid_path': 'Недействительный путь к файлу или папке. Процесс шифрования прерван.',
        'encryption_completed': 'Процесс шифрования завершен.',
        'password_entered': 'Пароль введен.',
        'enter_decrypt_path': 'Пожалуйста, введите путь к файлу для расшифровки: ',
        'incorrect_location': 'Неправильное или отсутствующее местоположение, хотите попробовать еще раз? (y/n): ',
        'confirm_info': 'Вы подтверждаете эту информацию? (y/n): ',
        'decryption_completed': 'Процесс расшифровки завершен.',
        'file_encrypted': 'Файл зашифрован: {}',
        'folder_encrypted': 'Папка зашифрована: {}',
        'incorrect_password': 'Неверный пароль!',
        'file_decrypted': 'Файл расшифрован: {}'
    },
    'de': {
        'program_started': 'Programm gestartet.',
        'encrypt_or_decrypt': 'Möchten Sie verschlüsseln oder entschlüsseln? (encrypt/decrypt): ',
        'encrypt': 'verschlüsseln',
        'decrypt': 'entschlüsseln',
        'visible_password': 'Soll das Passwort sichtbar sein? (y/n): ',
        'enter_password': 'Bitte geben Sie das Passwort ein: ',
        'confirm_password': 'Bitte bestätigen Sie das Passwort: ',
        'passwords_do_not_match': 'Passwörter stimmen nicht überein. Verschlüsselung abgebrochen.',
        'password_set': 'Passwort erfolgreich gesetzt.',
        'enter_path': 'Bitte geben Sie den Pfad der Datei oder des Ordners ein, der verschlüsselt werden soll: ',
        'entered_path': 'Eingegebener Pfad: {}',
        'initial_confirmation': 'Sind Sie sicher, dass Sie {} verschlüsseln möchten? (y/n): ',
        'process_canceled': 'Verschlüsselungsvorgang abgebrochen.',
        'final_confirmation': '{} wird verschlüsselt. Stimmen Sie zu? (y/n): ',
        'invalid_path': 'Ungültiger Datei- oder Ordnerpfad. Verschlüsselung abgebrochen.',
        'encryption_completed': 'Verschlüsselung abgeschlossen.',
        'password_entered': 'Passwort eingegeben.',
        'enter_decrypt_path': 'Bitte geben Sie den Pfad der Datei ein, die entschlüsselt werden soll: ',
        'incorrect_location': 'Falscher oder fehlender Ort, möchten Sie es erneut versuchen? (y/n): ',
        'confirm_info': 'Bestätigen Sie diese Informationen? (y/n): ',
        'decryption_completed': 'Entschlüsselung abgeschlossen.',
        'file_encrypted': 'Datei verschlüsselt: {}',
        'folder_encrypted': 'Ordner verschlüsselt: {}',
        'incorrect_password': 'Falsches Passwort!',
        'file_decrypted': 'Datei entschlüsselt: {}'
    },
    'zh': {
        'program_started': '程序启动。',
        'encrypt_or_decrypt': '您想加密还是解密？（encrypt/decrypt）：',
        'encrypt': '加密',
        'decrypt': '解密',
        'visible_password': '密码是否可见？（y/n）：',
        'enter_password': '请输入密码：',
        'confirm_password': '请确认密码：',
        'passwords_do_not_match': '密码不匹配。加密过程中止。',
        'password_set': '密码设置成功。',
        'enter_path': '请输入要加密的文件或文件夹的路径：',
        'entered_path': '输入的路径：{}',
        'initial_confirmation': '您确定要加密 {} 吗？（y/n）：',
        'process_canceled': '加密过程取消。',
        'final_confirmation': '{} 将被加密。你同意吗？（y/n）：',
        'invalid_path': '无效的文件或文件夹路径。加密过程中止。',
        'encryption_completed': '加密过程完成。',
        'password_entered': '密码已输入。',
        'enter_decrypt_path': '请输入要解密的文件路径：',
        'incorrect_location': '位置不正确或缺失，您想重试吗？（y/n）：',
        'confirm_info': '您确认这些信息吗？（y/n）：',
        'decryption_completed': '解密过程完成。',
        'file_encrypted': '文件已加密：{}',
        'folder_encrypted': '文件夹已加密：{}',
        'incorrect_password': '密码不正确！',
        'file_decrypted': '文件已解密：{}'
    },
    'ar': {
        'program_started': 'تم بدء البرنامج.',
        'encrypt_or_decrypt': 'هل ترغب في التشفير أم فك التشفير؟ (encrypt/decrypt): ',
        'encrypt': 'تشفير',
        'decrypt': 'فك التشفير',
        'visible_password': 'هل يجب أن تكون كلمة المرور مرئية؟ (y/n): ',
        'enter_password': 'يرجى إدخال كلمة المرور: ',
        'confirm_password': 'يرجى تأكيد كلمة المرور: ',
        'passwords_do_not_match': 'كلمتا المرور غير متطابقتين. تم إيقاف عملية التشفير.',
        'password_set': 'تم تعيين كلمة المرور بنجاح.',
        'enter_path': 'يرجى إدخال مسار الملف أو المجلد للتشفير: ',
        'entered_path': 'المسار المدخل: {}',
        'initial_confirmation': 'هل أنت متأكد أنك تريد تشفير {}؟ (y/n): ',
        'process_canceled': 'تم إلغاء عملية التشفير.',
        'final_confirmation': 'سيتم تشفير {}. هل توافق؟ (y/n): ',
        'invalid_path': 'مسار الملف أو المجلد غير صالح. تم إيقاف عملية التشفير.',
        'encryption_completed': 'تمت عملية التشفير.',
        'password_entered': 'تم إدخال كلمة المرور.',
        'enter_decrypt_path': 'يرجى إدخال مسار الملف لفك التشفير: ',
        'incorrect_location': 'الموقع غير صحيح أو مفقود، هل ترغب في المحاولة مرة أخرى؟ (y/n): ',
        'confirm_info': 'هل تؤكد هذه المعلومات؟ (y/n): ',
        'decryption_completed': 'تمت عملية فك التشفير.',
        'file_encrypted': 'تم تشفير الملف: {}',
        'folder_encrypted': 'تم تشفير المجلد: {}',
        'incorrect_password': 'كلمة المرور غير صحيحة!',
        'file_decrypted': 'تم فك تشفير الملف: {}'
    },
    'hi': {
        'program_started': 'प्रोग्राम शुरू हो गया।',
        'encrypt_or_decrypt': 'क्या आप एन्क्रिप्ट या डीक्रिप्ट करना चाहेंगे? (encrypt/decrypt): ',
        'encrypt': 'एन्क्रिप्ट',
        'decrypt': 'डीक्रिप्ट',
        'visible_password': 'क्या पासवर्ड को दृश्य में होना चाहिए? (y/n): ',
        'enter_password': 'कृपया पासवर्ड दर्ज करें: ',
        'confirm_password': 'कृपया पासवर्ड की पुष्टि करें: ',
        'passwords_do_not_match': 'पासवर्ड मेल नहीं खाते। एन्क्रिप्शन प्रक्रिया रद्द कर दी गई।',
        'password_set': 'पासवर्ड सफलतापूर्वक सेट कर दिया गया।',
        'enter_path': 'कृपया एन्क्रिप्ट करने के लिए फ़ाइल या फ़ोल्डर का पथ दर्ज करें: ',
        'entered_path': 'दर्ज किया गया पथ: {}',
        'initial_confirmation': 'क्या आप सुनिश्चित हैं कि आप {} एन्क्रिप्ट करना चाहते हैं? (y/n): ',
        'process_canceled': 'एन्क्रिप्शन प्रक्रिया रद्द कर दी गई।',
        'final_confirmation': '{} एन्क्रिप्ट किया जाएगा। क्या आप सहमत हैं? (y/n): ',
        'invalid_path': 'अवैध फ़ाइल या फ़ोल्डर पथ। एन्क्रिप्शन प्रक्रिया रद्द कर दी गई।',
        'encryption_completed': 'एन्क्रिप्शन प्रक्रिया पूरी हुई।',
        'password_entered': 'पासवर्ड दर्ज किया गया।',
        'enter_decrypt_path': 'कृपया डीक्रिप्ट करने के लिए फ़ाइल का पथ दर्ज करें: ',
        'incorrect_location': 'गलत या गायब स्थान, क्या आप फिर से प्रयास करना चाहेंगे? (y/n): ',
        'confirm_info': 'क्या आप इस जानकारी की पुष्टि करते हैं? (y/n): ',
        'decryption_completed': 'डीक्रिप्शन प्रक्रिया पूरी हुई।',
        'file_encrypted': 'फ़ाइल एन्क्रिप्ट की गई: {}',
        'folder_encrypted': 'फ़ोल्डर एन्क्रिप्ट किया गया: {}',
        'incorrect_password': 'गलत पासवर्ड!',
        'file_decrypted': 'फ़ाइल डीक्रिप्ट की गई: {}'
    }
}

# t.me/solidmarketing

import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import base64
import os
from hashlib import sha256
import getpass
import sys

# Dictionary for translations (same as before)

def translate(key, lang='en'):
    return translations[lang].get(key, key)

def generate_key(password):
    key = sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])

def encrypt_file(file_path, password):
    key = generate_key(password)
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as file:
        original_data = file.read()
    
    encrypted_data = fernet.encrypt(original_data)
    
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypted_data)
    
    os.remove(file_path)
    print(translate('file_encrypted').format(encrypted_file_path))

def encrypt_folder(folder_path, password):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            encrypt_file(file_path, password)
    print(translate('folder_encrypted').format(folder_path))

def decrypt_file(encrypted_file_path, password):
    key = generate_key(password)
    fernet = Fernet(key)
    
    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()
    
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except:
        print(translate('incorrect_password'))
        return
    
    decrypted_file_path = encrypted_file_path.replace('.encrypted', '')
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)
    
    print(translate('file_decrypted').format(decrypted_file_path))

def get_confirmation(prompt):
    while True:
        response = input(prompt).strip().lower()
        if response in ['y', 'yes', 'n', 'no']:
            return response
        print(translate('visible_password'))

def perform_action(lang):
    while True:
        action = input(translate('encrypt_or_decrypt', lang)).strip().lower()
        if action in [translate('encrypt', lang), translate('decrypt', lang)]:
            break
        print(translate('encrypt_or_decrypt', lang))
    
    if action == translate('encrypt', lang):
        # Get password visibility preference
        while True:
            show_password = input(translate('visible_password', lang)).strip().lower()
            if show_password in ['y', 'n']:
                break
            print(translate('visible_password', lang))
        
        if show_password == 'y':
            password = input(translate('enter_password', lang))
            confirm_password = input(translate('confirm_password', lang))
        else:
            password = getpass.getpass(translate('enter_password', lang))
            confirm_password = getpass.getpass(translate('confirm_password', lang))
        
        if password != confirm_password:
            print(translate('passwords_do_not_match', lang))
            sys.exit(1)

        print(translate('password_set', lang))

        # Get file or folder path from the user
        path = input(translate('enter_path', lang))
        print(translate('entered_path', lang).format(path))

        # Get initial confirmation
        first_confirmation = get_confirmation(translate('initial_confirmation', lang).format(path))
        if first_confirmation != 'y':
            print(translate('process_canceled', lang))
            sys.exit(1)
        
        # Get final confirmation
        second_confirmation = get_confirmation(translate('final_confirmation', lang).format(path))
        if second_confirmation != 'y':
            print(translate('process_canceled', lang))
            sys.exit(1)

        if os.path.isfile(path):
            encrypt_file(path, password)
        elif os.path.isdir(path):
            encrypt_folder(path, password)
        else:
            print(translate('invalid_path', lang))
            sys.exit(1)
        
        print(translate('encryption_completed', lang))
    
    elif action == translate('decrypt', lang):
        # Get password visibility preference
        while True:
            show_password = input(translate('visible_password', lang)).strip().lower()
            if show_password in ['y', 'n']:
                break
            print(translate('visible_password', lang))
        
        # Get the password
        if show_password == 'y':
            password = input(translate('enter_password', lang))
        else:
            password = getpass.getpass(translate('enter_password', lang))
        
        print(translate('password_entered', lang))
        
        while True:
            # Get encrypted file path from the user
            path = input(translate('enter_decrypt_path', lang))
            print(translate('entered_path', lang).format(path))

            # Check if the file exists
            if not os.path.isfile(path):
                retry = get_confirmation(translate('incorrect_location', lang))
                if retry != 'y':
                    print(translate('process_canceled', lang))
                    sys.exit(1)
            else:
                break

        # Get confirmation
        confirmation = get_confirmation(translate('confirm_info', lang))
        if confirmation != 'y':
            print(translate('process_canceled', lang))
            sys.exit(1)
        
        # Decrypt the file
        decrypt_file(path, password)
        print(translate('decryption_completed', lang))

def main():
    print(translate('program_started'))
    
    while True:
        # Language selection
        while True:
            lang = input("Select your language \nEnglish(en) \nРусский(ru) \nDeutsch(de) \n中文(zh) \nعربي(ar) \nहिंदी(hi)): ").strip().lower()
            if lang in translations:
                break
            print("Please select a valid language code.")

        perform_action(lang)

        while True:
            retry = get_confirmation("Do you want to perform another action? (y/n): ")
            if retry == 'y':
                break
            elif retry == 'n':
                print("Exiting the program.")
                sys.exit(0)
            else:
                print("Please enter 'y' or 'n'.")

if __name__ == '__main__':
    main()


# t.me/solidmarketing