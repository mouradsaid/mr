import os
import sys
import subprocess
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from tkinter import filedialog
from PIL import Image, ImageTk
import ctypes
from ctypes import wintypes
import winreg
import wmi
import configparser
from cryptography.fernet import Fernet


class MiresStore:
    def __init__(self, master):
        self.master = master
        self.master.title("MiresStore")
        self.master.geometry("434x500")
        self.master.resizable(False, False)
        self.master.iconbitmap(self.resource_path("dt\\22218foxface_98828.ico"))
        # self.master.iconbitmap(os.path.join(self.get_base_path(),"dt\\22218foxface_98828.ico"))
        
        self.key = b'Fo-Xyo7gXMVAh-0uSXZT1vZh7fMaPXFMV-QidULX9bM='
        self.password = self.read_data()[1]
        self.approved_programs_folder = self.read_data()[2]
        self.serial = self.read_data()[0]
        
        self.serial_conf(self.master)
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(expand=True, fill="both")

        self.install_tab = ttk.Frame(self.notebook)
        self.uninstall_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        self.change_password_tab = ttk.Frame(self.notebook)
        self.infotab = ttk.Frame(self.notebook)

        self.notebook.add(self.install_tab, text="Install Programs")
        self.notebook.add(self.uninstall_tab, text="Uninstall Programs")
        self.notebook.add(self.settings_tab, text="Settings")
        self.notebook.add(self.change_password_tab, text="Change Password")
        self.notebook.add(self.infotab, text="info")

        self.create_scrollable_frame(self.install_tab)
        self.create_scrollable_frame(self.uninstall_tab)

        self.load_approved_programs(self.install_tab, "install")
        self.load_installed_programs(self.uninstall_tab, "uninstall")


        self.create_settings_tab()
        self.create_change_password_tab()
        self.info_tab()
        
    def serial_conf(self,rt):
        c = wmi.WMI()
        for bios in c.Win32_BIOS():
            bios = bios.SerialNumber
        if bios != self.serial:
            rt.destroy()
        
    def get_base_path(self):
        if getattr(sys, 'frozen', False):
            return os.path.dirname(sys.executable)
        else:
            return os.path.dirname(os.path.abspath(__file__)) 
             
    def resource_path(self,relative_path):
        if hasattr(sys, '_MEIPASS'):
            return os.path.join(sys._MEIPASS, relative_path)
        return os.path.join(os.path.abspath("."), relative_path)         


    def read_data(self):
        try:
            data = []
            base_path = self.get_base_path()
            ini_file_path = os.path.join(base_path, "dt.ini.enc") 
            cipher = Fernet(self.key)
            
            # if not os.path.exists(ini_file_path):
            #     config = configparser.ConfigParser()
            #     config['Settings'] = {
            #         'bios': '',
            #         'password': '',
            #         'path': ''
            #     }
            #     with open(ini_file_path, 'w') as config_file:
            #         config.write(config_file)
            #     with open(ini_file_path, 'rb') as config_file:
            #         data_to_encrypt = config_file.read()
            #     encrypted_data = cipher.encrypt(data_to_encrypt)
            #     with open(ini_file_path, 'wb') as encrypted_file:
            #         encrypted_file.write(encrypted_data)
            #     return ['', '', '']


            with open(ini_file_path, "rb") as encrypted_file:
                encrypted_data = encrypted_file.read()
            decrypted_data = cipher.decrypt(encrypted_data).decode()
            config = configparser.ConfigParser()
            config.read_string(decrypted_data)

            if 'Settings' in config:
                bios = config['Settings'].get('bios', '').strip()
                password = config['Settings'].get('password', '').strip()
                path = config['Settings'].get('path', '').strip()
            else:
                raise Exception("Settings")

            if bios == "":
                c = wmi.WMI()
                for bios in c.Win32_BIOS():
                    bios = bios.SerialNumber

            data.append(bios)
            data.append(password)
            data.append(path)
  
            return data
        except Exception as e:
            messagebox.showerror("Error", f"{e}")
            return ["","",""]

    def read_config(self):
   
        try:
            base_path=self.get_base_path()
            with open(os.path.join(base_path, "password.txt"), "r") as file:
                path = file.readline().strip()
                if os.path.isdir(path):
                    return path
               
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read the configuration: {e}")
            return ""

    def create_scrollable_frame(self, tab):
        canvas = tk.Canvas(tab)
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        setattr(self, f"{tab}_canvas", canvas)
        setattr(self, f"{tab}_scrollable_frame", scrollable_frame)

    def load_approved_programs(self, tab, action): 
        try:
       
            scrollable_frame = getattr(self, f"{tab}_scrollable_frame")
            for widget in scrollable_frame.winfo_children():
                widget.destroy()
                
            programs = self.list_approved_programs()

            if programs:
                for program in programs:
                    row_frame = ttk.Frame(scrollable_frame) 
                    row_frame.pack(pady=5, padx=10, fill='x') 
                    program_label = tk.Label(row_frame, text=program, width=40, anchor='w') 
                    program_label.pack(side=tk.LEFT, padx=5) 
                    install_button = ttk.Button(row_frame, text="Install", command=lambda p=program: self.install_program(p)) 
                    install_button.pack(side=tk.LEFT, padx=5) 
            else:
                no_programs_label = tk.Label(scrollable_frame, text="No programs available to install.") 
                no_programs_label.pack(pady=20)

        except Exception as e:
            error_label = tk.Label(getattr(self, f"{tab}_scrollable_frame"), text=f"Error loading programs: {str(e)}", fg="red")
            error_label.pack(pady=20)

    def list_approved_programs(self):
        programs = [f for f in os.listdir(self.approved_programs_folder) if f.endswith('.exe') or f.endswith('.msi') or f.endswith('.bat')]
        return programs
    def install_program(self, program):
        program_path = os.path.join(self.approved_programs_folder, program)
        try:
            if program_path.endswith('.msi'):
                command = f'msiexec /i "{program_path}"'
            elif program_path.endswith('.exe'):
                command = f'"{program_path}"'
            elif program_path.endswith('.bat') or program_path.endswith('.cmd'):
                command = f'cmd /c "{program_path}"'
            else:
                raise ValueError(f"Unsupported file type: {program_path}")

            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo("Success", f"{program} installed successfully!")
            else:
                messagebox.showerror("Error", f"Error occurred while installing {program}: {result.stderr}")

        except Exception as e:
            messagebox.showerror("Error", f"Exception occurred: {e}")

    def load_installed_programs(self, tab, action): 
        try:
            scrollable_frame = getattr(self, f"{tab}_scrollable_frame")
            for widget in scrollable_frame.winfo_children():
                widget.destroy()
            programs = self.list_installed_programs()

            if programs:
                for program in programs:
                    row_frame = ttk.Frame(scrollable_frame) 
                    row_frame.pack(pady=5, padx=10, fill='x') 

                    program_label = tk.Label(row_frame, text=program, width=40, anchor='w') 
                    program_label.pack(side=tk.LEFT, padx=5) 

                    uninstall_button = ttk.Button(
                        row_frame, 
                        text="Uninstall", 
                        command=lambda p=program: self.uninstall_program(p)
                    ) 
                    uninstall_button.pack(side=tk.LEFT, padx=5) 
            else:

                no_programs_label = tk.Label(scrollable_frame, text="No installed programs to uninstall.") 
                no_programs_label.pack(pady=20)
        except Exception as e:
            error_label = tk.Label(
                scrollable_frame, 
                text=f"Error loading installed programs: {str(e)}", 
                fg="red"
            )
            error_label.pack(pady=20)
            
    def list_installed_programs(self):
        installed_programs = []
        try:
            uninstall_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninstall_key) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    subkey_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        try:
                            display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            installed_programs.append(display_name)
                        except FileNotFoundError:
                            continue
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list installed programs: {e}")

        return installed_programs
    
    
    def get_program_path(self, program_name):
        uninstall_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninstall_key) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                subkey_name = winreg.EnumKey(key, i)
                with winreg.OpenKey(key, subkey_name) as subkey:
                    try:
                        display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        if display_name == program_name:
                            return winreg.QueryValueEx(subkey, "UninstallString")[0]
                    except FileNotFoundError:
                        continue
        return None    
    
    def uninstall_program(self, program):
        program_path = self.get_program_path(program)
        if program_path:
            try:
                result = subprocess.run(program_path, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    messagebox.showinfo("Success", f"{program} uninstalled successfully!")
                else:
                    messagebox.showerror("Error", f"Error occurred while uninstalling {program}: {result.stderr}")
            except Exception as e:
                messagebox.showerror("Error", f"Exception occurred: {e}")
        else:
            messagebox.showerror("Error", "Unable to find uninstall path.")

    def create_settings_tab(self):

        settings_frame = ttk.Frame(self.settings_tab)
        settings_frame.pack(pady=20)

        path_label = tk.Label(settings_frame, text="Change Apps Folder:")
        path_label.pack(pady=5)

        change_path_button = ttk.Button(settings_frame, text="Browse Folder", command=self.ask_for_password_change_folder)
        change_path_button.pack(pady=5)

    def ask_for_password_change_folder(self):
        password_window = tk.Toplevel(self.master)
        password_window.title("Enter Password")
        password_window.geometry("300x150")
        password_window.iconbitmap(self.resource_path("dt\\22218foxface_98828.ico"))
        # password_window.iconbitmap(os.path.join(self.get_base_path(),"dt\\22218foxface_98828.ico"))
        
        password_label = tk.Label(password_window, text="Enter Password:")
        password_label.pack(pady=10)
        
        password_entry = tk.Entry(password_window, show='*')
        password_entry.pack(pady=5)

        confirm_button = ttk.Button(password_window, text="Confirm", command=lambda: self.change_approved_programs_folder(password_entry.get(), password_window))
        confirm_button.pack(pady=10)
           
    def change_approved_programs_folder(self, entered_password, window):
        if entered_password == self.password:
            new_path = filedialog.askdirectory()
            if new_path:
                base_path = self.get_base_path()
                cipher = Fernet(self.key)
                
                config = configparser.ConfigParser()
                config['Settings'] = {
                    'bios': self.serial,
                    'password': self.password,
                    'path': new_path
                }
                with open(os.path.join(base_path, "dt.ini"), "w") as temp_file:
                    config.write(temp_file)
                
                with open(os.path.join(base_path, "dt.ini"), "rb") as temp_file:
                    config_data = temp_file.read()
                    
                encrypted_data = cipher.encrypt(config_data)
        
                with open(os.path.join(base_path, "dt.ini.enc"), "wb") as encrypted_file:
                    encrypted_file.write(encrypted_data)       
                self.approved_programs_folder = new_path
                self.load_approved_programs(self.install_tab, "install")
                messagebox.showinfo("Success", "The apps folder path has been updated successfully!")

                os.remove(os.path.join(base_path, "dt.ini"))

        else:
            messagebox.showerror("Error", "Incorrect password. Please try again.")

        window.destroy()

    def create_change_password_tab(self): 
        change_password_frame = ttk.Frame(self.change_password_tab) 
        change_password_frame.pack(pady=40, padx=40, fill='both', expand=True) 

        title_label = tk.Label( change_password_frame, text="Change Password", font=('Arial', 16, 'bold')) 
        title_label.pack(pady=(0, 20))

        current_password_frame = ttk.Frame(change_password_frame)
        current_password_frame.pack(pady=10, fill='x')
        current_password_label = tk.Label(current_password_frame, text="Current Password:")
        current_password_label.pack(side='left', padx=5)
        current_password_entry = ttk.Entry(current_password_frame, show='*', width=30)
        current_password_entry.pack(side='left', padx=10)

        new_password_frame = ttk.Frame(change_password_frame)
        new_password_frame.pack(pady=10, fill='x')
        new_password_label = tk.Label(new_password_frame, text="New Password:")
        new_password_label.pack(side='left', padx=5)
        new_password_entry = ttk.Entry(new_password_frame, show='*', width=30)
        new_password_entry.pack(side='left', padx=23)
        
        change_button = ttk.Button( change_password_frame, text="Change Password", command=lambda: self.change_password( current_password_entry.get(), new_password_entry.get() )) 
        change_button.pack(pady=30)
        self.password_message_label = tk.Label( change_password_frame,  text="", fg="red", font=('Arial', 10) )
        self.password_message_label.pack(pady=10)


    def change_password(self, current_password, new_password):            
        if current_password == self.password:
            self.password = new_password
            
            base_path=self.get_base_path()
            cipher = Fernet(self.key)
            
            config = configparser.ConfigParser()
            config['Settings'] = {
                'bios': self.serial,
                'password': new_password,
                'path': self.approved_programs_folder
            }
            with open(os.path.join(base_path, "dt.ini"), "w") as temp_file:
                config.write(temp_file)
            
            with open(os.path.join(base_path, "dt.ini"), "rb") as temp_file:
                config_data = temp_file.read()
                    
            encrypted_data = cipher.encrypt(config_data)
        
            with open(os.path.join(base_path, "dt.ini.enc"), "wb") as encrypted_file:
                encrypted_file.write(encrypted_data)       
         
            messagebox.showinfo("Success", "Password changed successfully!")
            os.remove(os.path.join(base_path, "dt.ini"))    
        else:
            messagebox.showerror("Error", "Incorrect current password.")          
            
            
    def info_tab(self): 
        
        create_info_tab = ttk.Frame(self.infotab) 
        create_info_tab.pack(pady=40, padx=40, fill='both', expand=True) 

        text1 = tk.Label( create_info_tab, text="For a secure installl, from a local setup, use our solution : ") 
        text1.pack(pady=(0, 20))
        
        text2 = tk.Label( create_info_tab, text="« MiresStore »", font=('Arial', 11, 'bold')) 
        text2.pack(pady=(0, 20))

root = tk.Tk()
app = MiresStore(root)
root.mainloop()