import os
import numpy as np
import math
import sys
import hashlib
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import *
from Cryptodome.Cipher import AES
import re
import threading
from pathlib import Path

def hex_to_rgb(hx, hsl=False):
    """Converts a HEX code into RGB or HSL.
    Args:
        hx (str): Takes both short as well as long HEX codes.
        hsl (bool): Converts the given HEX code into HSL value if True.
    Return:
        Tuple of length 3 consisting of either int or float values.
    Raise:
        ValueError: If given value is not a valid HEX code."""
    if re.compile(r'#[a-fA-F0-9]{3}(?:[a-fA-F0-9]{3})?$').match(hx):
        div = 255.0 if hsl else 0
        if len(hx) <= 4:
            return tuple(int(hx[i]*2, 16) / div if div else
                        int(hx[i]*2, 16) for i in (1, 2, 3))
        return tuple(int(hx[i:i+2], 16) / div if div else
                    int(hx[i:i+2], 16) for i in (1, 3, 5))
    raise ValueError(f'"{hx}" is not a valid HEX code.')

class EncryptionTool:

    def __init__(
        self,
        user_file,
        user_key,
        user_salt,
        flag
        ):

        # get the path to input file

        self.user_file = user_file
        self.flag=flag
        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 1024
        self.total_chunks = self.input_file_size // self.chunk_size + 1

        # convert the key and salt to bytes

        self.user_key = bytes(user_key, 'utf-8')
        self.user_salt = bytes(user_key[::-1], 'utf-8')

        # get the file extension

        self.file_extension = self.user_file.split('.')[-1]

        # hash type for hashing key and salt

        self.hash_type = 'SHA256'

        self.encrypt_output_file = '.'.join(self.user_file.split('.'
                    )[:-1]) + '.' + self.file_extension + '.enc'
        # encrypted file name
        if self.flag==0:
            self.encrypt_output_file = '.'.join(self.user_file.split('.'
                    )[:-1]) + '.' + self.file_extension + '.enc'

        if self.flag==1:
            self.encrypt_output_file = '.'.join(self.user_file.split('.'
                    )[:-1]) + '.' + self.file_extension + 'r'

        # decrypted file name
        
        self.decrypt_output_file = self.user_file[:-5].split('.')
        self.decrypt_output_file = \
            '.'.join(self.decrypt_output_file[:-1]) + '_decrypted.' \
            + self.decrypt_output_file[-1]

        if self.flag==3:
            self.decrypt_output_file = self.user_file[:-5].split('.')
            self.decrypt_output_file = \
                '.'.join(self.decrypt_output_file[:-1]) + '.' \
                + self.decrypt_output_file[-1] + '.z'
        # dictionary to store hashed key and salt

        if self.flag==4:
            self.decrypt_output_file = self.user_file[:-1].split('.')
            self.decrypt_output_file = \
                '_decrypted_.'.join(self.decrypt_output_file[:-1])
        self.hashed_key_salt = dict()

        # hash key and salt into 16 bit hashes

        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=1024):
        """Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k.
        """

        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    

    def encrypt(self,key,data):
        print(key,data)
        rgb=hex_to_rgb(data)
        temp_key=[]
        for i in key:
            temp_key.append(int(i))
        for i in range(0,3):
            temp_key[i]=temp_key[i]+int(rgb[i])
        print(temp_key)
        # create a cipher object
        file = open(self.user_file, "r")
        b=[]

        while True:
            # read by character
            char = file.read(1)
            if not char: 
                break 
            b.append(ord(char))

        #making matrix for mulitiplication
        if len(b)%4 != 0:
            if len(b)%4 == 1:
                b.append(-1)
                b.append(-1)
                b.append(-1)
            if len(b)%4 == 2:
                b.append(-1)
                b.append(-1)
            if len(b)%4 == 3:
                b.append(-1)

        d=int(len(b)/4)
        starting_loop=1
        ending_loop=d
        temp=[]
        empt_array = np.empty((0,d), int)

        for j in range(1,5):
            for i in range(starting_loop,ending_loop+1):
                temp.append(b[i-1])
            empt_array = np.append(empt_array, np.array([temp]), axis=0)
            temp=[]
            starting_loop=(d*j)+1
            ending_loop=ending_loop+d

        key_array =np.empty((0,4),int)
        temp_key1=[number ** 2 for number in temp_key]
        temp_key2=[number ** 3 for number in temp_key]
        temp_key3=[number ** 4 for number in temp_key]

        key_array=np.append(key_array,np.array([temp_key]),axis=0)
        key_array=np.append(key_array,np.array([temp_key1]),axis=0)
        key_array=np.append(key_array,np.array([temp_key2]),axis=0)
        key_array=np.append(key_array,np.array([temp_key3]),axis=0)
        print(key_array)
        
        # This will return dot product
        res = np.dot(key_array,empt_array)



        file.close()

        file1 = open("myfile.txt", "w")  # write mode
        for x in np.nditer(res):
            file1.write(str(x))
            file1.write(',')
        file1.close()
        messagebox.showinfo('Tushar File Encryption',
                                'File Encryption Successful !!')

    def decrypt(self,key,data):
        try:
            print(key,data)
            rgb=hex_to_rgb(data)
            temp_key=[]
            for i in key:
                temp_key.append(int(i))
            for i in range(0,3):
                temp_key[i]=temp_key[i]+int(rgb[i])
            print(temp_key)
            file = open(self.user_file, "r")
            b=[]
            data = file.read()
            data = data.split(',')
            filter_empty = filter(lambda x: x != "", data)
            data = list(filter_empty)

            d=int(len(data)/4)
            starting_loop=1
            ending_loop=d
            temp=[]
            empt_array = np.empty((0,d), int)

            for j in range(1,5):
                for i in range(starting_loop,ending_loop+1):
                    temp.append(int(data[i-1]))
                empt_array = np.append(empt_array, np.array([temp]), axis=0)
                temp=[]
                starting_loop=(d*j)+1
                ending_loop=ending_loop+d

            key_array =np.empty((0,4),int)
            temp_key1=[number ** 2 for number in temp_key]
            temp_key2=[number ** 3 for number in temp_key]
            temp_key3=[number ** 4 for number in temp_key]

            key_array=np.append(key_array,np.array([temp_key]),axis=0)
            key_array=np.append(key_array,np.array([temp_key1]),axis=0)
            key_array=np.append(key_array,np.array([temp_key2]),axis=0)
            key_array=np.append(key_array,np.array([temp_key3]),axis=0)
            print(key_array)
            
            inv_key_array = np.linalg.inv(key_array)

            file.close()


            file1 = open("decrypt_file.txt", "w")
            for x in np.nditer(np.dot(inv_key_array,empt_array)):
                temp=round(float(x))
                if temp == int(-1):
                    print("hello")
                    break
                file1.write(chr(round(float(x))))
            file1.close()

            messagebox.showinfo('Tushar File Decryption',
                                    'File Decryption Successful !!')
        except:
            messagebox.showinfo('Tushar File Decryption',
                                    'File Decryption Unsuccessful !!')

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)

    def hash_key_salt(self):

        # --- convert key to hash
        #  create a new hash object

        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_key)

        # turn the output key hash into 32 bytes (256 bits)

        self.hashed_key_salt['key'] = bytes(hasher.hexdigest()[:32],
                'utf-8')

        # clean up hash object

        del hasher

        # --- convert salt to hash
        #  create a new hash object

        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_salt)

        # turn the output salt hash into 16 bytes (128 bits)

        self.hashed_key_salt['salt'] = bytes(hasher.hexdigest()[:16],
                'utf-8')

        # clean up hash object

        del hasher


class MainWindow:

    """ GUI Wrapper """

    # configure root directory path relative to this file

    THIS_FOLDER_G = ''
    if getattr(sys, 'frozen', False):

        # frozen

        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:

        # unfrozen

        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

    def __init__(self, root):
        self.root = root
        self._cipher = None
        self._file_url = tk.StringVar()
        self._secret_key = tk.StringVar()
        self._secret_key_check = tk.StringVar()
        self._salt = tk.StringVar()
        self._status = tk.StringVar()
        self._status.set('---')

        self.should_cancel = False

        root.title('Tushar File Encryption')
        root.configure(bg='#eeeeee')

        self.menu_bar = tk.Menu(root, bg='#eeeeee', relief=tk.FLAT)

        root.configure(menu=self.menu_bar)

        self.file_entry_label = tk.Label(root,
                text='Enter File Path Or Click SELECT FILE Button',
                bg='#eeeeee', anchor=tk.W)
        self.file_entry_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=0,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
            )

        self.file_entry = tk.Entry(root, textvariable=self._file_url,
                                   bg='#fff', exportselection=0,
                                   relief=tk.FLAT)
        self.file_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=1,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
            )

        self.select_btn = tk.Button(
            root,
            text='SELECT FILE',
            command=self.selectfile_callback,
            width=42,
            bg='#3498db',
            fg='#ffffff',
            bd=2,
            relief=tk.FLAT,
            )
        self.select_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=2,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
            )

        self.key_entry_label1 = tk.Label(root,
                text='Enter Key (To be Remembered while Decryption)',
                bg='#eeeeee', anchor=tk.W)
        self.key_entry_label1.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=3,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
            )

        self.key_entry1 = tk.Entry(root, textvariable=self._secret_key,
                                   bg='#fff', exportselection=0,
                                   relief=tk.FLAT)
        self.key_entry1.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=4,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
            )

        self.key_entry_label2 = tk.Label(root,
                text='Enter Color (To remembered while Decryption)', bg='#eeeeee',
                anchor=tk.W)
        self.key_entry_label2.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=5,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
            )

        self.key_entry2 = tk.Entry(root,
                                   textvariable=self._secret_key_check,
                                   bg='#fff', exportselection=0,
                                   relief=tk.FLAT)
        self.key_entry2.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=6,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
            )

        self.encrypt_btn = tk.Button(
            root,
            text='ENCRYPT',
            command=self.e_check_callback,
            bg='#27ae60',
            fg='#ffffff',
            bd=2,
            relief=tk.FLAT,
            )
        self.encrypt_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=7,
            column=0,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S,
            )

        self.decrypt_btn = tk.Button(
            root,
            text='DECRYPT',
            command=self.d_check_callback,
            bg='#27ae60',
            fg='#ffffff',
            bd=2,
            relief=tk.FLAT,
            )
        self.decrypt_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=7,
            column=2,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S,
            )

        self.reset_btn = tk.Button(
            root,
            text='CLEAR',
            command=self.reset_callback,
            bg='#717d7e',
            fg='#ffffff',
            bd=2,
            relief=tk.FLAT,
            )
        self.reset_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=8,
            column=0,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S,
            )

        self.stop_btn = tk.Button(
            root,
            text='STOP',
            command=self.cancel_callback,
            bg='#aaaaaa',
            fg='#ffffff',
            bd=2,
            state='disabled',
            relief=tk.FLAT,
            )
        self.stop_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=8,
            column=2,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S,
            )

        self.status_label = tk.Label(
            root,
            textvariable=self._status,
            bg='#eeeeee',
            anchor=tk.W,
            justify=tk.LEFT,
            relief=tk.FLAT,
            wraplength=350,
            )
        self.status_label.grid(
            padx=12,
            pady=(0, 12),
            ipadx=0,
            ipady=1,
            row=9,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
            )

        tk.Grid.columnconfigure(root, 0, weight=1)
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.columnconfigure(root, 3, weight=1)

    def selectfile_callback(self):
        try:
            name = filedialog.askopenfile()
            self._file_url.set(name.name)
        except Exception as e:
            self._status.set(e)
            self.status_label.update()

    def freeze_controls(self):
        self.file_entry.configure(state='disabled')
        self.key_entry1.configure(state='disabled')
        self.key_entry2.configure(state='disabled')
        self.select_btn.configure(state='disabled', bg='#aaaaaa')
        self.encrypt_btn.configure(state='disabled', bg='#aaaaaa')
        self.decrypt_btn.configure(state='disabled', bg='#aaaaaa')
        self.reset_btn.configure(state='disabled', bg='#aaaaaa')
        self.stop_btn.configure(state='normal', bg='#e74c3c')
        self.status_label.update()

    def unfreeze_controls(self):
        self.file_entry.configure(state='normal')
        self.key_entry1.configure(state='normal')
        self.key_entry2.configure(state='normal')
        self.select_btn.configure(state='normal', bg='#3498db')
        self.encrypt_btn.configure(state='normal', bg='#27ae60')
        self.decrypt_btn.configure(state='normal', bg='#27ae60')
        self.reset_btn.configure(state='normal', bg='#717d7e')
        self.stop_btn.configure(state='disabled', bg='#aaaaaa')
        self.status_label.update()

    def e_check_callback(self):
        newPath = Path(self._file_url.get())
        if newPath.is_file():
            pass
        else:
            messagebox.showinfo('Tushar File Encryption',
                                'Please Enter a valid File URL !!')
            return
        regex = re.compile('0')
        if len(self._secret_key.get()) != 4 or not(self._secret_key.get().isdigit()) or not(regex.search(self._secret_key.get()) == None):
            messagebox.showinfo('Tushar File Encryption',
                                'Please Enter four digit number not containing zero !!')
            return
        if not(re.compile(r'#[a-fA-F0-9]{3}(?:[a-fA-F0-9]{3})?$').match(self._secret_key_check.get())):
            messagebox.showinfo('Tushar File Encryption',
                                'Please Enter a valid color!!')
            return

        self.encrypt_callback()

    def d_check_callback(self):

        newPath = Path(self._file_url.get())
        if newPath.is_file():
            pass
        else:
            messagebox.showinfo('Tushar File Encryption',
                                'Please Enter a valid File URL !!')
            return

        regex = re.compile('0')
        if len(self._secret_key.get()) != 4 or not(self._secret_key.get().isdigit()) or not(regex.search(self._secret_key.get()) == None):
            messagebox.showinfo('Tushar File Encryption',
                                'Please Enter four digit number not containing zero !!')
            return
        if not(re.compile(r'#[a-fA-F0-9]{3}(?:[a-fA-F0-9]{3})?$').match(self._secret_key_check.get())):
            messagebox.showinfo('Tushar File Encryption',
                                'Please Enter a valid color!!')
            return

        self.decrypt_callback()

    def encrypt_callback(self):
        t1 = threading.Thread(target=self.encrypt_execute)
        t1.start()

    def encrypt_execute(self):
        self.freeze_controls()

        try:
            self._cipher = EncryptionTool(self._file_url.get(),
                    self._secret_key.get(), self._salt.get(),flag=0)
            self._cipher.encrypt(self._secret_key.get(),self._secret_key_check.get())
        except Exception as e:

            self._status.set(e)

        self.unfreeze_controls()

    def decrypt_callback(self):
        t2 = threading.Thread(target=self.decrypt_execute)
        t2.start()

    def decrypt_execute(self):
        self.freeze_controls()

        try:
            self._cipher = EncryptionTool(self._file_url.get(),
                    self._secret_key_check.get(), self._salt.get(),flag=3)

            self._cipher.decrypt(self._secret_key.get(),self._secret_key_check.get())
        except Exception as e:

            self._status.set(e)

        self.unfreeze_controls()

    def reset_callback(self):
        self._cipher = None
        self._file_url.set('')
        self._secret_key.set('')
        self._salt.set('')
        self._status.set('---')

    def cancel_callback(self):
        self.should_cancel = True


if __name__ == '__main__':
    ROOT = tk.Tk()
    MAIN_WINDOW = MainWindow(ROOT)
    bundle_dir = getattr(sys, '_MEIPASS',
                         os.path.abspath(os.path.dirname(__file__)))

    ROOT.resizable(height=False, width=False)
    ROOT.mainloop()
