# PasswordProtectedApp

This Python program is designed for more advanced users (recommend having a good understanding of Python & Cryptography to fully understand what this program is doing).

This program, written in Python, calls from the Cryptography library, so I recommend using pip install cryptography or install the library in a dedicted IDE of choice as the program won't run without it.

This program creates a local directory where your passphrases are stored securely as .pem files (.pem files are used in PKI infrastructure, in which they are encrypted via a chain, please research if you aren't familiar with PKI). 

The only way to decrypt is by re-entering the password used to encrypt your .pem file.

If you have knowledge of PKI in Cryptography, you could reverse the PEM chain but the average user would not know this and become confused.
