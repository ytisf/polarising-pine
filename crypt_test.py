import crypt, getpass, pwd

def login(pass2check, digest):
    cleartext = pass2check
    cryptedpasswd = digest
    return crypt.crypt(cleartext, cryptedpasswd) == cryptedpasswd

passwords = ["XXX", "XXX"]
words = open('10_million_password_list_top_1000000.txt', 'r').readlines()
words = open('darkc0de.lst', 'r').readlines()
words = open('rockyou.txt', 'r').readlines()


for password in passwords:
    for word in words:
        if login(word.strip(), password):
            print word.strip(),":", password
