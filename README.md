# LDAPi

## Description

LDAPi is a sophisticated tool designed to exploit LDAP injection vulnerabilities. With a focus on simplicity and efficiency, it offers a powerful mechanism to extract data through LDAP injection techniques, enabling users to retrieve comprehensive data sets from vulnerable systems. Its utilization of binary trees for data sorting and searching ensures a fast and effective approach in handling large volumes of user data.

## Features

- Advanced LDAP injection exploitation.
- Capable of retrieving extensive data from vulnerable systems.
- Utilizes binary trees for efficient data management.
- Integrated with essential libraries like sys, signal, time, requests, string, argparse, and pwn for enhanced functionality.

## Installation

```bash
git clone https://github.com/Hamibubu/LDAPi.git
cd LDAPi
pip install -r requirements.txt
```

## Usage

1. Adequate the payload = 
`f"user_id={new_pseudouser}*&password=*&login=1&submit=Submit"` and `payload = f"user_id={user})({obj}={data+char}*&password=*&login=1&submit=Submit"` to your POST request.
2. Run the following command
```bash
python3 ldapi.py --url http://<your endpoint>
```