# PASSWORD CHECKER TOOL #
import requests
import hashlib
import sys


def request_api(key_data):
    url = 'https://api.pwnedpasswords.com/range/' + key_data
    req = requests.get(url)
    if req.status_code != 200:
        return f'Error fetching: {req.status_code}, check the api & try again...'
    return req


def check_leaks(hashed, tail):
    data = request_api(hashed)
    hashes = (line.split(':') for line in data.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return count
    return 0


def check_password(password):
    hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  # 160 bits
    first_5_char, tail = hashed_password[:5], hashed_password[5:]
    return check_leaks(first_5_char, tail)


def main(args):
    for password in args:
        count = check_password(password)
        if count:
            print(f'{password} was found {count} times. You should change your password immediately...')
        else:
            print(f'{password} was not found. Carry on!')


if __name__ == '__main__':
    main(sys.argv[1:])
