# Password Manager (AES-Encryption)

This app is a __single-user password manager__ i.e. it is focused on *one-use-multiple-passwords* approach. The user first have to create an account in this app by filling in *username* and *password*. The password is used to encrypt the data to if the user forgets the password or any of the file is deleted then the passwords can never be decrypted.

Example password:  "c\\>ix/fr?8I!C1@'E_oF"

- Check the password strength -

  > [passwordmeter.com](http://www.passwordmeter.com/)

  > [thycotic.com](https://thycotic.com/resources/password-strength-checker/)


## Getting Started

These instructions will get you a copy of the project up and running on your local machine. Git clone the repository and open _[passwordmanager.py](passwordmanager.py "app")_ file. Now enter username and password to make an account if running the app for the first time. Restart the program after creating the account and enter the correct login credentials.
- __Make a password and save it__
  - __*Choose site for the details need to be saved*__
  - __*User-id for that site*__
  - __*Your password will be copied to your clipboard*__
- __View all saved password__
- __Exit the app__

### Prerequisites

Few modules are needed to be installed to use this app. They are :
- cryptograohy
- pyperclip
- passwordmeter

### Installing

To clone the repository to your local machine :
```
git clone https://github.com/prakharsaxena1/password-manager_AES_Encryption.git
```

To install the modules use the following commands :
```
pip install cryptography
pip install passwordmeter
pip install pyperclip
```

## Author

* [__Prakhar Saxena__](https://twitter.com/_thunder_cs)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* https://www.youtube.com/watch?v=H8t4DJ3Tdrg
* https://cryptography.io/en/latest/
* https://nitratine.net/blog/post/encryption-and-decryption-in-python/
* **Billie Thompson** - *readme.md layout* - [PurpleBooth](https://github.com/PurpleBooth)