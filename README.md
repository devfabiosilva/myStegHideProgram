# myStegHideProgram (fstg)

This is a powerful and lightweight steganography program to hide message to a file. There are two options:

- Hide file to another file without password
- Hide file to another file with passowrd encrypted with AES256 and PBKDF2 algorithms

## Dependencies

Before you install you must install dependency. In Debian and Ubuntu distribution type in your console:

```
sudo apt install libssl-dev
```

## Installation

To install, just type:

```
mkdir <YOUR_DIRECTORY> && cd <YOUR_DIRECTORY>
git clone https://github.com/devfabiosilva/myStegHideProgram.git
cd src && make install
```

Optionally you can install into your system program directory /usr/bin/

```
sudo make uninstall
```

## Uninstalling and cleaning

If you want to delete compile program:

```
make clean
```

If you installed and wish to unistall from system program directory /usr/bin/ type:

```
sudo make unistall
```

## Running fstg

Run locally:

```
./fstg [ OPTIONS ] <DEST. FILE> <FILE TO BE HIDDEN>
```

Or if you installed in system program directory type:

```
fstg [ OPTIONS ] <DEST. FILE> <FILE TO BE HIDDEN>
```

### Commands


- **add <DEST. FILE> <FILE TO BE HIDDEN>** Add <FILE TO BE HIDDEN> to <DEST. FILE>

Example:

Hide a message text in mytext.txt inside mypicture.jpeg without password:

```
fstg add mypicture.jpg mytext.txt
```

- **add-with-password <DEST. FILE> <FILE TO BE HIDDEN>** Encrypt and add <FILE TO BE HIDDEN> to <DEST. FILE>

Example:

Hide a message text in mytext.txt inside mypicture.jpeg with password encryption

```
fstg add-with-password mypicture.jpg mytext.txt
```

- **extract <DEST. FILE>** Extract an stegged file (if exists) from <DEST. FILE>

Example:

To extract a hidden message inside mypicture.jpeg type:

```
fstg extract mypicture.jpeg
```

- **usage** Shows program version and details.

- **version** Shows program version and details.

### Sample example file


## License

MIT

## Contact
