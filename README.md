# myStegHideProgram (fstg)

This is a powerful and lightweight steganography program to hide message to a file. There are two options:

- Hide file to another file without password
- Hide file to another file with passowrd encrypted with AES256 and PBKDF2 algorithms

## Dependencies

Before you install you must install dependency. In Debian and Ubuntu distributions:
Type in console:

```
sudo apt install libssl-dev
```

## Compiling and Installing

To compile, just type:

```
mkdir <YOUR_DIRECTORY> && cd <YOUR_DIRECTORY>
git clone https://github.com/devfabiosilva/myStegHideProgram.git
cd myStegHideProgram/src/ && make
```

Optionally you can install into your system program directory /usr/bin/

```
sudo make install
```

## Uninstalling and cleaning

If you want to delete compiled _fstg_ program:

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


- _add <DEST. FILE> <FILE TO BE HIDDEN>_ Add <FILE TO BE HIDDEN> to <DEST. FILE>

Example:

Hide a message text in _mytext.txt inside_ _mypicture.jpeg_ without password:

```
fstg add mypicture.jpg mytext.txt
```

- _add-with-password <DEST. FILE> <FILE TO BE HIDDEN>_ Encrypt and add <FILE TO BE HIDDEN> to <DEST. FILE>

Example:

Hide a message text in _mytext.txt_ inside _mypicture.jpeg_ with password encryption

```
fstg add-with-password mypicture.jpg mytext.txt
```

- _extract <DEST. FILE>_ Extract an stegged file (if exists) from <DEST. FILE>

Example:

To extract a hidden message inside _mypicture.jpeg_ type:

```
fstg extract mypicture.jpeg
```

- _usage_ Shows program version and details.

- _version_ Shows program version and details.

### Sample example file

In [example](/example/) directory there is an [image](/example/incognito.jpg) and a hidden message inside.

<p align="center">
  <img src="/example/incognito.jpg">
</p>

To open hidden message you must extract the encrypted hidden file:

```
fstg extract incognito.jpg
```

**PASSWORD IS** _1234_

## License

MIT

## Contact

Contact me at [fabioegel@gmail.com](mailto:fabioegel@gmail.com) or [fabioegel@protonmail.com](mailto:fabioegel@protonmail.com)

