from passgen import passgen

passwd = passgen(
    length=12,
    punctuation=True,
    digits=True,
    letters=True,
    #case='both'
)
print(passwd)

