

class Manipulator(object):
    KINDS=()
    SEPERATOR="$"
    
    def __call__(self, txt, **kwargs):
        data = {}
        splitted = txt.split("$")
        for kind, part in zip(self.KINDS, splitted):
            data[kind]=part

        for info, new_value in kwargs.items():
            kind, position = info.rsplit("_",1)

            part = data[kind]
            if position=="start":
                part = new_value + part[1:]
            elif position=="mid":
                mid=int(len(part)/2)
                part = part[:mid] + new_value + part[mid+1:]
            elif position=="end":
                part = part[:-1] + new_value
            else:
                raise AssertionError
            data[kind] = part

        return "$".join([data[kind] for kind in self.KINDS])


class CryptManipulator(Manipulator):
    KINDS = ("algorithm", "iterations", "salt", "hash", "data")

xor_crypt_manipulator = CryptManipulator()


class SecurePassManipulator(Manipulator):
    KINDS = ("pbkdf2_hash", "second_pbkdf2_part", "cnonce")

secure_pass_manipulator = SecurePassManipulator()
