"""Desafe for Safe In Cloud (safe-in-cloud.com).
A python utility to decrypt Safe In Cloud databases files

Usage:
  desafe <file> card [-t TITLE] [-f FILTER...] [-p] [-r] [-d]
  desafe <file> pass -t TITLE [-f FILTER...]
  desafe <file> export (json|xml) [-o FILE]
  desafe (-h | --help)

Arguments:
  card    print all cards.
  pass    print only the password for the card with the specified title.
  export  exports given file in clear in the given format (json or xml).
  file    the Safe in Cloud database file path

Options:
  -f, --filter FILTER    Includes only cards which contain the all specified strings (case insensitive).
  -t, --title TITLE      Find card with this exact title (case insensitive).
  -p --password          Include passwords in output.
  -r --raw               Print information keeping the original format.
  -d --deleted           Included deleted items.
  -o --output FILE       Included deleted items.
  -h --help              Show this screen.
  -v --version           Show version.
"""

import struct
import sys
import getpass
import io
import xmltodict
import zlib
import json
from docopt import docopt
from Crypto.Cipher import AES
from passlib.utils import pbkdf2


class Desafe:
    def __init__(self, desafe_filename, password):
        self.desafe_filename = desafe_filename
        self.password = password

    def __get_byte(self, f):
        return struct.unpack("B", f.read(1))[0]

    def __get_short(self, f):
        return struct.unpack("H", f.read(2))[0]

    def __get_array(self, f):
        size = self.__get_byte(f)
        return struct.unpack("%ds" % size, f.read(size))[0]

    def decrypt(self):

        # load database
        with open(self.desafe_filename, "rb") as f:
            self.__get_short(f)  # magic =
            self.__get_byte(f)  # sver =
            salt = self.__get_array(f)
            skey = pbkdf2.pbkdf2(self.password, salt, 10000, 32)
            iv = self.__get_array(f)
            cipher = AES.new(skey, AES.MODE_CBC, iv)
            salt2 = self.__get_array(f)
            block = self.__get_array(f)
            decr = cipher.decrypt(block)
            sub_fd = io.BytesIO(decr)
            iv2 = self.__get_array(sub_fd)
            pass2 = self.__get_array(sub_fd)
            self.__get_array(sub_fd)  # check =

            pbkdf2.pbkdf2(pass2, salt2, 1000, 32)  # skey2 =

            cipher = AES.new(pass2, AES.MODE_CBC, iv2)
            data = cipher.decrypt(f.read())

            decompressor = zlib.decompressobj()
            return decompressor.decompress(data) + decompressor.flush()

def is_valid_filter(filters, card):
    if filters is None or len(filters) <= 0:
        return True

    jsondump = json.dumps(card).lower()
    for filter in filters:
        if not filter.lower() in jsondump:
            return False
    return True

def is_valid_title(title, card):
    return title is None or title.lower() == card['@title'].lower()

def is_valid(filters, title, content):
    return is_valid_filter(filters, content) and is_valid_title(title, content)

def is_secret(type):
    return type and type in ['password', 'pin', 'secret']

def get_card(card):
    ocard = {'title': 'unknown', 'field': []}
    if '@title' in card:
        ocard['title'] = card['@title']
    if 'field' in card:
        # ensure field is a list
        if not isinstance(card['field'], (list)):
            field = []
            field.append(card['field'])
            card['field'] = field

        for field in card['field']:
            ofield = {'name': 'Unknown', 'text': ''}

            if '@name' in field and field['@name']:
                ofield['name'] = field['@name']
            if '@type' in field and field['@type']:
                ofield['type'] = field['@type']
            if '#text' in field and field['#text']:
                ofield['text'] = field['#text']
            ocard['field'].append(ofield)
    return ocard;


class Shell(object):
    def __init__(self):
        self.args = docopt(__doc__, version='Desafe for Safe In Cloud 0.0.6')
        # print self.args

        file_path = self.args["<file>"]
        try:
            open(file_path, "rb")  # or "a+", whatever you need
        except IOError:
            print("ERROR: could not open file '{}'".format(file_path))
            sys.exit(1)

        db = Desafe(file_path, getpass.getpass('Safe in Cloud Password:'))
        try:
            self.xmldata = db.decrypt()
        except Exception:
            print(
                "ERROR: could not decrypt file '{}'. Ensure provided password is valid".format(
                    file_path
                )
            )
            sys.exit(1)
        self.doc = xmltodict.parse(self.xmldata)

        # execute the commmand option
        if self.args["export"]:
            self.export()
        if self.args['card']:
            self.print_cards()
        if self.args['pass']:
            self.print_password()

    def export(self):

        if self.args["json"]:
            output = json.dumps(self.doc, indent=4)
        else:  # it must be xml
            output = self.xmldata

        if self.args['--output']:
            try:
                with open(self.args['--output'], "w") as f:
                    f.write(output)
            except Exception:
                print "ERROR: could not write on '{}'".format(self.args['--output'])
                sys.exit(1)
        else:
            print(output)

    def print_cards(self):
        for db in self.doc:
            if "card" not in self.doc[db] or len(self.doc[db]["card"]) <= 0:
                print("database does not contain cards")
                return

            for card in self.doc[db]['card']:
                if is_valid(self.args['--filter'], self.args['--title'], card):
                    # skip deleted ones
                    if (
                        "@deleted" in card
                        and card["@deleted"] == "true"
                        and not self.args["--deleted"]
                    ):
                        continue

                    if self.args["--raw"]:
                        ocard = card
                        if not self.args["--password"] and "field" in card:
                            fields = []
                            for field in card['field']:
                                if '@type' not in field or not is_secret(field['@type']):
                                    fields.append(field)
                            ocard["field"] = fields
                        print(json.dumps(ocard, indent=4))
                    else:
                        ocard = get_card(card)
                        print u'Card: {}'.format(ocard['title'])
                        for field in ocard['field']:
                            if not self.args['--password'] and 'type' in field and is_secret(field['type']):
                                continue
                            print u'  {}: {}'.format(field['name'], field['text'])

    def print_password(self):
        for db in self.doc:
            if 'card' not in self.doc[db] or len(self.doc[db]['card']) <= 0:
                print "database does not contain cards"
                return

            cards = []
            for card in self.doc[db]['card']:
                if is_valid(self.args['--filter'], self.args['--title'], card):
                    # skip deleted ones
                    if '@deleted' in card and card['@deleted'] == 'true' and not self.args['--deleted']:
                        continue
                    cards.append(card)

            card = get_card(cards[0])
            for field in card['field']:
                if 'type' in field and 'password' == field['type']:
                    print u'{}'.format(field['text'])

def main():
    Shell()


if __name__ == "__main__":
    Shell()
