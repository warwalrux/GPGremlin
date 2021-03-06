import yaml
import argparse
from GPGremlin import *

if __name__ == "__main__":
    with open("config.yml", "r") as conf:
        config = yaml.load(conf, Loader=yaml.FullLoader)
    parser = argparse.ArgumentParser(description='GPGremlin -- A Python GnuPG Jawn')
    
    parser.add_argument('-d', '--debug', action='store_true',
                        help='debug test switch')
    parser.add_argument('-n', '--name',
                        help='Key Ring Name')
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('-c', '--create', action='store_true',
                        help='Create Ring')
    actions.add_argument('-D', '--destroy', action='store_true',
                        help='Destroy Ring')
    actions.add_argument('-l', '--list', action='store_true',
                        help='List <rings|keys>')
    actions.add_argument('-r', '--run',
                        help='Run gpg with directives from YAML')
    actions.add_argument('-s', '--search',
                        help = "search term")
    args = parser.parse_args()

    g = Gremlin(config)

    if args.create and args.name:
        g.newKeyring(args.name)
    if args.list and args.name:
        g.listKeys(args.name)
    if args.search:
        g.searchKeys(args.search)
