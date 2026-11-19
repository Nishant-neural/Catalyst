"""ChatGPT Critical 1 repro: a call through a variable whose type the
analyser cannot infer. The attribute name is fixed (.load), so this
site can call yaml.load — it must be UNCERTAIN, never not_reachable."""
import yaml

def get_parser():
    return yaml

def main():
    parser = get_parser()
    parser.load("untrusted input")

if __name__ == "__main__":
    main()
