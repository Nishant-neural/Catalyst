"""yaml.load called with Loader=FullLoader: yaml.load itself is
reachable, so no OpenVEX not_affected statement may be emitted for
this advisory even though some candidates are not_reachable."""
import yaml

def main():
    yaml.load("x: 1", Loader=yaml.FullLoader)

if __name__ == "__main__":
    main()
