from .Args import Args
from .core.Script import run_script


def main():
    run_script(Args.args, Args.parser)


if __name__ == "__main__":
    main()
