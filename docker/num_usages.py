from sys import argv, exit, stderr

if len(argv) < 3:
    print("USAGES: python3 num_usages.py [max|min|sorted|sum] [value1] [value2] [valueN] ...", file=stderr)
    exit(1)

if argv[1] in ("sorted", "sum"):
    print(getattr(__builtins__, argv[1])((int(x) for x in argv[2:])))
else:
    print(getattr(__builtins__, argv[1])(*argv[2:]))

exit(0)