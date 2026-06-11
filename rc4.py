import sys

def main():
    testfile = sys.argv[1]
    password = sys.argv[2]
    operation = sys.argv[3].lower()

    print(testfile, password, operation)


if __name__ == "__main__":
    main()