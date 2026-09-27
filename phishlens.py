#Version 1.0 
#Author Jonathan Hall, Samuel Remp, Cole Crandall

from analyzer import analyze_email

def main():
    filename = input("Enter email file: ")

    try:
        with open(filename, "r") as file:
            email = file.read()

        analyze_email(email)

    except FileNotFoundError:
        print("Email file not found.")


if __name__ == "__main__":
    main()

