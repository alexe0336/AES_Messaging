Steps to Execute the Program

Step 1: Install Required Python Library

    Begin by installing the cryptography library using pip. This library is essential for the program's encryption and decryption processes. Open your terminal or command prompt and execute the following command:

        'pip install cryptography'

Step 2: Configure Network Settings

    Ensure that both the sender and receiver are connected to the same network, such as the same Wi-Fi router or LAN. This step is crucial for enabling successful communication between the two.

        IP Address Configuration: In sender.py, set the serverIP variable to the IP address of the machine hosting or running server.py. This tells the sender where to find the server.
        Port Configuration: In both sender.py and receiver.py, set the port variables (port in sender.py and serverPort in receiver.py) to the port number on which server.py will listen for incoming connections. It is important that these port values match.

Step 3: Prepare Encryption and Decryption Settings

    Before running the program, you need to specify the file you intend to encrypt or decrypt, as well as any Initialization Vector (IV) or SALT values required by the encryption scheme.

        Locate the "Global Variables" section at the top of both sender.py and receiver.py. Here, you can define the necessary settings for the file paths, IV, and any other parameters relevant to the encryption or decryption processes.

Step 4: Execute the Program

    To start the program, you must first run server.py on the host machine. Once the server is up and listening for connections, you can then run receiver.py on the receiving machine to initiate the file transfer and encryption/decryption processes.

        Running server.py: Open a terminal or command prompt where server.py is located and execute the script by typing python server.py or python3 server.py, depending on your environment.
        Running receiver.py: Similarly, on the receiving machine, open a terminal or command prompt, navigate to where receiver.py is located, and run it using python receiver.py or python3 receiver.py.