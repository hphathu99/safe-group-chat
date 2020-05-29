1. Running the chat application: 
-   Clean all data in the network root folder:
    python network.py -p .\network -a ABC --clean
-   Generate private and public keys for every member in the address. In each cmd window, run:
    python sender.py -p .\network -a A --keygen
    python receiver.py -p .\network -a B --keygen
    python receiver.py -p .\network -a C --keygen
-   Run the sender.py file at address A, type "start" to start a chat session (only A can create the session and invite members)
-   Type in requested keys for the chat members in order for the message to get through
-   Run the sender.py file for addresses that A invited, type "accept" to accept the message requested
    Type in requested keys for the chat members in order for the message to get through
-   After that, we'll enter a session loop. Chat members can send each other messages. 
-   The messages will be encrypted end-to-end until one member press "destroy"

2. Some modifications from the design protocol I've done:
-   Encrypted the messages in the session using GCM instead of CCM
-   I intended to create public and private keys for server and have every chat members encrypt their message with that one, but the message seems to be too long for such encryption

