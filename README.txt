# CSCI351_Project2
DNS Client in Python


# High Level Approach

- Python built in socket library to set up connection
- Main DNS Client Class
- - Sets up connection
- - Calls function to create the query dns packet
- - checks for errors in the response
- - goes through the answers and prints
-
- Class that sets up dns packet
- makes message header
-  encodes and decodes packet
-
- Class that decodes resource record
-
- classes that define A and CNAME resources


# Challenges
- researching on the message header, the different fields to have, how to pack/unpack, etc
- getting started!


# Good properties/design
- Good code structure
- can add more resource types (MX, NS, etc)