# CSCI351_Project4
DNSSEC Client in Python


# High Level Approach
- Python built in socket library to set up connection
- Sets up connection across UDP connection
- Calls function to create the query dns packet following eDNS format using python structs
- checks for errors in the response
- goes through the answers and prints out the responses
- Class that sets up dns packet
- makes message header bit by bit
- encodes and decodes packet
- Class that decodes resource record
- classes that define A, DS, DNSKEY, and RRSIG formats


# Challenges
- a significant amount of knowledge was neccessary to even begin working on the project which ate up a lot of time
- the project writeup was long and took time to understand the specific project requirements and how the project should function
- Implementing this in code was also pretty tricky 
- researching on the message header, the different fields to have, how to pack/unpack, etc
- The actual validation part across multiple zones was non-trivial to implement
- Understanding how to properly use dig/bind and wireshark to read and understand incoming DNS traffic was necessary to learn for this project


# Good properties/design
- Good code structure
- Code is commented well
- Building the packet is throughouly documented and easy to understand
- Handling of error checking


# Testing
- Testing was done extensively with packet matching using DIG as well as wireshark for understanding bit order
- manual testing for input parsing
- using test examples from the project writeup
