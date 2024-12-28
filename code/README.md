# Covert Storage Channel that exploits Protocol Field Manipulation using Z Flag field in DNS [Code: CSC-PSV-DNS-ZF]


## Explanation
This covert channel makes use of the DNS's Z flag, a 3 bit long field reserved for future use and is always set to 0 in standard DNS implementations. Our covert channel implementation can be split up into two parts, namely the sender and the receiver functions, which are explained below:

### Sender

- The sender takes several parameters:
    - log_file_name: The name of the sender log file (where the message sent will be displayed)

    - receiverIp: The receiver's IP address

    - pattern00: A list of bits of length 3 used to encode '00' bits
    
    - pattern01: A list of bits of length 3 used to encode '01' bits
    
    - pattern10: A list of bits of length 3 used to encode '10' bits
    
    - pattern11: A list of bits of length 3 used to encode '11' bits

- A random binary message is generated using the 'generate_random_binary_message_with_logging' method from the 'CovertChannelBase' class.

- Iterate through the binary message with a step size of 2 and read two bits at a time.

- Check what the two bit values are and choose the pattern depending on this. E.g. if they are '00' then we will be using the pattern00 list to encode the bits.

- Iterate through the pattern list and, for every bit in it, fill the z flag with the current bit. Send this bit through port 53 and using UDP (User Datagram Protocol), the standard port and method for DNS services, to the receiver by using the 'receiverIp' argument as the destination. This essentially sends the contents of the pattern list one bit at a time to the receiver.



### Receiver

- The receiver function takes the same arguments as the sender function except for the receiver ip. In addition, it takes the 'should_stop' parameter, a flag initialised to false that dictates whether we should stop receiving packets.

- The receiver extraxts the bit that was put in the DNS's z flag and concatenates it to an initially empty string 'collected_bits'.

- This process is repeated until the length of 'collected_bits' is greater than or equal to the pattern lists' length. (Basically until the full pattern is transmitted)

- The bits are then extracted from 'collected_bits' and compared to each pattern.

- Once the pattern is identified, the corresponding two bits are concatenated into 'received_message', an initially emmpty string. (E.g. If the sent pattern was pattern00 then "00" will be added to 'received_mesage')

- This process is repeated until 'received_message' has a lebgth of at least 8. (This is when the received message becomes one byte long, which means it can be cinverted into an ASCII character)

- The length of 'received_message' is checked to see whether it is greater than or equal to 8. If so, it is converted into an ASCII character and concatenated into the initially empty string, 'ascii_message'.

- This process is repeated until the '.' character is encountered, in which case we set 'should_stop' to True.

- We use 'sniff(prn=receive_packet, stop_filter=stop_message, filter="udp port 53")' to check for DNS packets and capture them when they have been transmitted by the sender.

    - The prn argument specifies that for every packet that is capturedm the function 'receive_packet' should be called;
    
    - The stop_filter argument provides us with the option of stopping the sniffing process. When it is True it stops further packet capture

    - The filter argument, in our case it is set to 'udp port 53', ensures that only DNS packets are being used to carry the data.

- Finally, the message is logged using the 'log_message' function with 'ascii_message' and 'log_file_name' passed as arguments.


### Constraints

- receiverIp: This should be set to the receiver's IP.

- The pattern variables in the sender function should be equal to their receiver function counterparts. (E.g. pattern00 in sender should be exactly the same as pattern00 in receiver)

- All patterns should have the same length.

- The patterns work for any size of 2 or more; however, we recommend using 3 because as the size gets larger the covert channel's capacity decreases. The other case of making it have a size of 2 would result in an encoding that is a bit too simple.

- should_stop: This should be set to false.


### Capacity

- The code that tests the covert channel's capacity is commented out.

- The covert channel's capacity was tested and resulted in a capacity of anywhere between 29 and 30 bits/second.
