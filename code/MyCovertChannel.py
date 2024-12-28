from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, DNS, sniff

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def _init_(self):
        """
        - You can edit _init_.
        """
        pass

    def send(self, log_file_name, receiverIp, pattern00, pattern01, pattern10, pattern11):
        """
        - A random binary message is generated 
        - Two bits are extracted at a time and the possible combinations are checked
        - Depending on what the two bits are a pattern is chosen from the patterns in the parameters
        - Iterate through this pattern (A list of bits) and send each bit to the receiver
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        # binary_message = self.generate_random_binary_message_with_logging(log_file_name, min_length = 16, max_length = 16) # For time testing

        # import time 
        # startTime = time.time() # Start timer

        for i in range(0, len(binary_message), 2):
            twoBits = binary_message[i: i+2]
            if twoBits == '00':
                pattern = pattern00
            elif twoBits == '01':
                pattern = pattern01
            elif twoBits == '10':
                pattern = pattern10
            elif twoBits == '11':
                pattern = pattern11

            for zVal in pattern:
                dns_query = IP(dst=receiverIp) / UDP(dport=53) / DNS(z=zVal)
                super().send(dns_query)

        # endTime = time.time() # Stop timer
        # elapsedTime = endTime - startTime # Calculate elapsed time
        # capacity = 128 / elapsedTime # Calculate capacity in bits/second
        # print(f"Covert channel capacity: {capacity:.2f} bits/second") # Display capacity
        
    def receive(self, log_file_name, pattern00, pattern01, pattern10, pattern11, should_stop):
        """
        - Receive the bits from sender and once all the bits in the chosen pattern is sent check which pattern it was
        - Add the two bits corresponding to the pattern to the 'received_message' variable
        - Once 'received_message' is a byte long add it to the 'ascii_message' variable
        - When the end of the message is reached, make the 'should_stop' flag true and pass it into the sniff function
        - Finally, log the full 'ascii_message'
        """
        collected_bits = ""
        received_message = ""
        pattern_length = len(pattern00)
        ascii_message = ""

        def stop_message(packet):
            return should_stop
            

        def receive_packet(packet):
            nonlocal collected_bits, should_stop, received_message, ascii_message
            if DNS in packet and hasattr(packet[DNS], 'z'):

                dns_packet = packet[DNS]
                z_val = dns_packet.z

                collected_bits += str(z_val)

                if len(collected_bits) >= pattern_length:
                    extractedPattern= collected_bits[:pattern_length]
                    collected_bits = collected_bits[pattern_length:]

                    if extractedPattern == ''.join(map(str, pattern00)):
                        received_message += "00"
                    elif extractedPattern == ''.join(map(str, pattern01)):
                        received_message += "01"
                    elif extractedPattern == ''.join(map(str, pattern10)):
                        received_message += "10"
                    elif extractedPattern == ''.join(map(str, pattern11)):
                        received_message += "11"


                    if len(received_message) >= 8:
                        char = self.convert_eight_bits_to_character(received_message[-8:])
                        ascii_message += char
                        received_message = ""

                        if char == '.':
                            should_stop = True

        sniff(prn=receive_packet, stop_filter=stop_message, filter="udp port 53")                                  
        self.log_message(ascii_message, log_file_name)