from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, DNS, sniff

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        self.receiver_ip = "172.17.0.3"
        pass

    def encode(self, bit):
        return int(bit) ^ 1
    
    def decode(self, bit):
        return int(bit) ^ 1

    def send(self, log_file_name, parameter1, parameter2):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for bit in binary_message:
            encoded_bit = self.encode(bit)
            
            #dns_query = IP(dst="receiver") / UDP(dport=53) / DNS(qd=DNSQR(qname="testtest.com"), z = encoded_bit)
            #flags = dns_query[DNS].flags
            #flags &= 0b1111000111111111
            #dns_query.show()
            dns_query = IP(dst=self.receiver_ip) / UDP(dport=53) / DNS(z=encoded_bit)
            super().send(dns_query)
        
    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        collected_bits = ""
        should_stop = False
        received_message = ""

        def stop_message(packet):
            return should_stop
            

        def receive_packet(packet):
            nonlocal collected_bits, should_stop, received_message
            if DNS in packet and hasattr(packet[DNS], 'z'):

                dns_packet = packet[DNS]
                z_val = dns_packet.z

                decoded_bit = self.decode(z_val)


                collected_bits += str(decoded_bit)
                
                while len(collected_bits) >= 8:
                    byte = collected_bits[:8]
                    collected_bits = collected_bits[8:] 
                    character = chr(int(byte, 2))
                    print(f"received character: {character}")
                    received_message += character


                    if character == '.':
                        should_stop =True
        sniff(prn=receive_packet, stop_filter=stop_message, filter="udp port 53")
                                            
        self.log_message(received_message, log_file_name)


if __name__ == "__main__":
    covert_channel = MyCovertChannel()
