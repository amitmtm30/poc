import pyshark
from sys import argv
import os

# # Taking PCAP file from command line
test_pcap_file = argv[1]
filename = os.path.basename(test_pcap_file).split('.')
print("The Given file name is '{}' and the size of file is bytes is '{}'  ".format(filename[0],
                                                                                   os.path.getsize(test_pcap_file)))
# # Declaring an empty list to add the protocol related data
protocol = []
diameter_data = []


# Declaring a function to Read the pcap file
def read_file(filename, option):
    fileContent = pyshark.FileCapture(filename, display_filter=option)
    print("Pcap File successfully parsed")
    if option == 'http':
        for data in fileContent:
            protocol.append(data)
    else:
        for data in fileContent:
            protocol.append(data[2])
    print("{} data added successfully".format(option))
    return fileContent


while True:
    print('''
    Below are only available Protocol options to filter out the data from pcap file '{}' for analysis:
    1. TCP
    2. UDP
    3. HTTP
    4. Diameter
    '''.format(filename[0]))

    user_input = input("Please Enter the Option as '1' or '2' or '3' or '4' : ")

    if user_input == '1':
        tcp_data = read_file(test_pcap_file, 'tcp')
        user_input2 = input("Want to deep dive in to the TCP data Please select Yes | No : ").lower()
        if user_input2 == 'yes':
            print("Total TCP Data Counts are : ", len(protocol))
            while True:
                user_input3 = int(input(
                    "Please Enter the data index starting with '0' to see the 1st index data or Enter any other index : "))
                print("Printing Data is : ", protocol[user_input3])
                user_input4 = input("Want to continue to see next data select Yes | No : ").lower()
                if user_input4 == 'yes':
                    continue
                elif user_input4 == 'no':
                    print("*" * 30)
                    print(len(protocol))
                    protocol.clear()
                    print(len(protocol))
                    break
        else:
            protocol.clear()
            tcp_data.close()
            continue

    elif user_input == '2':
        tcp_data = read_file(test_pcap_file, 'udp')
        user_input5 = input("Want to deep dive in to the UDP data Please select Yes | No : ").lower()
        if user_input5 == 'yes':
            print("Data indexes are : ", len(protocol))
            while True:
                user_input6 = int(input(
                    "Please Enter the data index starting with '0' to see the 1st index data or Enter any other index : "))
                print("Printing Data is : ", protocol[user_input6])
                user_input7 = input("Want to continue to see next data select Yes | No : ").lower()
                if user_input7 == 'yes':
                    continue
                else:
                    print("*" * 30)
                    print(len(protocol))
                    protocol.clear()
                    print(len(protocol))
                    break
        else:
            protocol.clear()
            tcp_data.close()
            continue

    elif user_input == '3':
        tcp_data = read_file(test_pcap_file, 'http')
        user_input8 = input("Want to deep dive in to the HTTP data Please select Yes | No : ").lower()
        if user_input8 == 'yes':
            print("Data indexes are : ", len(protocol))
            while True:
                user_input9 = int(input(
                    "Please Enter the data index starting with '0' to see the 1st index data or Enter any other index : "))
                if len(protocol[user_input9]) > 86:
                    print("Its HTTP Request Data and Data is : ", protocol[user_input9][3])
                elif len(protocol[user_input9]) == 86:
                    print(" ITS HTTP Response Data and Data is : ", protocol[user_input9][4])
                    print("The Response code is : ", protocol[user_input9][4].response_code)
                user_input10 = input("Want to continue to see next data select Yes | No : ").lower()
                if user_input10 == 'yes':
                    continue
                else:
                    print("*" * 30)
                    print(len(protocol))
                    protocol.clear()
                    print(len(protocol))
                    break
        else:
            protocol.clear()
            tcp_data.close()
            continue

    elif user_input == '4':
        user_input5 = input("Want to Search Diameter Data based on IMSI Yes | No : ").lower()
        if user_input5 == 'yes':
            file_content = pyshark.FileCapture(argv[1],display_filter='diameter.User-Name')
            for pkt in file_content:
                if 'diameter' in pkt:
                    diameter_data.append(pkt)
            print("Data added successfully")
            print("Total TCP Data Counts are : ", len(diameter_data))
            while True:
                user_input_imsi = input("Please Enter a valid IMSI : ")
                for x in diameter_data:
                    if x[-1].get('user_name') is not None:
                        imsi = x[-1].get('user_name')
                        actual_imsi = imsi[0:13]
                    if actual_imsi == user_input_imsi:
                        print(actual_imsi)
                        print("And the corresponding data is : ", x)
                        print("###################################################################")
                user_input = input("Want to continue with other IMSI Yes | NO : ").lower()
                if user_input == 'yes':
                    continue
                else:
                    break
            diameter_data.clear()
            print(len(diameter_data))

        else:
            protocol.clear()
            tcp_data.close()
            continue
    else:
        print("Please select the valid option")
        break

    user_input1 = input("Want to Continue with other protocol please select Yes | No : ").lower()
    if user_input1 == 'yes':
        continue
    elif user_input1 == 'no':
        break

print("########################### Thank You #################################")
