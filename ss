from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

#define our data
data = b"HelloWorld" 
...............AES..........
#get random bytes and generate the key in byte format
key = get_random_bytes(16) 
 
#create new object
cipher = AES.new(key,AES.MODE_EAX) 
  
#encryption part
ciphertext, tag = cipher.encrypt_and_digest(data)  

#create samp1 text file and write encryption code in this file.
file_out = open("samp1.txt","wb")
[file_out.write(x) for x in (cipher.nonce,tag,ciphertext)]   
file_out.close()

#To decryption, read created samp1 text file and decrypt the message
file_in = open ("samp1.txt","rb") 
nonce,tag,ciphertext = [file_in.read(x) for x in (16,16,-1)]  

#the person decrypting the message will need access to the key

cipher = AES.new(key,AES.MODE_EAX,nonce = nonce)

data = cipher.decrypt_and_verify(ciphertext,tag)

print("Decryption of data is : ",data.decode("UTF-8"))

...........Caesercipher............
def Encrypt(s, key):
	lalpha = "abcdefghijklmnopqrstuvwxyz"
	ualpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	res = ""
	for c in s:
		if str(c).islower():
			pos=(ord(c) - ord('a') + key) % 26
			res = res + lalpha[pos]
		elif str(c).isupper():
			pos = (ord(c) - ord('A') + key) % 26
			res = res + ualpha[pos]
		else:
			res = res + c
	return res
	
s = input("Enter your cipher text: ")
k = int(input("Enter an encrypt key: "))
print(Encrypt(s, k))


---------decryption-----------

def Decrypt(s, key):
	lalpha = "abcdefghijklmnopqrstuvwxyz"
	ualpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	res = ""
	for c in s:
		if str(c).islower():
			pos=(ord(c) - ord('a') - key) % 26
			res = res + lalpha[pos]
		elif str(c).isupper():
			pos = (ord(c) - ord('A') - key) % 26
			res = res + ualpha[pos]
		else:
			res = res + c
	return res
	
s = input("Enter your encrypted text: ")
k = int(input("Enter an decrypt key: "))
print(Decrypt(s, k))
...........column.............
# Python3 implementation of
# Columnar Transposition
import math

key = "HACK"

# Encryption
def encryptMessage(msg):
	cipher = ""

	# track key indices
	k_indx = 0

	msg_len = float(len(msg))
	msg_lst = list(msg)
	key_lst = sorted(list(key))

	# calculate column of the matrix
	col = len(key)
	
	# calculate maximum row of the matrix
	row = int(math.ceil(msg_len / col))

	# add the padding character '_' in empty
	# the empty cell of the matix
	fill_null = int((row * col) - msg_len)
	msg_lst.extend('_' * fill_null)

	# create Matrix and insert message and
	# padding characters row-wise
	matrix = [msg_lst[i: i + col]
			for i in range(0, len(msg_lst), col)]

	# read matrix column-wise using key
	for _ in range(col):
		curr_idx = key.index(key_lst[k_indx])
		cipher += ''.join([row[curr_idx]
						for row in matrix])
		k_indx += 1

	return cipher

# Decryption
def decryptMessage(cipher):
	msg = ""

	# track key indices
	k_indx = 0

	# track msg indices
	msg_indx = 0
	msg_len = float(len(cipher))
	msg_lst = list(cipher)

	# calculate column of the matrix
	col = len(key)
	
	# calculate maximum row of the matrix
	row = int(math.ceil(msg_len / col))

	# convert key into list and sort
	# alphabetically so we can access
	# each character by its alphabetical position.
	key_lst = sorted(list(key))

	# create an empty matrix to
	# store deciphered message
	dec_cipher = []
	for _ in range(row):
		dec_cipher += [[None] * col]

	# Arrange the matrix column wise according
	# to permutation order by adding into new matrix
	for _ in range(col):
		curr_idx = key.index(key_lst[k_indx])

		for j in range(row):
			dec_cipher[j][curr_idx] = msg_lst[msg_indx]
			msg_indx += 1
		k_indx += 1

	# convert decrypted msg matrix into a string
	try:
		msg = ''.join(sum(dec_cipher, []))
	except TypeError:
		raise TypeError("This program cannot",
						"handle repeating words.")

	null_count = msg.count('_')

	if null_count > 0:
		return msg[: -null_count]

	return msg

# Driver Code
msg = "Geeks for Geeks"

cipher = encryptMessage(msg)
print("Encrypted Message: {}".
			format(cipher))

print("Decryped Message: {}".
	format(decryptMessage(cipher)))

# This code is contributed by Aditya K

..............DES...............
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_key():
    # Generate a random 8-byte (64-bit) key for DES
    return get_random_bytes(8)

def des_encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def des_decrypt(key, ciphertext):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_data, DES.block_size)
    return plaintext.decode()

if __name__ == "__main__":
    # Example usage
    key = generate_key()
    plaintext = "Hello Thilara"
    
    encrypted_data = des_encrypt(key, plaintext)
    decrypted_data = des_decrypt(key, encrypted_data)
    
    print("Original plaintext:", plaintext)
    print("Encrypted data:", encrypted_data)
    print("Decrypted plaintext:", decrypted_data)


..............playfair.......
# Python program to implement Playfair Cipher

# Function to convert the string to lowercase


def toLowerCase(text):
	return text.lower()

# Function to remove all spaces in a string


def removeSpaces(text):
	newText = ""
	for i in text:
		if i == " ":
			continue
		else:
			newText = newText + i
	return newText

# Function to group 2 elements of a string
# as a list element


def Diagraph(text):
	Diagraph = []
	group = 0
	for i in range(2, len(text), 2):
		Diagraph.append(text[group:i])

		group = i
	Diagraph.append(text[group:])
	return Diagraph

# Function to fill a letter in a string element
# If 2 letters in the same string matches


def FillerLetter(text):
	k = len(text)
	if k % 2 == 0:
		for i in range(0, k, 2):
			if text[i] == text[i+1]:
				new_word = text[0:i+1] + str('x') + text[i+1:]
				new_word = FillerLetter(new_word)
				break
			else:
				new_word = text
	else:
		for i in range(0, k-1, 2):
			if text[i] == text[i+1]:
				new_word = text[0:i+1] + str('x') + text[i+1:]
				new_word = FillerLetter(new_word)
				break
			else:
				new_word = text
	return new_word


list1 = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'k', 'l', 'm',
		'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

# Function to generate the 5x5 key square matrix


def generateKeyTable(word, list1):
	key_letters = []
	for i in word:
		if i not in key_letters:
			key_letters.append(i)

	compElements = []
	for i in key_letters:
		if i not in compElements:
			compElements.append(i)
	for i in list1:
		if i not in compElements:
			compElements.append(i)

	matrix = []
	while compElements != []:
		matrix.append(compElements[:5])
		compElements = compElements[5:]

	return matrix


def search(mat, element):
	for i in range(5):
		for j in range(5):
			if(mat[i][j] == element):
				return i, j


def encrypt_RowRule(matr, e1r, e1c, e2r, e2c):
	char1 = ''
	if e1c == 4:
		char1 = matr[e1r][0]
	else:
		char1 = matr[e1r][e1c+1]

	char2 = ''
	if e2c == 4:
		char2 = matr[e2r][0]
	else:
		char2 = matr[e2r][e2c+1]

	return char1, char2


def encrypt_ColumnRule(matr, e1r, e1c, e2r, e2c):
	char1 = ''
	if e1r == 4:
		char1 = matr[0][e1c]
	else:
		char1 = matr[e1r+1][e1c]

	char2 = ''
	if e2r == 4:
		char2 = matr[0][e2c]
	else:
		char2 = matr[e2r+1][e2c]

	return char1, char2


def encrypt_RectangleRule(matr, e1r, e1c, e2r, e2c):
	char1 = ''
	char1 = matr[e1r][e2c]

	char2 = ''
	char2 = matr[e2r][e1c]

	return char1, char2


def encryptByPlayfairCipher(Matrix, plainList):
	CipherText = []
	for i in range(0, len(plainList)):
		c1 = 0
		c2 = 0
		ele1_x, ele1_y = search(Matrix, plainList[i][0])
		ele2_x, ele2_y = search(Matrix, plainList[i][1])

		if ele1_x == ele2_x:
			c1, c2 = encrypt_RowRule(Matrix, ele1_x, ele1_y, ele2_x, ele2_y)
			# Get 2 letter cipherText
		elif ele1_y == ele2_y:
			c1, c2 = encrypt_ColumnRule(Matrix, ele1_x, ele1_y, ele2_x, ele2_y)
		else:
			c1, c2 = encrypt_RectangleRule(
				Matrix, ele1_x, ele1_y, ele2_x, ele2_y)

		cipher = c1 + c2
		CipherText.append(cipher)
	return CipherText


text_Plain = 'balloon'
text_Plain = removeSpaces(toLowerCase(text_Plain))
PlainTextList = Diagraph(FillerLetter(text_Plain))
if len(PlainTextList[-1]) != 2:
	PlainTextList[-1] = PlainTextList[-1]+'z'

key = "cryptography"
print("Key text:", key)
key = toLowerCase(key)
Matrix = generateKeyTable(key, list1)

print("Plain Text:", text_Plain)
CipherList = encryptByPlayfairCipher(Matrix, PlainTextList)

CipherText = ""
for i in CipherList:
	CipherText += i
print("CipherText:", CipherText)

# This code is Contributed by Boda_Venkata_Nikith


..............railfence..........
def encrypt_rail_fence(text, rails):
    rail_fence = [[' ' for _ in range(len(text))] for _ in range(rails)]
    direction = 1
    row, col = 0, 0

    for char in text:
        rail_fence[row][col] = char
        col += 1

        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1

        row += direction

    encrypted_text = ''
    for row in rail_fence:
        encrypted_text += ''.join(row)

    return encrypted_text

def decrypt_rail_fence(encrypted_text, rails):
    rail_fence = [[' ' for _ in range(len(encrypted_text))] for _ in range(rails)]
    direction = 1
    row, col = 0, 0

    for _ in range(len(encrypted_text)):
        rail_fence[row][col] = 'X'  # Placeholder character to mark visited cells
        col += 1

        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1

        row += direction

    index = 0
    for i in range(rails):
        for j in range(len(encrypted_text)):
            if rail_fence[i][j] == 'X':
                rail_fence[i][j] = encrypted_text[index]
                index += 1

    direction = 1
    row, col = 0, 0
    decrypted_text = ''

    for _ in range(len(encrypted_text)):
        decrypted_text += rail_fence[row][col]
        col += 1

        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1

        row += direction

    return decrypted_text

# Example usage:
text = "HELLOWORLDEXAMPLE"
rails = 3

encrypted_text = encrypt_rail_fence(text, rails)
print("Encrypted:", encrypted_text)

decrypted_text = decrypt_rail_fence(encrypted_text, rails)
print("Decrypted:", decrypted_text)



..............RSA..........
# Python for RSA asymmetric cryptographic algorithm.
# For demonstration, values are
# relatively small compared to practical application
import math


def gcd(a, h):
	temp = 0
	while(1):
		temp = a % h
		if (temp == 0):
			return h
		a = h
		h = temp


p = 3
q = 5
n = p*q
e = 3
phi = (p-1)*(q-1)

while (e < phi):

	# e must be co-prime to phi and
	# smaller than phi.
	if(gcd(e, phi) == 1):
		break
	else:
		e = e+1

# Private key (d stands for decrypt)
# choosing d such that it satisfies
# d*e = 1 + k * totient

k = 2
d = (1 + (k*phi))/e

# Message to be encrypted
msg = 4.0

print("Message data = ", msg)

# Encryption c = (msg ^ e) % n
c = pow(msg, e)
c = math.fmod(c, n)
print("Encrypted data = ", c)

# Decryption m = (c ^ d) % n
m = pow(c, d)
m = math.fmod(m, n)
print("Original Message Sent = ", m)


# This code is contributed by Pranay Arora.


-----------------------------------------------------------------------All cipher methods with switch function-----------------------------------------------------------------------
import math

alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '

print('1.Ceaser Cipher')
print('2.Railfence Cipher')
print('3.Row Transposition Cipher')
print('4.Playfair Cipher\n')

def process_condition(condition):

    if condition == '1': #playfair cipher start-----------
        print('1.Encryption')
        print('2.Decryption')

        choice = input('Enter Number:')

        if choice == '1': #playfair cipher encryption----------------

                plaintext = input("Enter plaintext: ")
                key = int(input("Enter Key value: "))

                plaintext = plaintext.upper()
                cipher = ''

                for c in plaintext:
                    index = alphabet.find(c)
                    index = (index+key) % len(alphabet)
                    cipher = cipher + alphabet[index]

                print(cipher)
                return process_condition(user_input)


        elif choice == '2': #playfair cipher decryption---------------

                ciphertext = input("Enter ciphertext: ")
                key = int(input("Enter Key value: "))

                ciphertext = ciphertext.upper()
                plain = ''

                for d in ciphertext:
                    index1 = alphabet.find(d)
                    index1 = (index1-key) % len(alphabet)
                    plain = plain + alphabet[index1]

                print(plain)
                return process_condition(user_input)

        else:
                print('Invalid condition.')
                return process_condition(user_input)

    elif condition == '2': #railfence cipher start-----------------
        print('1.Encryption')
        print('2.Decryption')

        choice = input("Enter Number:")

        if choice =='1': #railfence cipher encryption-----------------

                plainText = input('Enter Any Text: ')
                key = int(input("Enter key value: "))
                        
                cipherText = ''

                matrix = [['' for i in range(len(plainText))] for y in range(key)]

                i = 1
                row = 0
                col = 0

                for c in plainText:
                    if row+i<0 or row+i >= len(matrix):
                        i = i*-1

                    matrix[row][col] = c 
                        
                    row += i
                    col += 1

                for d in matrix:
                        cipherText += ''.join(d)

                print (cipherText)
                return process_condition(user_input)

        elif choice == '2': #railfence cipher decryption--------------

            cipherText = input('Enter the Cipher Text: ')
            key = int(input("Enter the key value: "))

            plainText = ''

            matrix = [['' for i in range(len(cipherText))] for y in range(key)]

            i = 1
            row = 0
            col = 0

            for c in cipherText:
                if row + i < 0 or row + i >= len(matrix):
                    i = i * -1

                matrix[row][col] = 'X' 

                row += i
                col += 1

            index = 0
            for row in range(len(matrix)):
                for col in range(len(matrix[row])):
                    if matrix[row][col] == 'X' and index < len(cipherText):
                        matrix[row][col] = cipherText[index]
                        index += 1

            col = 0
            row = 0
            for _ in range(len(cipherText)):
                if row + i < 0 or row + i >= len(matrix):
                    i = i * -1
                plainText += matrix[row][col]
                row += i
                col += 1

            print(plainText)
            return process_condition(user_input)

        else:
            print('Invalid condition')
            return process_condition(user_input)

    elif condition == '3': #Row Transposition cipher start----------------------
        print('1.Encryption')
        print('2.Decryption')

        choice = input("Enter Number:")

        if choice == '1':
            def encryptMessage(key, message): 
                cipherText = [''] * key

                for column in range(key):
                    currentIndex = column

                    while currentIndex < len(message):
                        cipherText[column] += message[currentIndex]
                        currentIndex += key

                return ''.join(cipherText)

            plainText = input("Enter plaintext: ")
            keyVal = int(input("Enter keyValue:"))

            cipher = encryptMessage(keyVal, plainText)
            print(cipher)
            
            return process_condition(user_input)

        elif choice == '2':
            def decryptMessage(key, message):
                numColumns = int(math.ceil(len(message) / key))
                numRows = key
                numEmptyBoxes = (numColumns * numRows) - len(message)

                plaintext = [''] * numColumns

                col = 0
                row = 0

                for symbol in message:
                    plaintext[col] += symbol
                    col += 1

                    if (col == numColumns) or (col == numColumns - 1 and row >= numRows - numEmptyBoxes):
                        col = 0
                        row += 1

                return ''.join(plaintext)

            cipherText = input("Enter ciphertext: ")
            keyVal = int(input("Enter keyValue: "))

            plainText = decryptMessage(keyVal, cipherText)

            print(plainText)
            return process_condition(user_input)

        else:
            print('Invalid condition')
            return process_condition(user_input)

    elif condition == '4': #Playfair cipher start------------------------------
        print('1.Encryption')
        print('2.Decryption')

        choice = input("Enter Number:")

        if choice =='1': #Playfair cipher encryption----------------

            def create_playfair_matrix(key):
                # Create a Playfair matrix from the given key
                key = key.replace(" ", "").upper()
                key = "".join(dict.fromkeys(key))  # Remove duplicate characters
                alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

                # Initialize the matrix with the key
                matrix = [list(key)]

                # Fill the matrix with the remaining alphabet characters
                for char in alphabet:
                    if char not in matrix[0]:
                        matrix[0].append(char)

                # Create a 5x5 matrix from the flattened list
                playfair_matrix = [matrix[0][i:i + 5] for i in range(0, 25, 5)]
                return playfair_matrix

            def encrypt_playfair(plaintext, key):
                def find_position(matrix, char):
                    for i in range(5):
                        for j in range(5):
                            if matrix[i][j] == char:
                                return i, j

                def process_text(text):
                    text = text.replace(" ", "").upper().replace("J", "I")
                    text_pairs = [text[i:i + 2] if i + 1 < len(text) and text[i] != text[i + 1] else text[i] + "X" for i in range(0, len(text), 2)]
                    return text_pairs

                playfair_matrix = create_playfair_matrix(key)
                plaintext_pairs = process_text(plaintext)
                ciphertext = ""

                for pair in plaintext_pairs:
                    row1, col1 = find_position(playfair_matrix, pair[0])
                    row2, col2 = find_position(playfair_matrix, pair[1])

                    if row1 == row2:  # Same row
                        ciphertext += playfair_matrix[row1][(col1 + 1) % 5] + playfair_matrix[row2][(col2 + 1) % 5]
                    elif col1 == col2:  # Same column
                        ciphertext += playfair_matrix[(row1 + 1) % 5][col1] + playfair_matrix[(row2 + 1) % 5][col2]
                    else:  # Different row and column
                        ciphertext += playfair_matrix[row1][col2] + playfair_matrix[row2][col1]

                return ciphertext

            plaintext = input("Enter plain text:")
            key = input("Enter Key Word:")
            encrypted_text = encrypt_playfair(plaintext, key)
            print("Encrypted Text:", encrypted_text)

            return process_condition(user_input)
  

        elif choice == '2': #Playfair cipher decryption----------------

            def create_playfair_matrix(key):
                # Create a Playfair matrix from the given key
                key = key.replace(" ", "").upper()
                key = "".join(dict.fromkeys(key))  # Remove duplicate characters
                alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

                # Initialize the matrix with the key
                matrix = [list(key)]

                # Fill the matrix with the remaining alphabet characters
                for char in alphabet:
                    if char not in matrix[0]:
                        matrix[0].append(char)

                # Create a 5x5 matrix from the flattened list
                playfair_matrix = [matrix[0][i:i + 5] for i in range(0, 25, 5)]
                return playfair_matrix

            def decrypt_playfair(ciphertext, key):
                def find_position(matrix, char):
                    for i in range(5):
                        for j in range(5):
                            if matrix[i][j] == char:
                                return i, j

                playfair_matrix = create_playfair_matrix(key)
                plaintext = ""

                for i in range(0, len(ciphertext), 2):
                    pair = ciphertext[i:i + 2]
                    row1, col1 = find_position(playfair_matrix, pair[0])
                    row2, col2 = find_position(playfair_matrix, pair[1])

                    if row1 == row2:  # Same row
                        plaintext += playfair_matrix[row1][(col1 - 1) % 5] + playfair_matrix[row2][(col2 - 1) % 5]
                    elif col1 == col2:  # Same column
                        plaintext += playfair_matrix[(row1 - 1) % 5][col1] + playfair_matrix[(row2 - 1) % 5][col2]
                    else:  # Different row and column
                        plaintext += playfair_matrix[row1][col2] + playfair_matrix[row2][col1]

                return plaintext

            ciphertext = input("Enter cipher text:")
            key = input("Enter Key Word:")
            decrypted_text = decrypt_playfair(ciphertext, key)
            print("Decrypted Text:", decrypted_text)

            return process_condition(user_input)

        else:
            print('Invalid condition')
            return process_condition(user_input)

    else:
        print("Invalid input")


user_input = input('Select Encryption Method: ')
process_condition(user_input)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

-----------------------------------------------------------------------------------------AES Algorithm-------------------------------------------------------------------------------
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

#define our data
data=b"SECRETDATA"

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)

file_out = open("Encrypt.txt", "wb")
[ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
file_out.close()

file_in = open("Encrypt.txt", "rb")
nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
print(data.decode('UTF-8'))
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------DES Algorithm-----------------------------------------------------------------------------------
from Cryptodome.Cipher import DES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

def generate_key():
    # Generate a random 8-byte (64-bit) key for DES
    return get_random_bytes(8)

def des_encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def des_decrypt(key, ciphertext):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_data, DES.block_size)
    return plaintext.decode()

if __name__ == "__main__":
    # Example usage
    key = generate_key()
    plaintext = "There is no data here. Please type anytext!"
    
    encrypted_data = des_encrypt(key, plaintext)
    decrypted_data = des_decrypt(key, encrypted_data)
    
    print("Original plaintext:", plaintext)
    print("Encrypted data:", encrypted_data)
    print("Decrypted plaintext:", decrypted_data)
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

-------------------------------------------------------------------------------------ciser cipher--------------------------------------------------------------------------------------------

import math

alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '

print('1.Ceaser Cipher/n')

def process_condition(condition):

    if condition == '1': #playfair cipher start-----------
        print('1.Encryption')
        print('2.Decryption')

        choice = input('Enter Number:')

        if choice == '1': #playfair cipher encryption----------------

                plaintext = input("Enter plaintext: ")
                key = int(input("Enter Key value: "))

                plaintext = plaintext.upper()
                cipher = ''

                for c in plaintext:
                    index = alphabet.find(c)
                    index = (index+key) % len(alphabet)
                    cipher = cipher + alphabet[index]

                print(cipher)
                return process_condition(user_input)


        elif choice == '2': #playfair cipher decryption---------------

                ciphertext = input("Enter ciphertext: ")
                key = int(input("Enter Key value: "))

                ciphertext = ciphertext.upper()
                plain = ''

                for d in ciphertext:
                    index1 = alphabet.find(d)
                    index1 = (index1-key) % len(alphabet)
                    plain = plain + alphabet[index1]

                print(plain)
                return process_condition(user_input)

        else:
                print('Invalid condition.')
                return process_condition(user_input)

    else:
        print("Invalid input")


user_input = input('Select Encryption Method: ')
process_condition(user_input)










