import math


class SHA256:
	RIGHT = 0
	LEFT = 1
	BLOCK_SIZE = 512
	T1 = 8
	T2 = 9
	a = 0
	b = 1
	c = 2
	d = 3
	e = 4
	f = 5
	g = 6
	h = 7
	def __init__(self):
		self.totalSize = 0
		self.totalSize = 0
		self.mainBlock = ""
		self.M = []
		self.H = self.generateInitialHash()
		self.K = self.generateConstants()

	def generateInitialHash(self):
		H = []
		primes = self.generatePrime(8)
		for p in primes:
			sqrt = pow(p,0.5)
			bin = self.fractionalToBinary(sqrt, 32)
			H.append(bin)
		return H

	def generateConstants(self):
		C = []
		primes = self.generatePrime(64)
		for p in primes:
			sqrt = pow(p,1/3)
			bin = self.fractionalToBinary(sqrt, 32)
			C.append(bin)
		return C

	def print(self, data, gap=8):
		# Use list comprehension to split the string into chunks of size `interval`
		spaced_string = ' '.join(data[i:i + gap] for i in range(0, len(data), gap))
		print(spaced_string)

	def encrypt(self, data):
		# Converting the message to binary
		for i in data:
			self.mainBlock = self.mainBlock + self.decimalToBinary(ord(i))
		# Padding the message to get blocks with szie of multiple of 512
		self.messageSize = len(self.mainBlock)
		self.totalSize = self.calculateBlockSize(self.messageSize)
		padSize = self.totalSize - self.messageSize - 65
		self.mainBlock = self.mainBlock + "1" + "0"*padSize + self.decimalToBinary(self.messageSize, 64)
		# Parsing : splitting into blocks of size BLOCK_SIZE
		N = int(self.totalSize/SHA256.BLOCK_SIZE)
		for i in range(N):
			self.M.append(self.mainBlock[i * SHA256.BLOCK_SIZE: (i + 1) * SHA256.BLOCK_SIZE])
		# Starting Computation
		WT = []
		for m in self.M:
			W = ''
			Wt = []
			for i in range(64):
				if i<=15:
					W = m[i*32:(i+1)*32]
				else:
					a = self.sigma1(Wt[i-2])
					b = Wt[i-7]
					c = self.sigma0(Wt[i-15])
					d = Wt[i-16]
					W = self.sumMod2([a, b, c, d])
				Wt.append(W)
			WT.append(Wt)

		self.WV = list(self.H)
		self.iH = list(self.H)
		T1 = ""
		T2 = ""

		for j in range(N):
			Wt = WT[j]
			for t in range(64):
				S1 = self.Sigma1(self.WV[SHA256.e])
				ch = self.ch(self.WV[SHA256.e],self.WV[SHA256.f],self.WV[SHA256.g])
				T1 = self.sumMod2([self.WV[SHA256.h],S1,ch,self.K[t],Wt[t]])
				S0 = self.Sigma0(self.WV[SHA256.a])
				maj = self.maj([self.WV[SHA256.a],self.WV[SHA256.b],self.WV[SHA256.c]])
				T2 = self.sumMod2([S0,maj])
				self.WV[SHA256.h] = self.WV[SHA256.g]
				self.WV[SHA256.g] = self.WV[SHA256.f]
				self.WV[SHA256.f] = self.WV[SHA256.e]
				self.WV[SHA256.e] = self.sumMod2([self.WV[SHA256.d],T1])
				self.WV[SHA256.d] = self.WV[SHA256.c]
				self.WV[SHA256.c] = self.WV[SHA256.b]
				self.WV[SHA256.b] = self.WV[SHA256.a]
				self.WV[SHA256.a] = self.sumMod2([T2,T1])

			for i in range(8):
				self.iH[i] = self.sumMod2([self.WV[i],self.iH[i]])
			self.WV = list(self.iH)
		return self.binaryToHex(''.join([h for h in self.iH]))


	def maj(self,data):
		X = int(data[0],2)
		Y = int(data[1],2)
		Z = int(data[2],2)
		X_Y = (X & Y)
		X_Z = (X & Z)
		Y_Z = (Y & Z)
		r = self.xor([bin(X_Y)[2:].zfill(32),bin(X_Z)[2:].zfill(32),bin(Y_Z)[2:].zfill(32)])
		return r

	def ch(self, X, Y, Z):
		# Covert binary strings to integers
		Xn =''
		for i in X:
			Xn = Xn + ('0' if i =='1' else '1')
		Xn = int(Xn,2)
		X_int = int(X, 2)
		Y_int = int(Y, 2)
		Z_int = int(Z, 2)

		# Perform the AND operations
		and_xy = X_int & Y_int
		and_xz = Xn & Z_int

		# Perform the XOR operation
		result = and_xy ^ and_xz

		# Convert the result back to a binary string
		return bin(result)[2:].zfill(len(X))

	def Sigma0(self,data):
		data1 = self.circularShift(data,2)
		data2 = self.circularShift(data,13)
		data3 = self.circularShift(data,22)
		return self.xor([data1,data2,data3])

	def Sigma1(self,data):
		data1 = self.circularShift(data,6)
		data2 = self.circularShift(data,11)
		data3 = self.circularShift(data,25)
		return self.xor([data1,data2,data3])

	def sigma0(self,data):
		data1 = self.circularShift(data,7)
		data2 = self.circularShift(data,18)
		data3 = self.arithematicShift(data,3)
		return self.xor([data1,data2,data3])

	def sigma1(self, data):
		data1 = self.circularShift(data,17)
		data2 = self.circularShift(data,19)
		data3 = self.arithematicShift(data,10)

		return self.xor([data1,data2,data3])

	def sumMod2(self, data):
		# Define the modulo value as 2^32
		MODULO = 2**32

		# Initialize result to 0
		result = 0

		# Convert each binary string to an integer and add it to the result
		for s in data:
			result += int(s, 2)

		# Apply modulo 2^32 to the result
		result %= MODULO

		# Convert the result back to a binary string and remove the '0b' prefix
		return bin(result)[2:].zfill(len(data[0]))

	def xor(self, data):
		# Convert the first binary string to an integer
		result = int(data[0], 2)

		# XOR each subsequent binary string with the result
		for binary_string in data[1:]:
			result ^= int(binary_string, 2)

		# Convert the result back to a binary string
		return bin(result)[2:].zfill(len(data[0]))

	def generatePrime(self, count):
		primes = []
		primeCount = 0
		prime = 2
		while(primeCount!=count):
			isPrime = True
			for i in range(2,int(prime/2)+1):
				if prime%i == 0:
					isPrime = False
					break
			if isPrime:
				primes.append(prime)
				primeCount+=1
			prime += 1

		return primes

	def calculateBlockSize(self, totalSize):
		baseSize = int(totalSize/SHA256.BLOCK_SIZE)
		if (baseSize+1) * SHA256.BLOCK_SIZE - 65 < totalSize:
			messageBlockSize = (baseSize + 2) * SHA256.BLOCK_SIZE
		else:
			messageBlockSize = (baseSize + 1) * SHA256.BLOCK_SIZE

		return messageBlockSize


	def fractionalToBinary(self, num, precision=32):
		fractional_part = num - int(num)
		# Initialize binary string
		binary_fraction = ''

		# Compute binary representation
		while precision > 0:
			fractional_part *= 2
			bit = int(fractional_part)
			if bit == 1:
				binary_fraction += '1'
				fractional_part -= bit
			else:
				binary_fraction += '0'
			precision -= 1

		return binary_fraction

	def decimalToBinary(self, num, bitCount=8):
		binaryStr = bin(num)[2:]
		if len(binaryStr) > bitCount:
			raise ValueError(f"The number {num} cannot be represented in {bitCount} bits.")

		return binaryStr.zfill(bitCount)


	def binaryToHex(self, binary):
		# Pad binary string with leading zeros to make its length a multiple of 4
		padding_length = (4 - len(binary) % 4) % 4
		binary = '0' * padding_length + binary

		# Convert binary string to hexadecimal
		hex_str = ''.join(
			format(int(binary[i:i + 4], 2), 'X') for i in range(0, len(binary), 4)
		)

		return hex_str


	def arithematicShift(self, data, pos, dir = RIGHT):
		l = len(data)
		pos = min(pos,l)
		if dir == SHA256.RIGHT:
			return "0"*pos + data[0:l-pos]

		return data[pos:] + "0"*pos

	def circularShift(self, data, pos, dir=RIGHT):
		bitWidth = len(data)
		# Ensure position is within the bounds of the bit width
		pos %= bitWidth

		# Convert the binary string to an integer for manipulation
		data_int = int(data, 2)

		if dir == SHA256.LEFT:
			# Left circular shift
			shifted = ((data_int << pos) & ((1 << bitWidth) - 1)) | (data_int >> (bitWidth - pos))
		else:
			# Right circular shift
			shifted = (data_int >> pos) | ((data_int << (bitWidth - pos)) & ((1 << bitWidth) - 1))

		# Convert the integer back to a binary string with leading zeros
		return format(shifted, f'0{bitWidth}b')


if __name__ == "__main__":
	sha = SHA256()
	data = "this is what i was looking for and this is what i wantthis is what i was looking for and this is what i want wow this is working as expected this is what i wantthis is what i was looking for and this is what i wantthis is what i was looking for and this is what i want wow this is working as expected this is what i want"
	print(len(data))
	print(sha.encrypt(data))
	ans = 'f8f05f79fe0c0f876d26368bd12c08ef31617039ae3104c34f22db9c0afd3bd9'
