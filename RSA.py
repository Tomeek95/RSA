#!/usr/bin/env python3

import time
import random
import math


####################################################
def eucAlg(a, b): 
    """ 
    Euclidean algorithm 

    Returns the greatest common divisor. 
    """
    # RecursionError: maximum recursion depth exceeded in comparison ... (1024bites prímek esetén)
    if (b == 0):
        return a
    return eucAlg(b, a % b)


####################################################
def extendedEucAlg(a, b):
    """ 
    Extended Euclidean algorithm

    Returns the coefficients of integers a and b. 
    """
    x, prev_x = 0, 1

    while (b != 0):
        quotient = a // b
        a, b = b, a - quotient * b
        prev_x, x = x, prev_x - quotient * x

    return prev_x


####################################################
def fastPower(a, b, m):
    """ 
    Modular multiplicative inverse
    
    This method is basically Python's built in pow(a,b,c) function. 
    """
    number = 1
    while b:
        if b & 1:
            number = number * a % m
        b >>= 1
        a = a * a % m
    return number


####################################################
def isPrime(num):
    """ Miller-Rabin primality test

    The essentials of this algorithm, is to generate multiple bases and to test the given integer with them,
    whether it is a prime number or not.
    """
    if num % 2 == 0:
        return False
    if num in knownPrimes:
        return True

    d = num - 1
    s = 0
    while d % 2 == 0:
        d = d // 2
        s += 1

    for _ in range(5): 
        a = random.randrange(2, num - 1)
        x = fastPower(a, d, num)
        if x != 1: 
            r = 0
            while x != (num - 1):
                if r == s - 1:
                    return False
                else:
                    r += 1
                    x = fastPower(x, 2, num)
    knownPrimes.append(num)
    return True
####################################################
knownPrimes = []


####################################################
def chineseRemainderTheorem(pq, sk, m):
    """ 
    Chinese Remainder theorem
    
    With getting the generated primes's coefficients and with the modulus and private key,
    we decrypt the coded char. 
    """
    p, q = pq
    d, n = sk
    miP = extendedEucAlg(p, q)
    miQ = extendedEucAlg(q, p)
    message1 = fastPower(m, d, p)
    message2 = fastPower(m, d, q)

    return ((message1 * q * miQ) + (message2 * p * miP)) % n


####################################################
def choosePublicKey(phiN):
    """ 
    Selecting the Public key
    
    
    "e" needs to be selected the way that it fulfils the following condition: 1 < e < phi(n),
    then we check whether e is co-prime with phiN or not.  
    """

    while True:
        e = random.randrange(2, phiN)
        if eucAlg(e, phiN) == 1:
            return e


####################################################
def keyGen():
    """ 
    Key Generator
    """
    print("Generating the prime numbers ...")
    p = 0
    q = 0
    n = 1
    while(int((math.log(n) / math.log(2)) + 1) < 1024):
        while(True):
            p = random.getrandbits(512)
            if int((math.log(p) / math.log(2)) + 1) >= 512:
                if isPrime(p):
                    break
        while(True):
            q = random.getrandbits(520)
            if(int((math.log(q) / math.log(2)) + 1) >= 512):
                if isPrime(q):
                    break
        if p != q:
            n = p * q #modulus

    #print(f"A modulus {int((math.log(n) / math.log(2)) + 1)} bites")
    phiN = (p - 1) * (q - 1)
    e = choosePublicKey(phiN)
    print("Generating the secret key ...")
    x = extendedEucAlg(e, phiN)
    d = x
    while x < 0:
        d = x + phiN
        x += phiN

    return (p, q), (e, n), (d, n)


####################################################
def encrypt(pk, message):
    """ 
    Encrypting algorithm 
    """

    key, n = pk
    encryptedMessage = [fastPower(ord(char), key, n) for char in message]

    return encryptedMessage


####################################################
def decrypt(pq, sk, message):
    """ 
    Decrypting algorithm 
    """

    decodedMessage = [chr(chineseRemainderTheorem(pq, sk, char)) for char in message]
    return "".join(decodedMessage)


####################################################
def main():
    """ 
    Driver code 
    """

    inp = input("Enter the message that needs to be encrypted: ")
    start_time = time.time()
    pq, pk, sk = keyGen() 
    codedMessage = encrypt(pk, inp)
    print(f"The coded message: {codedMessage}")
    print(f"The decoded message: {decrypt(pq, sk, codedMessage)}")
    print("The runTime: ")
    print(time.time() - start_time)


####################################################
if __name__ == "__main__":
    main()


